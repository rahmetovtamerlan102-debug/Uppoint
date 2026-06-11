#!/usr/bin/env python3
import os
import sys
import asyncio
import json
import secrets
import random
import argparse
import hashlib
from datetime import datetime, timedelta
from contextlib import asynccontextmanager
from typing import Optional, List
import logging

from fastapi import FastAPI, HTTPException, Depends, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from pydantic import BaseModel
import asyncpg
import redis.asyncio as redis
import aiohttp
from passlib.context import CryptContext
from jose import jwt
from dotenv import load_dotenv
from tenacity import retry, stop_after_attempt, wait_exponential

load_dotenv()

# ---------- CONFIG ----------
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL required")
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    SECRET_KEY = secrets.token_urlsafe(32)
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
MAX_MONITORS_PER_USER = int(os.getenv("MAX_MONITORS_PER_USER", "100"))
CHECK_CONCURRENCY = int(os.getenv("CHECK_CONCURRENCY", "50"))
MAX_CHECK_TIME = int(os.getenv("MAX_CHECK_TIME", "30"))
REGION = os.getenv("REGION", "default")
ALL_REGIONS = ["us-east", "eu-west", "ap-southeast"]
HOST_RATE_LIMIT = 60

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
limiter = Limiter(key_func=get_remote_address)
logger = logging.getLogger(__name__)

db_pool = None
redis_client = None
http_session = None
check_semaphore = asyncio.Semaphore(CHECK_CONCURRENCY)

def normalize_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

async def get_http_session():
    global http_session
    if http_session is None:
        connector = aiohttp.TCPConnector(limit=200, limit_per_host=50, ttl_dns_cache=300)
        http_session = aiohttp.ClientSession(connector=connector)
    return http_session

async def check_host_rate_limit(target: str) -> bool:
    if not redis_client:
        return True
    from urllib.parse import urlparse
    host = urlparse(target).hostname or target.split(':')[0]
    key = f"rate_limit:{host}"
    try:
        current = await redis_client.incr(key)
        if current == 1:
            await redis_client.expire(key, 60)
        return current <= HOST_RATE_LIMIT
    except:
        return True

class LoginRequest(BaseModel):
    email: str
    password: str

class RegisterRequest(BaseModel):
    email: str
    password: str

class MonitorCreate(BaseModel):
    name: str
    target: str
    type: str
    keyword: Optional[str] = None
    interval_sec: int = 300
    timeout_sec: int = 10
    regions: Optional[List[str]] = None

async def init_db():
    global db_pool
    db_pool = await asyncpg.create_pool(DATABASE_URL, min_size=10, max_size=50)
    async with db_pool.acquire() as conn:
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                monitors_count INTEGER DEFAULT 0,
                max_monitors INTEGER DEFAULT 100,
                created_at TIMESTAMP DEFAULT NOW()
            )
        """)
        regions_default = "{" + ",".join(ALL_REGIONS) + "}"
        await conn.execute(f"""
            CREATE TABLE IF NOT EXISTS monitors (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                target TEXT NOT NULL,
                type TEXT NOT NULL,
                keyword TEXT,
                regions TEXT[] DEFAULT '{regions_default}',
                interval_sec INTEGER DEFAULT 300,
                timeout_sec INTEGER DEFAULT 10,
                status TEXT DEFAULT 'pending',
                response_ms INTEGER DEFAULT 0,
                last_check TIMESTAMP,
                fail_count INTEGER DEFAULT 0,
                enabled BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT NOW()
            )
        """)
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS checks (
                id SERIAL,
                monitor_id INTEGER NOT NULL,
                region TEXT NOT NULL,
                status TEXT NOT NULL,
                response_ms INTEGER,
                error TEXT,
                checked_at TIMESTAMP DEFAULT NOW()
            ) PARTITION BY RANGE (checked_at)
        """)
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS daily_stats (
                id SERIAL PRIMARY KEY,
                monitor_id INTEGER NOT NULL,
                date DATE NOT NULL,
                region TEXT NOT NULL,
                checks_total INTEGER DEFAULT 0,
                checks_up INTEGER DEFAULT 0,
                UNIQUE(monitor_id, date, region)
            )
        """)
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS worker_heartbeats (
                worker_id TEXT PRIMARY KEY,
                region TEXT,
                last_heartbeat TIMESTAMP DEFAULT NOW(),
                status TEXT DEFAULT 'active'
            )
        """)
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS dead_letter_checks (
                id SERIAL PRIMARY KEY,
                monitor_id INTEGER,
                region TEXT,
                error TEXT,
                failed_at TIMESTAMP DEFAULT NOW()
            )
        """)
        demo = await conn.fetchval("SELECT id FROM users WHERE email = 'demo@uppoint.com'")
        if not demo:
            demo_pwd = normalize_password("demo123")
            await conn.execute(
                "INSERT INTO users (email, password_hash) VALUES ($1, $2)",
                "demo@uppoint.com", pwd_context.hash(demo_pwd)
            )
        start_date = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        for i in range(13):
            part_start = start_date + timedelta(days=30*i)
            part_end = part_start + timedelta(days=30)
            part_name = f"checks_{part_start.strftime('%Y_%m')}"
            await conn.execute(f"""
                CREATE TABLE IF NOT EXISTS {part_name} PARTITION OF checks
                FOR VALUES FROM ('{part_start.isoformat()}') TO ('{part_end.isoformat()}')
            """)

async def update_heartbeat(worker_id: str):
    while True:
        if not db_pool:
            await asyncio.sleep(30)
            continue
        try:
            async with db_pool.acquire() as conn:
                await conn.execute("""
                    INSERT INTO worker_heartbeats (worker_id, region, last_heartbeat, status)
                    VALUES ($1, $2, NOW(), 'active')
                    ON CONFLICT (worker_id) DO UPDATE SET
                        last_heartbeat = NOW(),
                        status = 'active'
                """, worker_id, REGION)
            await asyncio.sleep(30)
        except Exception as e:
            logger.error(f"Heartbeat error: {e}")
            await asyncio.sleep(60)

def create_token(user_id: int) -> str:
    expire = datetime.utcnow() + timedelta(days=7)
    return jwt.encode({"sub": str(user_id), "exp": expire}, SECRET_KEY, algorithm="HS256")

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer())):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        user_id = int(payload["sub"])
    except:
        raise HTTPException(401, "Invalid token")
    async with db_pool.acquire() as conn:
        user = await conn.fetchrow("SELECT id, email FROM users WHERE id = $1", user_id)
        if not user:
            raise HTTPException(401, "User not found")
        return dict(user)

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=10))
async def check_http(target: str, timeout: int, keyword: str = None) -> tuple:
    session = await get_http_session()
    if not target.startswith("http"):
        target = "https://" + target
    if not await check_host_rate_limit(target):
        return "down", 0, "Rate limit exceeded"
    start = datetime.utcnow()
    async with session.get(target, timeout=timeout, ssl=True) as resp:
        elapsed = int((datetime.utcnow() - start).total_seconds() * 1000)
        if not (200 <= resp.status < 400):
            return "down", elapsed, f"HTTP {resp.status}"
        if keyword:
            text = await resp.text()
            if keyword.lower() not in text.lower():
                return "down", elapsed, "Keyword missing"
        return "up", elapsed, None

async def check_port(target: str, timeout: int) -> tuple:
    try:
        if ":" not in target:
            host, port = target, 80
        else:
            host, port = target.rsplit(":", 1)
        start = datetime.utcnow()
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, int(port)), timeout=timeout)
        elapsed = int((datetime.utcnow() - start).total_seconds() * 1000)
        writer.close()
        await writer.wait_closed()
        return "up", elapsed, None
    except asyncio.TimeoutError:
        return "down", timeout * 1000, "Timeout"
    except:
        return "down", 0, "Port error"

async def run_check(check_type: str, target: str, timeout: int, keyword: str = None):
    if check_type == "http":
        return await check_http(target, timeout, keyword)
    elif check_type == "port":
        return await check_port(target, timeout)
    else:
        return "down", 0, "Unsupported type"

async def worker_task(worker_id: str):
    await update_heartbeat(worker_id)
    while True:
        if not redis_client:
            await asyncio.sleep(5)
            continue
        try:
            result = await redis_client.xreadgroup(
                "workers", worker_id, {"checks_stream": ">"}, count=10, block=5000
            )
            if result:
                for stream, msgs in result:
                    for msg_id, data in msgs:
                        monitor_id = int(data["monitor_id"])
                        region = data.get("region", "default")
                        if REGION != "default" and region != REGION:
                            await redis_client.xack(stream, "workers", msg_id)
                            continue
                        async with check_semaphore:
                            await asyncio.sleep(random.uniform(0, 0.2))
                            try:
                                async with db_pool.acquire() as conn:
                                    monitor = await conn.fetchrow("SELECT * FROM monitors WHERE id=$1 AND enabled=TRUE", monitor_id)
                                    if not monitor:
                                        await redis_client.xack(stream, "workers", msg_id)
                                        continue
                                status, ms, error = await run_check(
                                    monitor["type"], monitor["target"],
                                    monitor["timeout_sec"], monitor.get("keyword")
                                )
                                now = datetime.utcnow()
                                async with db_pool.acquire() as conn:
                                    async with conn.transaction():
                                        await conn.execute(
                                            "INSERT INTO checks (monitor_id, region, status, response_ms, error, checked_at) VALUES ($1,$2,$3,$4,$5,$6)",
                                            monitor_id, region, status, ms, error, now
                                        )
                                        new_fail = 0 if status == "up" else monitor["fail_count"] + 1
                                        await conn.execute(
                                            "UPDATE monitors SET status=$1, response_ms=$2, last_check=$3, fail_count=$4 WHERE id=$5",
                                            status, ms, now, new_fail, monitor_id
                                        )
                                        today = now.date()
                                        await conn.execute("""
                                            INSERT INTO daily_stats (monitor_id, date, region, checks_total, checks_up)
                                            VALUES ($1,$2,$3,1,$4)
                                            ON CONFLICT (monitor_id, date, region) DO UPDATE SET
                                                checks_total = daily_stats.checks_total + 1,
                                                checks_up = daily_stats.checks_up + $4
                                        """, monitor_id, today, region, 1 if status == "up" else 0)
                                        if monitor["status"] != "pending" and monitor["status"] != status:
                                            if status == "down":
                                                await conn.execute(
                                                    "INSERT INTO incidents (monitor_id, region, started_at) VALUES ($1,$2,$3)",
                                                    monitor_id, region, now
                                                )
                                                if redis_client:
                                                    await redis_client.publish("incidents", json.dumps({"monitor_id": monitor_id, "status": "down"}))
                                            elif monitor["status"] == "down" and status == "up":
                                                await conn.execute("""
                                                    UPDATE incidents SET ended_at=$1, duration_sec=EXTRACT(EPOCH FROM ($1 - started_at))
                                                    WHERE monitor_id=$2 AND region=$3 AND ended_at IS NULL
                                                """, now, monitor_id, region)
                                                if redis_client:
                                                    await redis_client.publish("incidents", json.dumps({"monitor_id": monitor_id, "status": "up"}))
                                        if redis_client:
                                            await redis_client.delete(f"user:{monitor['user_id']}:monitors")
                                            await redis_client.publish("status_changes", json.dumps({"monitor_id": monitor_id, "status": status, "region": region, "response_ms": ms}))
                            except Exception as e:
                                logger.error(f"Check error: {e}")
                                async with db_pool.acquire() as conn:
                                    await conn.execute(
                                        "INSERT INTO dead_letter_checks (monitor_id, region, error) VALUES ($1,$2,$3)",
                                        monitor_id, region, str(e)
                                    )
                            finally:
                                if redis_client:
                                    await redis_client.xack(stream, "workers", msg_id)
            await asyncio.sleep(0.1)
        except Exception as e:
            logger.error(f"Worker error: {e}")
            await asyncio.sleep(5)

async def scheduler_task():
    while True:
        if not redis_client:
            await asyncio.sleep(5)
            continue
        try:
            now = datetime.utcnow().timestamp()
            monitor_ids = await redis_client.zrangebyscore("monitor_schedule", 0, now)
            for monitor_id_str in monitor_ids:
                monitor_id = int(monitor_id_str)
                async with db_pool.acquire() as conn:
                    monitor = await conn.fetchrow("SELECT interval_sec, regions FROM monitors WHERE id=$1 AND enabled=TRUE", monitor_id)
                    if monitor:
                        regions = monitor["regions"] if monitor["regions"] else ALL_REGIONS
                        for region in regions:
                            await redis_client.xadd("checks_stream", {"monitor_id": str(monitor_id), "region": region})
                        next_time = now + monitor["interval_sec"]
                        await redis_client.zadd("monitor_schedule", {str(monitor_id): next_time})
                    else:
                        await redis_client.zrem("monitor_schedule", str(monitor_id))
            await asyncio.sleep(5)
        except Exception as e:
            logger.error(f"Scheduler error: {e}")
            await asyncio.sleep(10)

async def populate_schedule():
    if not redis_client:
        return
    async with db_pool.acquire() as conn:
        monitors = await conn.fetch("SELECT id, interval_sec, last_check FROM monitors WHERE enabled=TRUE")
    for m in monitors:
        if m["last_check"]:
            last = m["last_check"].timestamp()
            next_time = last + m["interval_sec"]
        else:
            next_time = datetime.utcnow().timestamp()
        await redis_client.zadd("monitor_schedule", {str(m["id"]): next_time})

async def aggregator_task():
    while True:
        try:
            yesterday = (datetime.utcnow() - timedelta(days=1)).date()
            async with db_pool.acquire() as conn:
                await conn.execute("""
                    INSERT INTO daily_stats (monitor_id, date, region, checks_total, checks_up)
                    SELECT monitor_id, DATE(checked_at) as date, region, COUNT(*),
                           SUM(CASE WHEN status='up' THEN 1 ELSE 0 END)
                    FROM checks WHERE DATE(checked_at)=$1
                    GROUP BY monitor_id, DATE(checked_at), region
                    ON CONFLICT (monitor_id, date, region) DO UPDATE SET
                        checks_total = EXCLUDED.checks_total,
                        checks_up = EXCLUDED.checks_up
                """, yesterday)
                cutoff = datetime.utcnow() - timedelta(days=90)
                await conn.execute("DELETE FROM checks WHERE checked_at < $1", cutoff)
            await asyncio.sleep(3600)
        except Exception as e:
            logger.error(f"Aggregator error: {e}")
            await asyncio.sleep(3600)

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
    async def broadcast(self, message: str):
        for conn in self.active_connections:
            try:
                await conn.send_text(message)
            except:
                pass
    async def listen_redis(self):
        if not redis_client:
            return
        pubsub = redis_client.pubsub()
        await pubsub.subscribe("status_changes", "incidents")
        async for message in pubsub.listen():
            if message["type"] == "message":
                await self.broadcast(message["data"])

manager = ConnectionManager()

async def wait_for_redis(retries=5, delay=2):
    for i in range(retries):
        try:
            client = await redis.from_url(REDIS_URL, decode_responses=True)
            await client.ping()
            return client
        except Exception as e:
            logger.warning(f"Redis connection attempt {i+1}/{retries} failed: {e}")
            await asyncio.sleep(delay)
    logger.error("Redis unavailable after retries – running without Redis")
    return None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global redis_client, db_pool
    await init_db()
    redis_client = await wait_for_redis()
    if redis_client:
        try:
            await redis_client.xgroup_create("checks_stream", "workers", id="0", mkstream=True)
        except redis.ResponseError:
            pass
        asyncio.create_task(manager.listen_redis())
        await populate_schedule()
        logger.info("Redis connected, background workers (scheduler, worker) started")
    else:
        logger.warning("Redis not available – realtime updates, scheduling and WebSocket disabled. Only API and DB work.")
    yield
    if redis_client:
        await redis_client.close()
    await db_pool.close()

app = FastAPI(lifespan=lifespan, title="Uppoint Monitor")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
security = HTTPBearer()

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    if not redis_client:
        await websocket.close(code=1008, reason="Redis unavailable")
        return
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

@app.post("/api/login")
@limiter.limit("5 per minute")
async def login(data: LoginRequest, request: Request):
    async with db_pool.acquire() as conn:
        user = await conn.fetchrow("SELECT id, password_hash FROM users WHERE email=$1", data.email)
        if not user or not pwd_context.verify(normalize_password(data.password), user["password_hash"]):
            raise HTTPException(401, "Invalid credentials")
        return {"access_token": create_token(user["id"]), "token_type": "bearer"}

@app.post("/api/register")
@limiter.limit("5 per minute")
async def register(data: RegisterRequest, request: Request):
    async with db_pool.acquire() as conn:
        existing = await conn.fetchval("SELECT id FROM users WHERE email=$1", data.email)
        if existing:
            raise HTTPException(400, "Email already exists")
        pwd_hash = pwd_context.hash(normalize_password(data.password))
        user_id = await conn.fetchval("INSERT INTO users (email, password_hash) VALUES ($1,$2) RETURNING id", data.email, pwd_hash)
        token = create_token(user_id)
        return {"access_token": token, "token_type": "bearer"}

@app.post("/api/monitors")
@limiter.limit("30 per minute")
async def create_monitor(monitor: MonitorCreate, request: Request, user=Depends(get_current_user)):
    async with db_pool.acquire() as conn:
        updated = await conn.fetchrow("UPDATE users SET monitors_count = monitors_count + 1 WHERE id=$1 AND monitors_count < max_monitors RETURNING monitors_count", user["id"])
        if not updated:
            raise HTTPException(429, "Monitor limit reached")
        regions = monitor.regions if monitor.regions else ALL_REGIONS
        monitor_id = await conn.fetchval("""
            INSERT INTO monitors (user_id, name, target, type, keyword, regions, interval_sec, timeout_sec)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id
        """, user["id"], monitor.name, monitor.target, monitor.type, monitor.keyword, regions, monitor.interval_sec, monitor.timeout_sec)
        if redis_client:
            next_time = datetime.utcnow().timestamp() + monitor.interval_sec
            await redis_client.zadd("monitor_schedule", {str(monitor_id): next_time})
        return {"id": monitor_id}

@app.delete("/api/monitors/{monitor_id}")
async def delete_monitor(monitor_id: int, user=Depends(get_current_user)):
    async with db_pool.acquire() as conn:
        await conn.execute("DELETE FROM monitors WHERE id=$1 AND user_id=$2", monitor_id, user["id"])
        await conn.execute("UPDATE users SET monitors_count = monitors_count - 1 WHERE id=$1", user["id"])
        if redis_client:
            await redis_client.zrem("monitor_schedule", str(monitor_id))
            await redis_client.delete(f"user:{user['id']}:monitors")
    return {"ok": True}

@app.get("/api/monitors")
async def get_monitors(user=Depends(get_current_user)):
    cache_key = f"user:{user['id']}:monitors"
    if redis_client:
        cached = await redis_client.get(cache_key)
        if cached:
            return JSONResponse(json.loads(cached))
    async with db_pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT m.id, m.name, m.target, m.type, m.status, m.response_ms, m.last_check,
                   COALESCE(ROUND((SUM(CASE WHEN c.status='up' THEN 1 ELSE 0 END)::float / NULLIF(COUNT(c.id),0))*100,1),100) as uptime_30d
            FROM monitors m
            LEFT JOIN checks c ON c.monitor_id = m.id AND c.checked_at > NOW() - INTERVAL '30 days'
            WHERE m.user_id=$1 AND m.enabled=TRUE
            GROUP BY m.id
        """, user["id"])
        result = {"monitors": [dict(r) for r in rows]}
        if redis_client:
            await redis_client.setex(cache_key, 30, json.dumps(result))
        return result

@app.get("/api/monitors/{monitor_id}/history")
async def get_history(monitor_id: int, period: str = "24h", user=Depends(get_current_user)):
    async with db_pool.acquire() as conn:
        owner = await conn.fetchval("SELECT user_id FROM monitors WHERE id=$1", monitor_id)
        if owner != user["id"]:
            raise HTTPException(403)
        delta = {"24h": 24, "7d": 168, "30d": 720}.get(period, 24)
        since = datetime.utcnow() - timedelta(hours=delta)
        checks = await conn.fetch("SELECT checked_at, region, response_ms, status FROM checks WHERE monitor_id=$1 AND checked_at>$2 ORDER BY checked_at", monitor_id, since)
        return {"history": [{"time": c["checked_at"].isoformat(), "region": c["region"], "response_ms": c["response_ms"], "status": c["status"]} for c in checks]}

@app.get("/api/incidents")
async def get_incidents(user=Depends(get_current_user)):
    async with db_pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT i.*, m.name as monitor_name
            FROM incidents i JOIN monitors m ON i.monitor_id = m.id
            WHERE m.user_id=$1 ORDER BY i.started_at DESC LIMIT 50
        """, user["id"])
        return {"incidents": [dict(r) for r in rows]}

@app.get("/api/workers/status")
async def workers_status():
    async with db_pool.acquire() as conn:
        workers = await conn.fetch("SELECT worker_id, region, last_heartbeat, status FROM worker_heartbeats WHERE last_heartbeat > NOW() - INTERVAL '2 minutes'")
        return {"workers": [dict(w) for w in workers]}

@app.get("/api/status")
async def public_status():
    async with db_pool.acquire() as conn:
        rows = await conn.fetch("SELECT name, status, response_ms, last_check FROM monitors WHERE enabled=TRUE")
        return {"monitors": [dict(r) for r in rows]}

@app.get("/api/health")
async def health():
    return {"status": "ok"}

# ---------- ФИНАЛЬНЫЙ ДИЗАЙН В СТИЛЕ UPTIMEROBOT ----------
HTML_APP = """<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Uppoint Monitor</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            background: #0f172a;
            font-family: 'Inter', system-ui, -apple-system, sans-serif;
            color: #f1f5f9;
        }

        /* Header */
        .header {
            background: rgba(15, 23, 42, 0.9);
            backdrop-filter: blur(10px);
            border-bottom: 1px solid #334155;
            padding: 0 24px;
            height: 60px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            z-index: 10;
        }
        .logo {
            font-size: 20px;
            font-weight: 700;
            background: linear-gradient(135deg, #3b82f6, #a855f7);
            -webkit-background-clip: text;
            background-clip: text;
            color: transparent;
        }
        .user-info {
            display: flex;
            align-items: center;
            gap: 16px;
        }
        .logout-btn {
            background: #ef4444;
            color: white;
            padding: 6px 14px;
            border-radius: 8px;
            text-decoration: none;
            font-size: 14px;
        }

        /* Sidebar */
        .sidebar {
            position: fixed;
            top: 60px;
            left: 0;
            bottom: 0;
            width: 220px;
            background: #0f172a;
            border-right: 1px solid #334155;
            padding: 24px 0;
        }
        .nav-item {
            padding: 12px 24px;
            display: flex;
            align-items: center;
            gap: 12px;
            color: #94a3b8;
            cursor: pointer;
            transition: 0.2s;
            border-left: 3px solid transparent;
        }
        .nav-item:hover {
            background: #1e293b;
            color: #f1f5f9;
        }
        .nav-item.active {
            background: #1e293b;
            color: #3b82f6;
            border-left-color: #3b82f6;
        }

        /* Main content */
        .main {
            margin-left: 220px;
            margin-top: 60px;
            padding: 32px;
        }

        /* Stats cards */
        .stats-row {
            display: flex;
            gap: 24px;
            margin-bottom: 32px;
            flex-wrap: wrap;
        }
        .stat-card {
            background: #1e293b;
            border-radius: 12px;
            padding: 20px 24px;
            flex: 1;
            min-width: 180px;
            border: 1px solid #334155;
        }
        .stat-value {
            font-size: 32px;
            font-weight: 700;
        }
        .stat-label {
            color: #94a3b8;
            font-size: 14px;
            margin-top: 8px;
        }
        .stat-badge {
            background: #334155;
            padding: 4px 8px;
            border-radius: 20px;
            font-size: 12px;
            display: inline-block;
            margin-left: 12px;
        }

        /* Monitor list */
        .monitor-item {
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 12px;
            padding: 16px 20px;
            margin-bottom: 12px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            transition: 0.2s;
        }
        .monitor-left {
            display: flex;
            align-items: center;
            gap: 20px;
            flex-wrap: wrap;
        }
        .monitor-status {
            width: 12px;
            height: 12px;
            border-radius: 50%;
        }
        .status-up {
            background: #22c55e;
            box-shadow: 0 0 0 2px #22c55e20;
        }
        .status-down {
            background: #ef4444;
            box-shadow: 0 0 0 2px #ef444420;
        }
        .monitor-name {
            font-weight: 500;
        }
        .monitor-type {
            background: #334155;
            padding: 2px 8px;
            border-radius: 20px;
            font-size: 11px;
        }
        .monitor-target {
            color: #94a3b8;
            font-size: 13px;
        }
        .monitor-time {
            font-size: 13px;
            color: #ef4444;
        }
        .uptime-badge {
            background: #0f172a;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
        }

        /* Modal (create monitor) */
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0,0,0,0.7);
            z-index: 1000;
            justify-content: center;
            align-items: center;
        }
        .modal-content {
            background: #1e293b;
            border-radius: 16px;
            width: 560px;
            max-width: 90%;
            max-height: 85vh;
            overflow-y: auto;
        }
        .modal-header {
            padding: 20px 24px;
            border-bottom: 1px solid #334155;
            font-size: 20px;
            font-weight: 500;
            display: flex;
            justify-content: space-between;
        }
        .modal-body {
            padding: 24px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        .form-group label {
            display: block;
            font-size: 13px;
            font-weight: 500;
            margin-bottom: 6px;
            color: #94a3b8;
        }
        .form-group input, .form-group select {
            width: 100%;
            padding: 10px 12px;
            background: #0f172a;
            border: 1px solid #334155;
            border-radius: 8px;
            color: white;
        }
        .type-grid {
            display: grid;
            grid-template-columns: repeat(2,1fr);
            gap: 12px;
            margin-top: 8px;
        }
        .type-option {
            padding: 12px;
            border: 1px solid #334155;
            border-radius: 12px;
            cursor: pointer;
            text-align: center;
        }
        .type-option.selected {
            border-color: #3b82f6;
            background: #3b82f620;
        }
        .interval-buttons {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
        }
        .interval-btn {
            padding: 8px 16px;
            border: 1px solid #334155;
            border-radius: 8px;
            background: #0f172a;
            cursor: pointer;
        }
        .interval-btn.selected {
            background: #3b82f6;
            border-color: #3b82f6;
        }
        .notification-row {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 12px;
        }
        .modal-footer {
            padding: 16px 24px;
            border-top: 1px solid #334155;
            display: flex;
            justify-content: flex-end;
            gap: 12px;
        }
        .btn-primary {
            background: #3b82f6;
            border: none;
            padding: 8px 20px;
            border-radius: 8px;
            color: white;
            cursor: pointer;
        }
        .btn-secondary {
            background: #334155;
            border: none;
            padding: 8px 20px;
            border-radius: 8px;
            color: white;
            cursor: pointer;
        }

        @media (max-width: 768px) {
            .sidebar { display: none; }
            .main { margin-left: 0; }
        }
    </style>
</head>
<body>

<div class="header">
    <div class="logo">Uppoint Monitor</div>
    <div class="user-info">
        <span id="userEmail">demo@uppoint.com</span>
        <a href="/logout" class="logout-btn">Sign out</a>
    </div>
</div>

<div class="sidebar">
    <div class="nav-item active" data-tab="monitors">📊 Monitoring</div>
    <div class="nav-item" data-tab="incidents">⚠️ Incidents</div>
    <div class="nav-item" data-tab="status">📄 Status pages</div>
</div>

<div class="main">
    <div id="monitorsTab">
        <div class="stats-row" id="statsContainer"></div>
        <div style="display: flex; justify-content: flex-end; margin-bottom: 20px;">
            <button class="btn-primary" id="createMonitorBtn">+ Add New Monitor</button>
        </div>
        <div id="monitorsList"></div>
    </div>

    <div id="incidentsTab" style="display: none;">
        <h2>Incident History</h2>
        <div id="incidentsList" style="margin-top: 20px;"></div>
    </div>

    <div id="statusTab" style="display: none;">
        <h2>Public Status Page</h2>
        <p style="color: #94a3b8; margin-bottom: 20px;">Current system status – all monitors</p>
        <div id="publicStatusList"></div>
    </div>
</div>

<!-- Modal Create Monitor -->
<div id="monitorModal" class="modal">
    <div class="modal-content">
        <div class="modal-header">
            <span>Create monitor</span>
            <span style="cursor:pointer" onclick="closeModal()">✕</span>
        </div>
        <div class="modal-body">
            <div class="form-group">
                <label>Monitor type</label>
                <div class="type-grid" id="typeGrid">
                    <div class="type-option selected" data-type="http">🌐 HTTP / website</div>
                    <div class="type-option" data-type="port">🔌 Port</div>
                </div>
            </div>
            <div class="form-group">
                <label>URL / target to monitor</label>
                <input type="text" id="target" placeholder="https://example.com or example.com:443">
            </div>
            <div class="form-group">
                <label>Monitor interval</label>
                <div class="interval-buttons" id="intervalGroup">
                    <button type="button" class="interval-btn" data-interval="60">1m</button>
                    <button type="button" class="interval-btn selected" data-interval="300">5m</button>
                    <button type="button" class="interval-btn" data-interval="1800">30m</button>
                    <button type="button" class="interval-btn" data-interval="3600">1h</button>
                </div>
            </div>
            <div class="form-group">
                <label>Region to monitor from</label>
                <select id="regionSelect">
                    <option value="default">Default (auto-select)</option>
                    <option value="us-east">🇺🇸 US East</option>
                    <option value="eu-west">🇪🇺 EU West</option>
                    <option value="ap-southeast">🌏 Asia Southeast</option>
                </select>
            </div>
            <div class="form-group">
                <label>How will we notify you?</label>
                <div class="notification-row">
                    <input type="checkbox" id="notifyEmail" checked> <label>E-mail</label>
                    <input type="email" id="emailContact" placeholder="your@email.com" style="width:200px; margin-left:8px">
                </div>
                <div class="notification-row">
                    <input type="checkbox" id="notifySMS"> <label>SMS message</label>
                    <input type="text" id="smsContact" placeholder="+1234567890" style="width:200px; margin-left:8px">
                </div>
                <div class="notification-row">
                    <input type="checkbox" id="notifyPush"> <label>Push (iOS/Android)</label>
                </div>
                <div>
                    <input type="checkbox" id="noDelay"> <label style="color:#ef4444">No delay, no repeat</label>
                </div>
            </div>
        </div>
        <div class="modal-footer">
            <button class="btn-secondary" onclick="closeModal()">Cancel</button>
            <button class="btn-primary" onclick="createMonitor()">Create monitor</button>
        </div>
    </div>
</div>

<script>
    const token = localStorage.getItem('token');
    if (!token) window.location.href = '/';
    let selectedType = 'http';
    let selectedInterval = 300;

    // UI helpers
    document.querySelectorAll('.type-option').forEach(opt => {
        opt.onclick = () => {
            document.querySelectorAll('.type-option').forEach(o => o.classList.remove('selected'));
            opt.classList.add('selected');
            selectedType = opt.dataset.type;
        };
    });
    document.querySelectorAll('.interval-btn').forEach(btn => {
        btn.onclick = () => {
            document.querySelectorAll('.interval-btn').forEach(b => b.classList.remove('selected'));
            btn.classList.add('selected');
            selectedInterval = parseInt(btn.dataset.interval);
        };
    });

    // Navigation tabs
    document.querySelectorAll('.nav-item').forEach(item => {
        item.onclick = () => {
            const tab = item.dataset.tab;
            document.querySelectorAll('.nav-item').forEach(i => i.classList.remove('active'));
            item.classList.add('active');
            document.getElementById('monitorsTab').style.display = tab === 'monitors' ? 'block' : 'none';
            document.getElementById('incidentsTab').style.display = tab === 'incidents' ? 'block' : 'none';
            document.getElementById('statusTab').style.display = tab === 'status' ? 'block' : 'none';
            if (tab === 'monitors') loadMonitors();
            if (tab === 'incidents') loadIncidents();
            if (tab === 'status') loadPublicStatus();
        };
    });

    // API functions
    async function apiCall(endpoint, opts = {}) {
        const res = await fetch(endpoint, {
            ...opts,
            headers: { 'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json' }
        });
        if (res.status === 401) {
            localStorage.removeItem('token');
            window.location.href = '/';
            throw new Error('Unauthorized');
        }
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || 'Error');
        return data;
    }

    async function loadMonitors() {
        const data = await apiCall('/api/monitors');
        const monitors = data.monitors || [];
        const total = monitors.length;
        const up = monitors.filter(m => m.status === 'up').length;
        const down = monitors.filter(m => m.status === 'down').length;
        const paused = monitors.filter(m => m.status === 'pending').length;
        const downPercent = total ? ((down / total) * 100).toFixed(1) : 0;

        document.getElementById('statsContainer').innerHTML = `
            <div class="stat-card"><div class="stat-value">${down}</div><div class="stat-label">Down</div></div>
            <div class="stat-card"><div class="stat-value">${up}</div><div class="stat-label">Up</div></div>
            <div class="stat-card"><div class="stat-value">${paused}</div><div class="stat-label">Paused</div></div>
            <div class="stat-card"><div class="stat-value">${downPercent}%</div><div class="stat-label">Last 24h downtime</div></div>
        `;

        let html = '';
        for (let m of monitors) {
            const statusClass = m.status === 'up' ? 'status-up' : 'status-down';
            const timeText = m.status === 'down' && m.last_check ? new Date(m.last_check).toLocaleString() : '';
            html += `
                <div class="monitor-item">
                    <div class="monitor-left">
                        <div class="monitor-status ${statusClass}"></div>
                        <span class="monitor-name">${escapeHtml(m.name)}</span>
                        <span class="monitor-type">${m.type.toUpperCase()}</span>
                        <span class="monitor-target">${escapeHtml(m.target)}</span>
                    </div>
                    <div>
                        ${m.status === 'down' ? `<div class="monitor-time">${timeText}</div>` : ''}
                        <span class="uptime-badge">${m.uptime_30d || 100}% uptime</span>
                    </div>
                </div>
            `;
        }
        document.getElementById('monitorsList').innerHTML = html || '<div style="text-align:center; padding:40px;">No monitors yet</div>';
    }

    async function loadIncidents() {
        const data = await apiCall('/api/incidents');
        const incidents = data.incidents || [];
        let html = '';
        for (let i of incidents) {
            const duration = i.duration_sec ? `${Math.floor(i.duration_sec/60)}m ${i.duration_sec%60}s` : 'Ongoing';
            html += `
                <div style="background: #1e293b; border-radius: 12px; padding: 16px; margin-bottom: 12px;">
                    <strong>${escapeHtml(i.monitor_name)}</strong>
                    <div>⬇️ Down: ${new Date(i.started_at).toLocaleString()}</div>
                    <div>⬆️ Up: ${i.ended_at ? new Date(i.ended_at).toLocaleString() : '—'}</div>
                    <div>⏱ Duration: ${duration}</div>
                </div>
            `;
        }
        document.getElementById('incidentsList').innerHTML = html || '<div style="color:#64748b">No incidents</div>';
    }

    async function loadPublicStatus() {
        const res = await fetch('/api/status');
        const data = await res.json();
        const monitors = data.monitors || [];
        let html = '';
        for (let m of monitors) {
            html += `
                <div style="background: #1e293b; border-radius: 12px; padding: 16px; margin-bottom: 12px;">
                    <strong>${escapeHtml(m.name)}</strong>
                    <span style="float:right;" class="${m.status === 'up' ? 'status-up' : 'status-down'}">${m.status.toUpperCase()}</span>
                    <div>Response: ${m.response_ms}ms</div>
                    <div>Last check: ${new Date(m.last_check).toLocaleString()}</div>
                </div>
            `;
        }
        document.getElementById('publicStatusList').innerHTML = html || '<div style="text-align:center;">No monitors</div>';
    }

    async function createMonitor() {
        const target = document.getElementById('target').value.trim();
        if (!target) { alert('Enter target'); return; }
        const emailContact = document.getElementById('emailContact').value;
        const notifyEmail = document.getElementById('notifyEmail').checked;
        const region = document.getElementById('regionSelect').value;
        const regions = region === 'default' ? ['us-east','eu-west','ap-southeast'] : [region];
        const monitorData = {
            name: target.split('/')[0],
            target: target,
            type: selectedType,
            interval_sec: selectedInterval,
            regions: regions
        };
        await apiCall('/api/monitors', { method: 'POST', body: JSON.stringify(monitorData) });
        if (notifyEmail && emailContact) {
            await apiCall('/api/alerts', { method: 'POST', body: JSON.stringify({ monitor_id: 0, channel: 'email', contact: emailContact }) });
        }
        closeModal();
        loadMonitors();
    }

    function openModal() { document.getElementById('monitorModal').style.display = 'flex'; }
    function closeModal() { document.getElementById('monitorModal').style.display = 'none'; }
    function escapeHtml(t) { if(!t) return ''; return t.replace(/[&<>]/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[m])); }

    document.getElementById('createMonitorBtn').onclick = openModal;
    loadMonitors();
    setInterval(loadMonitors, 30000);
</script>
</body>
</html>
"""

@app.get("/")
async def root():
    return HTMLResponse(HTML_APP)

@app.get("/status")
async def status_page():
    return HTMLResponse('<html><body><h1>Публичный статус</h1><div id="status"></div><script>fetch("/api/status").then(r=>r.json()).then(data=>{document.getElementById("status").innerHTML=data.monitors.map(m=>`<div><b>${m.name}</b> ${m.status.toUpperCase()} ${m.response_ms}ms</div>`).join("")});setInterval(()=>location.reload(),30000);</script></body></html>')

@app.get("/logout")
async def logout():
    return HTMLResponse('<script>localStorage.removeItem("token");window.location.href="/";</script>')

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--worker", action="store_true", help="Run as worker only")
    parser.add_argument("--scheduler", action="store_true", help="Run scheduler only")
    parser.add_argument("--aggregator", action="store_true", help="Run aggregator only")
    args = parser.parse_args()

    if args.worker:
        async def run_worker():
            global redis_client, db_pool
            redis_client = await wait_for_redis()
            await init_db()
            worker_id = f"worker_{REGION}_{secrets.token_hex(4)}"
            if redis_client:
                try:
                    await redis_client.xgroup_create("checks_stream", "workers", id="0", mkstream=True)
                except:
                    pass
            asyncio.create_task(update_heartbeat(worker_id))
            await worker_task(worker_id)
        asyncio.run(run_worker())
    elif args.scheduler:
        async def run_scheduler():
            global redis_client, db_pool
            redis_client = await wait_for_redis()
            await init_db()
            if redis_client:
                await populate_schedule()
                await scheduler_task()
            else:
                logger.warning("Scheduler requires Redis, exiting")
        asyncio.run(run_scheduler())
    elif args.aggregator:
        async def run_aggregator():
            await init_db()
            await aggregator_task()
        asyncio.run(run_aggregator())
    else:
        import uvicorn
        uvicorn.run(app, host="0.0.0.0", port=8000)
