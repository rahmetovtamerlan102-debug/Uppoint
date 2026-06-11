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

# ---------- НОВЫЙ ПРЕМИУМ ДИЗАЙН (две колонки, современный дашборд) ----------
HTML_APP = """<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
    <title>Uppoint — мониторинг</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }

        :root {
            --bg: #05060a;
            --card: rgba(255, 255, 255, 0.04);
            --card2: rgba(255, 255, 255, 0.06);
            --border: rgba(255, 255, 255, 0.08);
            --text: #e5e7eb;
            --muted: #9ca3af;
            --blue: #6366f1;
            --green: #22c55e;
            --red: #ef4444;
            --yellow: #f59e0b;
            --radius-xl: 24px;
            --radius-2xl: 32px;
            --shadow: 0 20px 60px rgba(0,0,0,0.5);
        }

        body {
            background:
                radial-gradient(circle at 20% 10%, rgba(99,102,241,0.25), transparent 40%),
                radial-gradient(circle at 80% 80%, rgba(34,197,94,0.12), transparent 40%),
                radial-gradient(circle at 50% 50%, rgba(239,68,68,0.08), transparent 60%),
                var(--bg);
            font-family: 'Inter', system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            color: var(--text);
            min-height: 100vh;
            letter-spacing: -0.01em;
        }

        /* Общие карточки */
        .card {
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: var(--radius-xl);
            backdrop-filter: blur(20px);
            box-shadow: var(--shadow);
            transition: all 0.2s ease;
        }
        .card:hover {
            transform: translateY(-3px);
            border-color: rgba(99,102,241,0.4);
        }

        /* Кнопки */
        .btn-primary {
            background: linear-gradient(135deg, var(--blue), #22c55e);
            border: none;
            padding: 14px;
            border-radius: 16px;
            color: white;
            font-weight: 600;
            cursor: pointer;
            transition: 0.2s;
            width: 100%;
        }
        .btn-primary:hover {
            transform: scale(1.02);
            background: linear-gradient(135deg, #4f46e5, #16a34a);
        }
        .btn-outline {
            background: rgba(255,255,255,0.05);
            border: 1px solid var(--border);
            padding: 10px;
            border-radius: 16px;
            color: var(--text);
            cursor: pointer;
            transition: 0.2s;
        }
        .btn-outline:hover {
            background: rgba(255,255,255,0.1);
        }

        /* Инпуты */
        input, select {
            width: 100%;
            padding: 14px 16px;
            margin: 10px 0;
            border-radius: 16px;
            border: 1px solid var(--border);
            background: rgba(255,255,255,0.03);
            color: white;
            outline: none;
            transition: 0.2s;
        }
        input:focus, select:focus {
            border-color: var(--blue);
            box-shadow: 0 0 0 4px rgba(99,102,241,0.15);
        }

        /* Базовые стили экранов */
        .screen { display: none; animation: fadeIn 0.2s ease; }
        .screen.active { display: block; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: translateY(0); } }

        /* === AUTH (две колонки) === */
        .auth-wrap {
            display: grid;
            grid-template-columns: 1.2fr 1fr;
            min-height: 100vh;
            gap: 40px;
            padding: 40px;
        }
        .auth-left {
            display: flex;
            flex-direction: column;
            justify-content: center;
        }
        .brand {
            font-size: 18px;
            opacity: 0.7;
            margin-bottom: 20px;
            letter-spacing: -0.5px;
        }
        .auth-left h1 {
            font-size: 48px;
            line-height: 1.1;
            margin-bottom: 12px;
            background: linear-gradient(135deg, #fff, var(--blue));
            -webkit-background-clip: text;
            background-clip: text;
            color: transparent;
        }
        .auth-left p {
            color: var(--muted);
            max-width: 400px;
        }
        .auth-right {
            padding: 32px;
            border-radius: var(--radius-2xl);
            background: var(--card);
            backdrop-filter: blur(20px);
            border: 1px solid var(--border);
        }
        .tabs {
            display: flex;
            gap: 12px;
            margin-bottom: 28px;
        }
        .tab {
            background: transparent;
            border: none;
            padding: 8px 20px;
            border-radius: 40px;
            color: var(--muted);
            cursor: pointer;
            font-weight: 500;
            transition: 0.2s;
        }
        .tab.active {
            background: rgba(99,102,241,0.2);
            color: var(--blue);
            border: 1px solid var(--border);
        }
        .error {
            color: var(--red);
            font-size: 13px;
            margin-top: 8px;
        }
        .demo-hint {
            text-align: center;
            font-size: 13px;
            margin-top: 20px;
            color: var(--muted);
        }

        /* === DASHBOARD === */
        .dashboard-container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px 24px 80px;
        }
        .flex-between {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .avatar {
            width: 44px;
            height: 44px;
            background: linear-gradient(135deg, var(--blue), #22c55e);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 700;
            font-size: 18px;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 20px;
            margin-bottom: 32px;
        }
        .stat-card {
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 20px;
            padding: 18px;
            transition: 0.2s;
        }
        .stat-value {
            font-size: 36px;
            font-weight: 700;
            letter-spacing: -1px;
        }
        .stat-label {
            color: var(--muted);
            font-size: 13px;
            margin-top: 6px;
        }
        .green { color: var(--green); }
        .red { color: var(--red); }

        .glass-card {
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: var(--radius-xl);
            padding: 24px;
            margin-bottom: 28px;
            backdrop-filter: blur(16px);
        }
        .circle-uptime {
            width: 140px;
            height: 140px;
            border-radius: 50%;
            margin: 0 auto 16px;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .circle-uptime-inner {
            width: 110px;
            height: 110px;
            background: var(--bg);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 28px;
            font-weight: 700;
        }

        .monitor-card {
            background: rgba(0,0,0,0.3);
            border-radius: 20px;
            padding: 18px;
            margin-bottom: 12px;
            cursor: pointer;
            transition: 0.15s;
            border: 1px solid transparent;
        }
        .monitor-card:hover {
            border-color: var(--border);
            background: rgba(255,255,255,0.02);
        }
        .status {
            position: relative;
            padding: 4px 12px;
            border-radius: 40px;
            font-size: 12px;
            font-weight: 500;
            overflow: hidden;
        }
        .online {
            background: rgba(34,197,94,0.15);
            color: var(--green);
        }
        .online::after {
            content: "";
            position: absolute;
            inset: 0;
            background: rgba(34,197,94,0.15);
            animation: pulse 2s infinite;
        }
        .down {
            background: rgba(239,68,68,0.15);
            color: var(--red);
        }
        @keyframes pulse {
            0% { opacity: 0.3; }
            50% { opacity: 0.6; }
            100% { opacity: 0.3; }
        }
        .delete-icon {
            color: var(--red);
            cursor: pointer;
            font-size: 18px;
        }
        .skeleton {
            background: rgba(255,255,255,0.05);
            border-radius: 16px;
            padding: 16px;
            margin-bottom: 12px;
            animation: pulse 1.5s infinite;
        }
        /* Modal */
        .modal {
            display: none;
            position: fixed;
            top: 0; left: 0; right: 0; bottom: 0;
            background: rgba(0,0,0,0.8);
            backdrop-filter: blur(12px);
            z-index: 1000;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .modal-content {
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: var(--radius-2xl);
            width: 100%;
            max-width: 550px;
            max-height: 80vh;
            overflow-y: auto;
            padding: 28px;
            backdrop-filter: blur(20px);
        }
        .chart-container { height: 260px; margin: 20px 0; }
        .bottom-nav {
            position: fixed;
            bottom: 0;
            left: 0;
            right: 0;
            background: rgba(5,6,10,0.85);
            backdrop-filter: blur(20px);
            border-top: 1px solid var(--border);
            display: flex;
            justify-content: space-around;
            padding: 10px 12px 22px;
            z-index: 20;
        }
        .nav-item {
            text-align: center;
            font-size: 12px;
            color: var(--muted);
            cursor: pointer;
            flex: 1;
        }
        .nav-item.active { color: var(--blue); }
        .nav-icon { font-size: 24px; display: block; margin-bottom: 4px; }
        .toast {
            position: fixed;
            bottom: 80px;
            left: 50%;
            transform: translateX(-50%);
            background: #1e293b;
            border: 1px solid var(--border);
            border-radius: 60px;
            padding: 12px 24px;
            color: white;
            z-index: 2000;
            opacity: 0;
            transition: opacity 0.2s;
            pointer-events: none;
            white-space: nowrap;
        }
        @media (max-width: 860px) {
            .auth-wrap { grid-template-columns: 1fr; padding: 24px; gap: 20px; }
            .auth-left h1 { font-size: 36px; }
            .stats-grid { grid-template-columns: 1fr 1fr; gap: 12px; }
        }
        @media (max-width: 560px) {
            .stats-grid { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>

<!-- TOAST -->
<div id="toast" class="toast"></div>

<!-- АУТЕНТИФИКАЦИЯ (две колонки) -->
<div id="authScreen" class="screen active">
    <div class="auth-wrap">
        <div class="auth-left">
            <div class="brand">● Uppoint</div>
            <h1>Realtime system monitoring</h1>
            <p>Track uptime, incidents and performance globally. Modern observability at your fingertips.</p>
        </div>
        <div class="auth-right">
            <div class="tabs">
                <button id="tabLogin" class="tab active">Вход</button>
                <button id="tabRegister" class="tab">Регистрация</button>
            </div>
            <div id="loginForm">
                <input type="email" id="loginEmail" placeholder="Email" value="demo@uppoint.com">
                <input type="password" id="loginPassword" placeholder="Пароль" value="demo123">
                <button class="btn-primary" id="doLoginBtn">Войти</button>
                <div id="loginError" class="error"></div>
            </div>
            <div id="registerForm" style="display:none">
                <input type="text" id="regName" placeholder="Имя">
                <input type="email" id="regEmail" placeholder="Email">
                <input type="password" id="regPassword" placeholder="Пароль">
                <input type="password" id="regPassword2" placeholder="Повторите пароль">
                <button class="btn-primary" id="doRegisterBtn">Создать аккаунт</button>
                <div id="regError" class="error"></div>
            </div>
            <div class="demo-hint">demo@uppoint.com / demo123</div>
        </div>
    </div>
</div>

<!-- ОСНОВНОЙ ДАШБОРД -->
<div id="appScreen" class="screen" style="padding-bottom: 80px;">
    <div class="dashboard-container">
        <div class="flex-between" style="margin-bottom: 28px;">
            <div class="brand" style="font-size: 24px;">● Uppoint</div>
            <div class="avatar" id="userAvatar">A</div>
        </div>
        <h1 style="font-size: 32px; margin-bottom: 6px;">Дашборд</h1>
        <p style="color:var(--muted); margin-bottom: 32px;">Обзор всех систем</p>

        <div class="stats-grid" id="statsGrid"><!-- скелетоны будут добавлены --></div>

        <div class="glass-card" style="text-align:center">
            <div class="circle-uptime" id="uptimeCircle"></div>
            <div class="green" id="uptimeChange">▲ загрузка...</div>
        </div>

        <div class="glass-card" style="padding: 20px;">
            <div class="flex-between" style="margin-bottom: 18px;">
                <h3>Мониторы</h3>
                <button class="btn-primary" style="width: auto; padding: 8px 20px;" id="addMonitorBtn">+ Добавить</button>
            </div>
            <div id="dashboardMonitorsList"><div class="skeleton"></div><div class="skeleton"></div></div>
        </div>
    </div>
</div>

<!-- МОДАЛКИ -->
<div id="addMonitorModal" class="modal">
    <div class="modal-content">
        <h3>➕ Новый монитор</h3>
        <input type="text" id="monName" placeholder="Название">
        <input type="text" id="monTarget" placeholder="URL или host:port">
        <select id="monType">
            <option value="http">HTTP/HTTPS</option>
            <option value="port">TCP порт</option>
        </select>
        <input type="number" id="monInterval" placeholder="Интервал (сек)" value="300">
        <button class="btn-primary" id="saveMonitorModalBtn">Создать</button>
        <button class="btn-outline" id="closeModalBtn" style="margin-top: 12px;">Отмена</button>
    </div>
</div>
<div id="detailModal" class="modal">
    <div class="modal-content">
        <div class="flex-between">
            <h3 id="detailTitle">Монитор</h3>
            <span id="closeDetailBtn" style="cursor:pointer">✕</span>
        </div>
        <div class="chart-container"><canvas id="historyChart"></canvas></div>
        <div id="detailInfo"></div>
        <button class="btn-outline" id="deleteMonitorDetailBtn" style="border-color:var(--red); color:var(--red); margin-top: 16px;">Удалить</button>
    </div>
</div>

<!-- НИЖНЯЯ НАВИГАЦИЯ -->
<div class="bottom-nav" id="bottomNav" style="display: none;">
    <div class="nav-item active" data-nav="dashboard"><span class="nav-icon">📊</span>Дашборд</div>
    <div class="nav-item" data-nav="monitors"><span class="nav-icon">📡</span>Мониторы</div>
    <div class="nav-item" data-nav="incidents"><span class="nav-icon">⚠️</span>Инциденты</div>
    <div class="nav-item" data-nav="profile"><span class="nav-icon">👤</span>Профиль</div>
</div>

<script>
    // ---------- Глобальные ----------
    let token = localStorage.getItem('token');
    let ws = null;
    let currentChart = null;
    let currentMonitorId = null;

    function showToast(msg, duration = 3000) {
        const toast = document.getElementById('toast');
        toast.innerText = msg;
        toast.style.opacity = '1';
        setTimeout(() => { toast.style.opacity = '0'; }, duration);
    }

    // ---------- API ----------
    async function apiCall(endpoint, options = {}) {
        const headers = { 'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json' };
        const res = await fetch(endpoint, { ...options, headers });
        if (res.status === 401) {
            localStorage.removeItem('token');
            window.location.reload();
            throw new Error('Unauthorized');
        }
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || 'Ошибка');
        return data;
    }

    // ---------- WebSocket ----------
    function connectWebSocket() {
        if (ws) ws.close();
        ws = new WebSocket(`ws://${window.location.host}/ws`);
        ws.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                if (data.monitor_id) { loadDashboard(); if (document.querySelector('.nav-item.active')?.dataset.nav === 'monitors') showMonitorsPage(); }
                if (data.incident) showToast('Инцидент обновлён', 2000);
            } catch(e) {}
        };
        ws.onclose = () => setTimeout(connectWebSocket, 3000);
    }

    // ---------- Загрузка дашборда ----------
    async function loadDashboard() {
        try {
            const data = await apiCall('/api/monitors');
            const monitors = data.monitors || [];
            const total = monitors.length;
            const upCount = monitors.filter(m => m.status === 'up').length;
            const downCount = total - upCount;
            const avgUptime = total ? (monitors.reduce((s,m)=> s + (m.uptime_30d || 100),0)/total).toFixed(1) : 100;

            const statsHtml = `
                <div class="stat-card"><div class="stat-label">Всего</div><div class="stat-value">${total}</div><div class="green">▲</div></div>
                <div class="stat-card"><div class="stat-label">Работают</div><div class="stat-value green">${upCount}</div><div class="green">${total ? Math.round(upCount/total*100) : 0}%</div></div>
                <div class="stat-card"><div class="stat-label">Не работают</div><div class="stat-value red">${downCount}</div><div class="red">${downCount>0?'Инцидент':'Нет'}</div></div>
                <div class="stat-card"><div class="stat-label">Аптайм</div><div class="stat-value">${avgUptime}%</div><div class="green">SLA</div></div>
            `;
            document.getElementById('statsGrid').innerHTML = statsHtml;

            const deg = (avgUptime / 100) * 360;
            const circleDiv = document.getElementById('uptimeCircle');
            circleDiv.style.background = `conic-gradient(#6366f1 0deg, #22c55e ${deg}deg, #1e293b ${deg}deg)`;
            circleDiv.innerHTML = `<div class="circle-uptime-inner">${avgUptime}%</div>`;
            document.getElementById('uptimeChange').innerHTML = `▲ за 30 дней`;

            const listHtml = monitors.slice(0,3).map(m => `
                <div class="monitor-card" data-id="${m.id}">
                    <div class="flex-between">
                        <span class="monitor-name">${escapeHtml(m.name)}</span>
                        <span class="status ${m.status === 'up' ? 'online' : 'down'}">${m.status === 'up' ? 'Online' : 'Down'}</span>
                    </div>
                    <div style="display:flex; gap:16px; margin-top: 10px; font-size:13px; color:var(--muted);">
                        <span>${m.uptime_30d || 100}%</span>
                        <span>${m.response_ms || 0} ms</span>
                    </div>
                </div>
            `).join('');
            document.getElementById('dashboardMonitorsList').innerHTML = listHtml || '<div class="glass-card" style="text-align:center">Нет мониторов. Добавьте первый!</div>';
            document.querySelectorAll('#dashboardMonitorsList .monitor-card').forEach(card => {
                card.addEventListener('click', () => showMonitorDetail(card.dataset.id));
            });
        } catch(e) { console.error(e); }
    }

    // ---------- Страница всех мониторов ----------
    async function showMonitorsPage() {
        const data = await apiCall('/api/monitors');
        const monitors = data.monitors || [];
        const container = document.getElementById('monitorsContainer');
        if (!container) return;
        if (monitors.length === 0) {
            container.innerHTML = '<div class="glass-card">Нет мониторов. Добавьте!</div>';
            return;
        }
        container.innerHTML = monitors.map(m => `
            <div class="monitor-card" data-id="${m.id}">
                <div class="flex-between">
                    <span class="monitor-name">${escapeHtml(m.name)}</span>
                    <span class="status ${m.status === 'up' ? 'online' : 'down'}">${m.status === 'up' ? 'Online' : 'Down'}</span>
                </div>
                <div style="display:flex; gap:16px; margin-top: 10px; font-size:13px;">
                    <span>${m.uptime_30d || 100}%</span>
                    <span>${m.response_ms || 0} ms</span>
                </div>
                <div style="text-align:right; margin-top:8px">
                    <span class="delete-icon" data-id="${m.id}">🗑️</span>
                </div>
            </div>
        `).join('');
        document.querySelectorAll('#monitorsContainer .delete-icon').forEach(icon => {
            icon.addEventListener('click', async (e) => {
                e.stopPropagation();
                const id = icon.dataset.id;
                if (confirm('Удалить монитор?')) {
                    await apiCall(`/api/monitors/${id}`, { method: 'DELETE' });
                    showMonitorsPage();
                    loadDashboard();
                    showToast('Монитор удалён', 2000);
                }
            });
        });
        document.querySelectorAll('#monitorsContainer .monitor-card').forEach(card => {
            card.addEventListener('click', () => showMonitorDetail(card.dataset.id));
        });
    }

    // ---------- Детали и график ----------
    async function showMonitorDetail(id) {
        currentMonitorId = id;
        const data = await apiCall(`/api/monitors/${id}/history?period=24h`);
        const history = data.history || [];
        const labels = history.slice(-60).map(h => new Date(h.time).toLocaleTimeString());
        const values = history.slice(-60).map(h => h.response_ms || 0);
        const ctx = document.getElementById('historyChart').getContext('2d');
        if (currentChart) currentChart.destroy();
        currentChart = new Chart(ctx, {
            type: 'line',
            data: { labels, datasets: [{ label: 'Время ответа (мс)', data: values, borderColor: '#6366f1', tension: 0.2, fill: true, backgroundColor: 'rgba(99,102,241,0.1)' }] },
            options: { responsive: true, maintainAspectRatio: false }
        });
        const monitors = await apiCall('/api/monitors');
        const mon = monitors.monitors.find(m => m.id == id);
        if (mon) {
            document.getElementById('detailTitle').innerHTML = escapeHtml(mon.name);
            document.getElementById('detailInfo').innerHTML = `
                <div class="flex-between"><span>Статус:</span><span class="status ${mon.status === 'up' ? 'online' : 'down'}">${mon.status.toUpperCase()}</span></div>
                <div class="flex-between"><span>Аптайм 30д:</span><span>${mon.uptime_30d || 100}%</span></div>
                <div class="flex-between"><span>Ответ:</span><span>${mon.response_ms || 0} ms</span></div>
                <div class="flex-between"><span>Цель:</span><span>${escapeHtml(mon.target)}</span></div>
            `;
        }
        document.getElementById('detailModal').style.display = 'flex';
    }

    async function deleteCurrentMonitor() {
        if (!currentMonitorId) return;
        if (confirm('Удалить монитор?')) {
            await apiCall(`/api/monitors/${currentMonitorId}`, { method: 'DELETE' });
            document.getElementById('detailModal').style.display = 'none';
            loadDashboard();
            if (document.querySelector('.nav-item.active')?.dataset.nav === 'monitors') showMonitorsPage();
            showToast('Монитор удалён', 2000);
        }
    }

    // ---------- Инциденты ----------
    async function showIncidentsPage() {
        const data = await apiCall('/api/incidents');
        const incidents = data.incidents || [];
        const container = document.getElementById('incidentsContainer');
        if (!container) return;
        if (incidents.length === 0) {
            container.innerHTML = '<div class="glass-card">Нет инцидентов</div>';
            return;
        }
        container.innerHTML = incidents.map(i => `
            <div class="card" style="padding: 18px; margin-bottom: 12px;">
                <div class="flex-between"><strong>${escapeHtml(i.monitor_name)}</strong><span class="status ${i.ended_at ? 'online' : 'down'}">${i.ended_at ? 'Восстановлен' : 'Падение'}</span></div>
                <div style="margin-top: 12px; font-size:13px; color:var(--muted); display:flex; flex-wrap:wrap; gap:16px;">
                    <span>⬇️ ${new Date(i.started_at).toLocaleString()}</span>
                    <span>⬆️ ${i.ended_at ? new Date(i.ended_at).toLocaleString() : '—'}</span>
                    <span>⏱ ${i.duration_sec ? Math.floor(i.duration_sec/60)+'м '+i.duration_sec%60+'с' : 'Идёт'}</span>
                    <span>📍 ${i.region || 'все'}</span>
                </div>
            </div>
        `).join('');
    }

    // ---------- Профиль ----------
    function showProfilePage() {
        const profileDiv = document.getElementById('profileInfo');
        if (!profileDiv) return;
        profileDiv.innerHTML = `
            <div class="glass-card" style="text-align:center">
                <div class="avatar" style="width:80px;height:80px;font-size:36px;margin:0 auto 16px;">${localStorage.getItem('userName')?.[0] || 'U'}</div>
                <h3>${localStorage.getItem('userName') || 'Пользователь'}</h3>
                <button class="btn-outline" id="logoutBtn" style="margin-top: 20px;">Выйти</button>
            </div>
        `;
        document.getElementById('logoutBtn')?.addEventListener('click', () => {
            localStorage.removeItem('token');
            window.location.reload();
        });
    }

    // ---------- Навигация SPA ----------
    function showScreen(screenId) {
        document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
        if (screenId === 'auth') {
            document.getElementById('authScreen').classList.add('active');
            document.getElementById('bottomNav').style.display = 'none';
            return;
        }
        document.getElementById('appScreen').classList.add('active');
        document.getElementById('bottomNav').style.display = 'flex';
        document.querySelectorAll('.nav-item').forEach(item => {
            item.classList.toggle('active', item.dataset.nav === screenId);
        });
        if (screenId === 'dashboard') loadDashboard();
        if (screenId === 'monitors') showMonitorsPage();
        if (screenId === 'incidents') showIncidentsPage();
        if (screenId === 'profile') showProfilePage();
    }

    // ---------- Добавление монитора ----------
    async function addMonitor() {
        const name = document.getElementById('monName').value.trim();
        const target = document.getElementById('monTarget').value.trim();
        const type = document.getElementById('monType').value;
        const interval_sec = parseInt(document.getElementById('monInterval').value);
        if (!target) { showToast('Введите цель', 2000); return; }
        await apiCall('/api/monitors', {
            method: 'POST',
            body: JSON.stringify({ name: name || target, target, type, interval_sec })
        });
        document.getElementById('addMonitorModal').style.display = 'none';
        loadDashboard();
        if (document.querySelector('.nav-item.active')?.dataset.nav === 'monitors') showMonitorsPage();
        showToast('Монитор добавлен', 2000);
    }

    // ---------- Аутентификация ----------
    async function login() {
        const email = document.getElementById('loginEmail').value;
        const password = document.getElementById('loginPassword').value;
        try {
            const res = await fetch('/api/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email, password })
            });
            const data = await res.json();
            if (!res.ok) throw new Error(data.detail);
            token = data.access_token;
            localStorage.setItem('token', token);
            localStorage.setItem('userName', email.split('@')[0]);
            document.getElementById('userAvatar').innerText = email.charAt(0).toUpperCase();
            connectWebSocket();
            showScreen('dashboard');
            showToast('Добро пожаловать!', 2000);
        } catch(e) {
            document.getElementById('loginError').innerText = e.message;
        }
    }

    async function register() {
        const name = document.getElementById('regName').value;
        const email = document.getElementById('regEmail').value;
        const pwd = document.getElementById('regPassword').value;
        const pwd2 = document.getElementById('regPassword2').value;
        if (!name || !email || !pwd || pwd !== pwd2) {
            document.getElementById('regError').innerText = 'Заполните все поля и проверьте пароль';
            return;
        }
        try {
            const res = await fetch('/api/register', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email, password: pwd })
            });
            const data = await res.json();
            if (!res.ok) throw new Error(data.detail);
            token = data.access_token;
            localStorage.setItem('token', token);
            localStorage.setItem('userName', name);
            document.getElementById('userAvatar').innerText = name.charAt(0).toUpperCase();
            connectWebSocket();
            showScreen('dashboard');
            showToast('Аккаунт создан!', 2000);
        } catch(e) {
            document.getElementById('regError').innerText = e.message;
        }
    }

    // ---------- Инициализация ----------
    function init() {
        if (token) {
            try { connectWebSocket(); } catch(e) {}
            showScreen('dashboard');
        } else {
            showScreen('auth');
        }
        const containers = ['monitorsContainer', 'incidentsContainer', 'profileInfo'];
        containers.forEach(id => {
            if (!document.getElementById(id)) {
                const div = document.createElement('div');
                div.id = id;
                document.getElementById('appScreen').appendChild(div);
            }
        });
        document.getElementById('doLoginBtn').onclick = login;
        document.getElementById('doRegisterBtn').onclick = register;
        document.getElementById('tabLogin').onclick = () => {
            document.getElementById('loginForm').style.display = 'block';
            document.getElementById('registerForm').style.display = 'none';
            document.getElementById('tabLogin').classList.add('active');
            document.getElementById('tabRegister').classList.remove('active');
        };
        document.getElementById('tabRegister').onclick = () => {
            document.getElementById('loginForm').style.display = 'none';
            document.getElementById('registerForm').style.display = 'block';
            document.getElementById('tabRegister').classList.add('active');
            document.getElementById('tabLogin').classList.remove('active');
        };
        document.getElementById('addMonitorBtn').onclick = () => document.getElementById('addMonitorModal').style.display = 'flex';
        document.getElementById('saveMonitorModalBtn').onclick = addMonitor;
        document.getElementById('closeModalBtn').onclick = () => document.getElementById('addMonitorModal').style.display = 'none';
        document.getElementById('closeDetailBtn').onclick = () => document.getElementById('detailModal').style.display = 'none';
        document.getElementById('deleteMonitorDetailBtn').onclick = deleteCurrentMonitor;
        document.querySelectorAll('.nav-item').forEach(item => {
            item.onclick = () => showScreen(item.dataset.nav);
        });
        const origShowScreen = showScreen;
        window.showScreen = function(screenId) {
            origShowScreen(screenId);
            if (screenId === 'monitors') document.getElementById('monitorsContainer').style.display = 'block';
            if (screenId === 'incidents') document.getElementById('incidentsContainer').style.display = 'block';
            if (screenId === 'profile') document.getElementById('profileInfo').style.display = 'block';
            if (screenId === 'dashboard') document.getElementById('dashboardMonitorsList').style.display = 'block';
        };
        loadDashboard();
    }

    function escapeHtml(str) { return String(str).replace(/[&<>]/g, m => m==='&'?'&amp;': m==='<'?'&lt;':'&gt;'); }
    init();
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
