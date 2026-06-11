#!/usr/bin/env python3
import os
import sys
import asyncio
import json
import secrets
import random
import argparse
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

# ---------- GLOBAL HTTP SESSION ----------
async def get_http_session():
    global http_session
    if http_session is None:
        connector = aiohttp.TCPConnector(limit=200, limit_per_host=50, ttl_dns_cache=300)
        http_session = aiohttp.ClientSession(connector=connector)
    return http_session

# ---------- PER-HOST RATE LIMIT ----------
async def check_host_rate_limit(target: str) -> bool:
    from urllib.parse import urlparse
    host = urlparse(target).hostname or target.split(':')[0]
    key = f"rate_limit:{host}"
    current = await redis_client.incr(key)
    if current == 1:
        await redis_client.expire(key, 60)
    return current <= HOST_RATE_LIMIT

# ---------- MODELS ----------
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

# ---------- DATABASE ----------
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
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS monitors (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                target TEXT NOT NULL,
                type TEXT NOT NULL,
                keyword TEXT,
                regions TEXT[] DEFAULT $1,
                interval_sec INTEGER DEFAULT 300,
                timeout_sec INTEGER DEFAULT 10,
                status TEXT DEFAULT 'pending',
                response_ms INTEGER DEFAULT 0,
                last_check TIMESTAMP,
                fail_count INTEGER DEFAULT 0,
                enabled BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT NOW()
            )
        """, ALL_REGIONS)
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
            await conn.execute(
                "INSERT INTO users (email, password_hash) VALUES ($1, $2)",
                "demo@uppoint.com", pwd_context.hash("demo123")
            )
        # Create partitions for next months
        start_date = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        for i in range(13):
            part_start = start_date + timedelta(days=30*i)
            part_end = part_start + timedelta(days=30)
            part_name = f"checks_{part_start.strftime('%Y_%m')}"
            await conn.execute(f"""
                CREATE TABLE IF NOT EXISTS {part_name} PARTITION OF checks
                FOR VALUES FROM ('{part_start.isoformat()}') TO ('{part_end.isoformat()}')
            """)

# ---------- WORKER HEARTBEAT ----------
async def update_heartbeat(worker_id: str):
    while True:
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

# ---------- AUTH ----------
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

# ---------- CHECK FUNCTIONS ----------
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

# ---------- WORKER TASK ----------
async def worker_task(worker_id: str):
    await update_heartbeat(worker_id)
    while True:
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
                                                await redis_client.publish("incidents", json.dumps({"monitor_id": monitor_id, "status": "down"}))
                                            elif monitor["status"] == "down" and status == "up":
                                                await conn.execute("""
                                                    UPDATE incidents SET ended_at=$1, duration_sec=EXTRACT(EPOCH FROM ($1 - started_at))
                                                    WHERE monitor_id=$2 AND region=$3 AND ended_at IS NULL
                                                """, now, monitor_id, region)
                                                await redis_client.publish("incidents", json.dumps({"monitor_id": monitor_id, "status": "up"}))
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
                                await redis_client.xack(stream, "workers", msg_id)
            await asyncio.sleep(0.1)
        except Exception as e:
            logger.error(f"Worker error: {e}")
            await asyncio.sleep(5)

# ---------- SCHEDULER ----------
async def scheduler_task():
    while True:
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
    async with db_pool.acquire() as conn:
        monitors = await conn.fetch("SELECT id, interval_sec, last_check FROM monitors WHERE enabled=TRUE")
    for m in monitors:
        if m["last_check"]:
            last = m["last_check"].timestamp()
            next_time = last + m["interval_sec"]
        else:
            next_time = datetime.utcnow().timestamp()
        await redis_client.zadd("monitor_schedule", {str(m["id"]): next_time})

# ---------- AGGREGATOR ----------
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

# ---------- WEBSOCKET MANAGER ----------
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
        pubsub = redis_client.pubsub()
        await pubsub.subscribe("status_changes", "incidents")
        async for message in pubsub.listen():
            if message["type"] == "message":
                await self.broadcast(message["data"])

manager = ConnectionManager()

# ---------- FASTAPI APP ----------
@asynccontextmanager
async def lifespan(app: FastAPI):
    global redis_client, db_pool
    redis_client = await redis.from_url(REDIS_URL, decode_responses=True)
    await init_db()
    try:
        await redis_client.xgroup_create("checks_stream", "workers", id="0", mkstream=True)
    except:
        pass
    asyncio.create_task(manager.listen_redis())
    await populate_schedule()
    logger.info("API started")
    yield
    await db_pool.close()
    await redis_client.close()

app = FastAPI(lifespan=lifespan, title="Uppoint Monitor")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
security = HTTPBearer()

# ---------- WEBSOCKET ENDPOINT ----------
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# ---------- API ROUTES ----------
@app.post("/api/login")
@limiter.limit("5 per minute")
async def login(data: LoginRequest, request: Request):
    async with db_pool.acquire() as conn:
        user = await conn.fetchrow("SELECT id, password_hash FROM users WHERE email=$1", data.email)
        if not user or not pwd_context.verify(data.password, user["password_hash"]):
            raise HTTPException(401, "Invalid credentials")
        return {"access_token": create_token(user["id"]), "token_type": "bearer"}

@app.post("/api/register")
@limiter.limit("5 per minute")
async def register(data: RegisterRequest, request: Request):
    async with db_pool.acquire() as conn:
        existing = await conn.fetchval("SELECT id FROM users WHERE email=$1", data.email)
        if existing:
            raise HTTPException(400, "Email already exists")
        pwd_hash = pwd_context.hash(data.password)
        user_id = await conn.fetchval("INSERT INTO users (email, password_hash) VALUES ($1,$2) RETURNING id", data.email, pwd_hash)
        return {"access_token": create_token(user_id), "token_type": "bearer"}

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
        next_time = datetime.utcnow().timestamp() + monitor.interval_sec
        await redis_client.zadd("monitor_schedule", {str(monitor_id): next_time})
        return {"id": monitor_id}

@app.delete("/api/monitors/{monitor_id}")
async def delete_monitor(monitor_id: int, user=Depends(get_current_user)):
    async with db_pool.acquire() as conn:
        await conn.execute("DELETE FROM monitors WHERE id=$1 AND user_id=$2", monitor_id, user["id"])
        await conn.execute("UPDATE users SET monitors_count = monitors_count - 1 WHERE id=$1", user["id"])
        await redis_client.zrem("monitor_schedule", str(monitor_id))
        await redis_client.delete(f"user:{user['id']}:monitors")
    return {"ok": True}

@app.get("/api/monitors")
async def get_monitors(user=Depends(get_current_user)):
    cache_key = f"user:{user['id']}:monitors"
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

# ---------- FRONTEND ----------
HTML_LOGIN = """<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Uppoint – вход и регистрация</title>
    <style>
        *{margin:0;padding:0;box-sizing:border-box}
        body{font-family:system-ui;background:#0f172a;color:#fff;display:flex;justify-content:center;align-items:center;min-height:100vh}
        .container{display:flex;gap:30px;flex-wrap:wrap;justify-content:center;padding:20px}
        .card{background:#1e293b;padding:32px;border-radius:24px;width:380px;border:1px solid #334155}
        h2{font-size:24px;margin-bottom:8px}
        .subtitle{font-size:14px;color:#94a3b8;margin-bottom:24px}
        input{width:100%;padding:12px 16px;margin-bottom:16px;background:#0f172a;border:1px solid #334155;border-radius:12px;color:#fff}
        input:focus{outline:none;border-color:#3b82f6}
        button{width:100%;padding:12px;background:#3b82f6;border:none;border-radius:12px;color:white;font-weight:600;cursor:pointer}
        .demo{font-size:12px;color:#475569;text-align:center;margin-top:16px}
        .error{color:#ef4444;margin-bottom:16px;text-align:center}
        .success{color:#22c55e;margin-bottom:16px;text-align:center}
    </style>
</head>
<body>
<div class="container">
    <div class="card">
        <h2>🚀 Регистрация</h2>
        <div class="subtitle">Создайте аккаунт за 10 секунд</div>
        <div id="regError" class="error" style="display:none"></div>
        <div id="regSuccess" class="success" style="display:none"></div>
        <input type="email" id="regEmail" placeholder="Email">
        <input type="password" id="regPassword" placeholder="Пароль">
        <input type="password" id="regPasswordConfirm" placeholder="Подтвердите пароль">
        <button onclick="register()">Зарегистрироваться</button>
    </div>
    <div class="card">
        <h2>🔐 Вход</h2>
        <div class="subtitle">Добро пожаловать обратно!</div>
        <div id="loginError" class="error" style="display:none"></div>
        <input type="email" id="loginEmail" placeholder="Email">
        <input type="password" id="loginPassword" placeholder="Пароль">
        <button onclick="login()">Войти</button>
        <div class="demo">demo@uppoint.com / demo123</div>
    </div>
</div>
<script>
    async function register() {
        const email = document.getElementById('regEmail').value;
        const password = document.getElementById('regPassword').value;
        const confirm = document.getElementById('regPasswordConfirm').value;
        const errorDiv = document.getElementById('regError');
        const successDiv = document.getElementById('regSuccess');
        errorDiv.style.display = 'none';
        successDiv.style.display = 'none';
        if (!email || !password) {
            errorDiv.innerText = 'Заполните все поля';
            errorDiv.style.display = 'block';
            return;
        }
        if (password !== confirm) {
            errorDiv.innerText = 'Пароли не совпадают';
            errorDiv.style.display = 'block';
            return;
        }
        try {
            const res = await fetch('/api/register', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({email, password})
            });
            const data = await res.json();
            if (res.ok) {
                successDiv.innerText = 'Регистрация успешна! Теперь войдите.';
                successDiv.style.display = 'block';
                document.getElementById('regEmail').value = '';
                document.getElementById('regPassword').value = '';
                document.getElementById('regPasswordConfirm').value = '';
            } else {
                errorDiv.innerText = data.detail || 'Ошибка регистрации';
                errorDiv.style.display = 'block';
            }
        } catch(err) {
            errorDiv.innerText = 'Ошибка сети';
            errorDiv.style.display = 'block';
        }
    }
    async function login() {
        const email = document.getElementById('loginEmail').value;
        const password = document.getElementById('loginPassword').value;
        const errorDiv = document.getElementById('loginError');
        errorDiv.style.display = 'none';
        if (!email || !password) {
            errorDiv.innerText = 'Введите email и пароль';
            errorDiv.style.display = 'block';
            return;
        }
        try {
            const res = await fetch('/api/login', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({email, password})
            });
            const data = await res.json();
            if (res.ok && data.access_token) {
                localStorage.setItem('token', data.access_token);
                window.location.href = '/dashboard';
            } else {
                errorDiv.innerText = data.detail || 'Неверный email или пароль';
                errorDiv.style.display = 'block';
            }
        } catch(err) {
            errorDiv.innerText = 'Ошибка соединения';
            errorDiv.style.display = 'block';
        }
    }
</script>
</body>
</html>
"""

HTML_DASHBOARD = """<!DOCTYPE html>
<html><head><title>Uppoint – мониторинг</title><meta charset="UTF-8"><script src="https://cdn.jsdelivr.net/npm/chart.js"></script><style>
*{margin:0;padding:0;box-sizing:border-box}body{font-family:system-ui;background:#0f172a;color:#f1f5f9;padding:24px}.container{max-width:1400px;margin:0 auto}.header{display:flex;justify-content:space-between;margin-bottom:32px}h1{background:linear-gradient(135deg,#3b82f6,#a855f7);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.logout{background:#ef4444;padding:8px 20px;border-radius:12px;text-decoration:none;color:white}.stats{display:flex;gap:24px;margin-bottom:32px}.stat-card{background:#1e293b;padding:24px;border-radius:20px;flex:1}.stat-value{font-size:36px;font-weight:bold}
.add-card{background:#1e293b;border-radius:20px;padding:24px;margin-bottom:32px}.form-row{display:flex;gap:12px;flex-wrap:wrap}.form-group{flex:1}.form-group label{font-size:12px;color:#94a3b8;display:block;margin-bottom:4px}
.form-group input,.form-group select{width:100%;padding:10px;background:#0f172a;border:1px solid #334155;border-radius:10px;color:white}button{background:#3b82f6;border:none;padding:10px 24px;border-radius:10px;color:white;cursor:pointer}
.monitor-card{background:#1e293b;border-radius:16px;padding:20px;margin-bottom:12px;border-left:4px solid;cursor:pointer}.status-up{border-left-color:#22c55e}.status-down{border-left-color:#ef4444}
.monitor-header{display:flex;justify-content:space-between;margin-bottom:12px}.status-badge{padding:4px 12px;border-radius:20px;font-size:12px}.status-up-bg{background:#22c55e20;color:#22c55e}
.status-down-bg{background:#ef444420;color:#ef4444}.delete-btn{background:#dc2626;border:none;padding:4px 12px;border-radius:8px;cursor:pointer;color:white}
.modal{display:none;position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.7);justify-content:center;align-items:center}.modal-content{background:#1e293b;border-radius:20px;width:700px;max-width:90%;padding:24px}
.chart-container{height:300px;margin-bottom:20px}.tabs{display:flex;gap:8px;margin-bottom:24px}.tab{padding:8px 20px;background:#1e293b;border-radius:12px;cursor:pointer}.tab.active{background:#3b82f6}
.incident-item{background:#0f172a;border-radius:12px;padding:16px;margin-bottom:12px}
</style></head>
<body><div class="container"><div class="header"><h1>📡 Uppoint Monitor</h1><a href="/logout" class="logout">Sign out</a></div>
<div class="stats"><div class="stat-card"><div class="stat-value" id="upCount">0</div><div>Up</div></div><div class="stat-card"><div class="stat-value" id="downCount">0</div><div>Down</div></div><div class="stat-card"><div class="stat-value" id="uptimeAvg">0%</div><div>Avg 30d uptime</div></div></div>
<div class="add-card"><h2>➕ Add monitor</h2><div class="form-row"><div class="form-group"><label>Name</label><input id="name" placeholder="My site"></div><div class="form-group"><label>Target</label><input id="target" placeholder="example.com or https://..."></div><div class="form-group"><label>Type</label><select id="type"><option value="http">HTTP</option><option value="port">Port</option></select></div><div class="form-group"><label>Interval (sec)</label><input id="interval" value="300"></div><button onclick="addMonitor()">Add</button></div></div>
<div class="tabs"><div class="tab active" onclick="showTab('monitors')">Monitors</div><div class="tab" onclick="showTab('incidents')">Incidents</div></div>
<div id="monitorsTab"><div id="monitorsList"></div></div><div id="incidentsTab" style="display:none"><div id="incidentsList"></div></div></div>
<div id="modal" class="modal"><div class="modal-content"><div id="modalTitle">Monitor Details</div><div class="chart-container"><canvas id="historyChart"></canvas></div><button onclick="closeModal()">Close</button></div></div>
<script>
const token=localStorage.getItem('token');if(!token)location.href='/';
let currentMonitorId=null,historyChart=null;
const ws = new WebSocket(`ws://${window.location.host}/ws`);
ws.onmessage = (event) => { loadMonitors(); loadIncidents(); };
async function api(endpoint,opts={}){const res=await fetch(endpoint,{...opts,headers:{'Authorization':'Bearer '+token,'Content-Type':'application/json'}});if(res.status===401)location.href='/';return res.json();}
async function loadMonitors(){const data=await api('/api/monitors');let up=0,down=0,total=0,html='';for(let m of data.monitors){if(m.status==='up')up++;if(m.status==='down')down++;total+=m.uptime_30d||100;html+=`<div class="monitor-card status-${m.status}" onclick="showDetails(${m.id})"><div class="monitor-header"><strong>${escape(m.name)}</strong><div><span class="status-badge status-${m.status}-bg">${m.status.toUpperCase()}</span><span style="margin-left:12px">${m.response_ms}ms</span><button class="delete-btn" onclick="event.stopPropagation();deleteMonitor(${m.id})">Delete</button></div></div><div>${escape(m.target)} | ${m.type}</div><div style="margin-top:8px">📊 30d uptime: ${m.uptime_30d}%</div></div>`;}
document.getElementById('upCount').innerText=up;document.getElementById('downCount').innerText=down;document.getElementById('uptimeAvg').innerText=data.monitors.length?(total/data.monitors.length).toFixed(1)+'%':'0%';document.getElementById('monitorsList').innerHTML=html||'<div style="padding:40px;text-align:center">No monitors</div>';}
async function loadIncidents(){const data=await api('/api/incidents');let html='';for(let i of data.incidents){const dur=i.duration_sec?`${Math.floor(i.duration_sec/60)}m ${i.duration_sec%60}s`:'Ongoing';html+=`<div class="incident-item"><strong>${escape(i.monitor_name)}</strong><div>⬇️ ${new Date(i.started_at).toLocaleString()}</div><div>⬆️ ${i.ended_at?new Date(i.ended_at).toLocaleString():'—'}</div><div>⏱ ${dur}</div><div>📍 ${i.region}</div></div>`;}
document.getElementById('incidentsList').innerHTML=html||'<div style="color:#64748b">No incidents</div>';}
async function showDetails(id){currentMonitorId=id;const hist=await api(`/api/monitors/${id}/history?period=24h`);const ctx=document.getElementById('historyChart').getContext('2d');const labels=hist.history.slice(-50).map(h=>new Date(h.time).toLocaleTimeString());const values=hist.history.slice(-50).map(h=>h.response_ms);if(historyChart)historyChart.destroy();historyChart=new Chart(ctx,{type:'line',data:{labels,datasets:[{label:'Response (ms)',data:values,borderColor:'#3b82f6',fill:false}]}});document.getElementById('modal').style.display='flex';}
async function deleteMonitor(id){if(confirm('Delete?')){await api('/api/monitors/'+id,{method:'DELETE'});loadMonitors();}}
async function addMonitor(){await api('/api/monitors',{method:'POST',body:JSON.stringify({name:document.getElementById('name').value,target:document.getElementById('target').value,type:document.getElementById('type').value,interval_sec:parseInt(document.getElementById('interval').value)})});loadMonitors();}
function closeModal(){document.getElementById('modal').style.display='none';}
function showTab(tab){document.getElementById('monitorsTab').style.display=tab==='monitors'?'block':'none';document.getElementById('incidentsTab').style.display=tab==='incidents'?'block':'none';if(tab==='incidents')loadIncidents();document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));event.target.classList.add('active');}
function escape(t){if(!t)return '';return t.replace(/[&<>]/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[m]));}
loadMonitors();setInterval(loadMonitors,15000);
</script></body></html>
"""

@app.get("/")
async def root(): return HTMLResponse(HTML_LOGIN)
@app.get("/dashboard") async def dashboard(): return HTMLResponse(HTML_DASHBOARD)
@app.get("/status") async def status_page(): return HTMLResponse('<html><body><h1>Public Status</h1><div id="status"></div><script>fetch("/api/status").then(r=>r.json()).then(data=>{document.getElementById("status").innerHTML=data.monitors.map(m=>`<div><b>${m.name}</b> ${m.status.toUpperCase()} ${m.response_ms}ms</div>`).join("")});setInterval(()=>location.reload(),30000);</script></body></html>')
@app.get("/logout") async def logout(): return HTMLResponse('<script>localStorage.removeItem("token");location.href="/";</script>')

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--worker", action="store_true", help="Run as worker only")
    parser.add_argument("--scheduler", action="store_true", help="Run scheduler only")
    parser.add_argument("--aggregator", action="store_true", help="Run aggregator only")
    args = parser.parse_args()

    if args.worker:
        async def run_worker():
            global redis_client, db_pool
            redis_client = await redis.from_url(REDIS_URL, decode_responses=True)
            await init_db()
            worker_id = f"worker_{REGION}_{secrets.token_hex(4)}"
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
            redis_client = await redis.from_url(REDIS_URL, decode_responses=True)
            await init_db()
            await populate_schedule()
            await scheduler_task()
        asyncio.run(run_scheduler())
    elif args.aggregator:
        async def run_aggregator():
            global redis_client, db_pool
            redis_client = await redis.from_url(REDIS_URL, decode_responses=True)
            await init_db()
            await aggregator_task()
        asyncio.run(run_aggregator())
    else:
        import uvicorn
        uvicorn.run(app, host="0.0.0.0", port=8000)
