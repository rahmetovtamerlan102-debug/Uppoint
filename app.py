#!/usr/bin/env python3
import os
import asyncio
import json
import secrets
import hashlib
import random
from datetime import datetime, timedelta
from contextlib import asynccontextmanager
from typing import Optional, List
import logging

from fastapi import FastAPI, HTTPException, Depends, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
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
REGIONS = ["us-east", "eu-west", "ap-southeast"]
ALL_REGIONS = REGIONS

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
limiter = Limiter(key_func=get_remote_address)
logger = logging.getLogger(__name__)

db_pool = None
redis_client = None
http_session = None

def normalize_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

async def get_http_session():
    global http_session
    if http_session is None:
        connector = aiohttp.TCPConnector(limit=200, limit_per_host=50)
        http_session = aiohttp.ClientSession(connector=connector)
    return http_session

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
            CREATE TABLE IF NOT EXISTS incidents (
                id SERIAL PRIMARY KEY,
                monitor_id INTEGER NOT NULL,
                region TEXT NOT NULL,
                started_at TIMESTAMP,
                ended_at TIMESTAMP,
                duration_sec INTEGER
            )
        """)
        demo = await conn.fetchval("SELECT id FROM users WHERE email='demo@uppoint.com'")
        if not demo:
            demo_pwd = normalize_password("demo123")
            await conn.execute(
                "INSERT INTO users (email, password_hash) VALUES ($1, $2)",
                "demo@uppoint.com", pwd_context.hash(demo_pwd)
            )
        # Создание партиций на 12 месяцев
        start_date = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        for i in range(13):
            part_start = start_date + timedelta(days=30*i)
            part_end = part_start + timedelta(days=30)
            part_name = f"checks_{part_start.strftime('%Y_%m')}"
            await conn.execute(f"""
                CREATE TABLE IF NOT EXISTS {part_name} PARTITION OF checks
                FOR VALUES FROM ('{part_start.isoformat()}') TO ('{part_end.isoformat()}')
            """)

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
        user = await conn.fetchrow("SELECT id, email FROM users WHERE id=$1", user_id)
        if not user:
            raise HTTPException(401, "User not found")
        return dict(user)

# ---------- CHECK FUNCTIONS ----------
async def check_http(target: str, timeout: int, keyword: str = None) -> tuple:
    session = await get_http_session()
    if not target.startswith("http"):
        target = "https://" + target
    start = datetime.utcnow()
    try:
        async with session.get(target, timeout=timeout) as resp:
            elapsed = int((datetime.utcnow() - start).total_seconds() * 1000)
            if not (200 <= resp.status < 400):
                return "down", elapsed, f"HTTP {resp.status}"
            if keyword:
                text = await resp.text()
                if keyword.lower() not in text.lower():
                    return "down", elapsed, "Keyword missing"
            return "up", elapsed, None
    except asyncio.TimeoutError:
        return "down", timeout * 1000, "Timeout"
    except Exception as e:
        return "down", 0, str(e)[:200]

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
    return "down", 0, "Unsupported"

# ---------- BACKGROUND WORKER ----------
async def background_worker():
    while True:
        await asyncio.sleep(30)
        if not db_pool or not redis_client:
            continue
        async with db_pool.acquire() as conn:
            monitors = await conn.fetch("SELECT id, user_id, name, target, type, keyword, timeout_sec, status, fail_count FROM monitors WHERE enabled=TRUE")
        now = datetime.utcnow()
        for m in monitors:
            status, ms, error = await run_check(m["type"], m["target"], m["timeout_sec"], m.get("keyword"))
            async with db_pool.acquire() as conn:
                await conn.execute(
                    "INSERT INTO checks (monitor_id, region, status, response_ms, error, checked_at) VALUES ($1,$2,$3,$4,$5,$6)",
                    m["id"], "default", status, ms, error, now
                )
                new_fail = 0 if status == "up" else (m["fail_count"] or 0) + 1
                await conn.execute(
                    "UPDATE monitors SET status=$1, response_ms=$2, last_check=$3, fail_count=$4 WHERE id=$5",
                    status, ms, now, new_fail, m["id"]
                )
                if m["status"] != "pending" and m["status"] != status:
                    if status == "down":
                        await conn.execute(
                            "INSERT INTO incidents (monitor_id, region, started_at) VALUES ($1,$2,$3)",
                            m["id"], "default", now
                        )
                    elif m["status"] == "down" and status == "up":
                        await conn.execute(
                            "UPDATE incidents SET ended_at=$1, duration_sec=EXTRACT(EPOCH FROM ($1 - started_at)) WHERE monitor_id=$2 AND ended_at IS NULL",
                            now, m["id"]
                        )
                if redis_client:
                    await redis_client.publish("status_changes", json.dumps({"monitor_id": m["id"], "status": status, "response_ms": ms}))

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
        if not redis_client:
            return
        pubsub = redis_client.pubsub()
        await pubsub.subscribe("status_changes")
        async for message in pubsub.listen():
            if message["type"] == "message":
                await self.broadcast(message["data"])

manager = ConnectionManager()

async def wait_for_redis(retries=5):
    for i in range(retries):
        try:
            client = await redis.from_url(REDIS_URL, decode_responses=True)
            await client.ping()
            return client
        except:
            await asyncio.sleep(2)
    return None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global redis_client, db_pool
    await init_db()
    redis_client = await wait_for_redis()
    if redis_client:
        asyncio.create_task(manager.listen_redis())
        asyncio.create_task(background_worker())
        logger.info("Redis connected, background worker started")
    else:
        logger.warning("Redis not available, running without realtime")
    yield
    if redis_client:
        await redis_client.close()
    await db_pool.close()

app = FastAPI(lifespan=lifespan, title="Uppoint Monitor")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
security = HTTPBearer()

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    if not redis_client:
        await websocket.close(code=1008)
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
        return {"id": monitor_id}

@app.delete("/api/monitors/{monitor_id}")
async def delete_monitor(monitor_id: int, user=Depends(get_current_user)):
    async with db_pool.acquire() as conn:
        await conn.execute("DELETE FROM monitors WHERE id=$1 AND user_id=$2", monitor_id, user["id"])
        await conn.execute("UPDATE users SET monitors_count = monitors_count - 1 WHERE id=$1", user["id"])
    return {"ok": True}

@app.get("/api/monitors")
async def get_monitors(user=Depends(get_current_user)):
    async with db_pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT id, name, target, type, status, response_ms, last_check,
                   COALESCE(ROUND((SUM(CASE WHEN c.status='up' THEN 1 ELSE 0 END)::float / NULLIF(COUNT(c.id),0))*100,1),100) as uptime_30d
            FROM monitors m
            LEFT JOIN checks c ON c.monitor_id = m.id AND c.checked_at > NOW() - INTERVAL '30 days'
            WHERE m.user_id=$1 AND m.enabled=TRUE
            GROUP BY m.id
        """, user["id"])
        return {"monitors": [dict(r) for r in rows]}

@app.get("/api/monitors/{monitor_id}/history")
async def get_history(monitor_id: int, period: str = "24h", user=Depends(get_current_user)):
    async with db_pool.acquire() as conn:
        owner = await conn.fetchval("SELECT user_id FROM monitors WHERE id=$1", monitor_id)
        if owner != user["id"]:
            raise HTTPException(403)
        delta = {"24h": 24, "7d": 168, "30d": 720}.get(period, 24)
        since = datetime.utcnow() - timedelta(hours=delta)
        checks = await conn.fetch("SELECT checked_at, response_ms, status FROM checks WHERE monitor_id=$1 AND checked_at>$2 ORDER BY checked_at", monitor_id, since)
        return {"history": [{"time": c["checked_at"].isoformat(), "response_ms": c["response_ms"], "status": c["status"]} for c in checks]}

@app.get("/api/incidents")
async def get_incidents(user=Depends(get_current_user)):
    async with db_pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT i.*, m.name as monitor_name
            FROM incidents i JOIN monitors m ON i.monitor_id = m.id
            WHERE m.user_id=$1 ORDER BY i.started_at DESC LIMIT 50
        """, user["id"])
        return {"incidents": [dict(r) for r in rows]}

@app.get("/api/status")
async def public_status():
    async with db_pool.acquire() as conn:
        rows = await conn.fetch("SELECT name, status, response_ms, last_check FROM monitors WHERE enabled=TRUE")
        return {"monitors": [dict(r) for r in rows]}

@app.get("/api/health")
async def health():
    return {"status": "ok"}

# ---------- ФРОНТЕНД (HTML) ----------
HTML_APP = """<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
    <title>Uppoint Monitor — дашборд</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { background: #0a0f1c; font-family: 'Inter', system-ui, sans-serif; color: #e5e7eb; }
        .app { display: flex; min-height: 100vh; }
        .sidebar {
            width: 260px;
            background: #0f172a;
            border-right: 1px solid #1e293b;
            padding: 24px 16px;
            position: fixed;
            height: 100vh;
            overflow-y: auto;
        }
        .logo {
            font-size: 24px;
            font-weight: 800;
            background: linear-gradient(135deg, #38bdf8, #a855f7);
            -webkit-background-clip: text;
            background-clip: text;
            color: transparent;
            margin-bottom: 32px;
            padding-left: 8px;
        }
        .nav-item {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 12px 16px;
            margin-bottom: 4px;
            border-radius: 12px;
            color: #94a3b8;
            cursor: pointer;
            transition: all 0.2s;
        }
        .nav-item:hover, .nav-item.active {
            background: #1e293b;
            color: #3b82f6;
        }
        .main {
            margin-left: 260px;
            flex: 1;
            padding: 24px 32px;
        }
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 32px;
            flex-wrap: wrap;
            gap: 16px;
        }
        .title h1 { font-size: 28px; font-weight: 600; }
        .title p { color: #64748b; margin-top: 4px; }
        .actions { display: flex; gap: 12px; }
        .btn-primary {
            background: #3b82f6;
            border: none;
            padding: 10px 20px;
            border-radius: 12px;
            color: white;
            font-weight: 500;
            cursor: pointer;
        }
        .btn-outline {
            background: transparent;
            border: 1px solid #334155;
            padding: 10px 20px;
            border-radius: 12px;
            color: #94a3b8;
            cursor: pointer;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 20px;
            margin-bottom: 32px;
        }
        .stat-card {
            background: #0f172a;
            border: 1px solid #1e293b;
            border-radius: 20px;
            padding: 20px;
        }
        .stat-value { font-size: 32px; font-weight: 700; margin-top: 8px; }
        .stat-label { color: #94a3b8; font-size: 14px; }
        .status-up { color: #22c55e; }
        .status-down { color: #ef4444; }
        .graph-container {
            background: #0f172a;
            border: 1px solid #1e293b;
            border-radius: 20px;
            padding: 20px;
            margin-bottom: 32px;
        }
        .graph-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }
        .period-selector { display: flex; gap: 8px; }
        .period-btn {
            background: #1e293b;
            border: none;
            padding: 6px 14px;
            border-radius: 20px;
            color: #94a3b8;
            cursor: pointer;
        }
        .period-btn.active {
            background: #3b82f6;
            color: white;
        }
        canvas { max-height: 250px; width: 100%; }
        .table-container {
            background: #0f172a;
            border: 1px solid #1e293b;
            border-radius: 20px;
            overflow-x: auto;
        }
        table { width: 100%; border-collapse: collapse; }
        th { text-align: left; padding: 16px 20px; color: #94a3b8; border-bottom: 1px solid #1e293b; }
        td { padding: 14px 20px; border-bottom: 1px solid #1e293b; }
        .status-badge { display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin-right: 8px; }
        .status-badge.up { background: #22c55e; box-shadow: 0 0 0 2px #22c55e20; }
        .status-badge.down { background: #ef4444; box-shadow: 0 0 0 2px #ef444420; }
        .delete-btn {
            background: #dc2626;
            border: none;
            padding: 4px 12px;
            border-radius: 8px;
            color: white;
            cursor: pointer;
        }
        .modal {
            display: none;
            position: fixed;
            top: 0; left: 0; right: 0; bottom: 0;
            background: rgba(0,0,0,0.8);
            align-items: center;
            justify-content: center;
            z-index: 1000;
        }
        .modal-content {
            background: #0f172a;
            border-radius: 24px;
            width: 500px;
            max-width: 90%;
            padding: 28px;
        }
        .modal-content input, .modal-content select {
            width: 100%;
            padding: 12px;
            margin-bottom: 16px;
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 12px;
            color: white;
        }
        .modal-actions {
            display: flex;
            gap: 12px;
            justify-content: flex-end;
        }
        @media (max-width: 768px) {
            .sidebar { display: none; }
            .main { margin-left: 0; padding: 16px; }
            .stats-grid { grid-template-columns: repeat(2,1fr); gap: 12px; }
        }
    </style>
</head>
<body>
<div class="app">
    <aside class="sidebar">
        <div class="logo">Uppoint</div>
        <nav>
            <div class="nav-item active" data-tab="dashboard">📊 Дашборд</div>
            <div class="nav-item" data-tab="monitors">📡 Мониторы</div>
            <div class="nav-item" data-tab="incidents">⚠️ Инциденты</div>
            <div class="nav-item" data-tab="status">📄 Status pages</div>
        </nav>
    </aside>
    <main class="main">
        <div class="header">
            <div class="title"><h1>Дашборд</h1><p>Обзор состояния всех систем</p></div>
            <div class="actions">
                <button class="btn-primary" id="addMonitorBtn">+ Добавить монитор</button>
                <button class="btn-outline">📤 Экспорт</button>
            </div>
        </div>
        <div class="stats-grid" id="statsGrid"></div>
        <div class="graph-container">
            <div class="graph-header"><h3>Аптайм за последние 7 дней</h3><div class="period-selector"><button class="period-btn active">7д</button></div></div>
            <canvas id="uptimeChart" height="200"></canvas>
        </div>
        <div class="table-container"><table id="monitorsTable"><thead><tr><th>Название</th><th>Статус</th><th>Цель</th><th>Время ответа</th><th>Аптайм (30д)</th><th>Действия</th></tr></thead><tbody id="monitorsTableBody"></tbody></table></div>
    </main>
</div>
<div id="modal" class="modal">
    <div class="modal-content">
        <h3 style="margin-bottom:20px">➕ Новый монитор</h3>
        <input type="text" id="monName" placeholder="Название">
        <input type="text" id="monTarget" placeholder="URL или host:port">
        <select id="monType"><option value="http">HTTP/HTTPS</option><option value="port">TCP порт</option></select>
        <div class="modal-actions"><button id="cancelModalBtn" style="background:#334155">Отмена</button><button id="saveModalBtn" style="background:#3b82f6">Создать</button></div>
    </div>
</div>
<script>
    let monitors = [];
    let chart;
    const token = localStorage.getItem('token');
    if (!token) window.location.href = '/login';

    async function apiCall(endpoint, opts={}) {
        const res = await fetch(endpoint, {...opts, headers:{'Authorization':'Bearer '+token,'Content-Type':'application/json'}});
        if (res.status===401) { localStorage.removeItem('token'); window.location.href='/login'; throw new Error('Unauth'); }
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail);
        return data;
    }

    async function loadMonitors() {
        const data = await apiCall('/api/monitors');
        monitors = data.monitors;
        renderStats();
        renderTable();
    }

    function renderStats() {
        const total = monitors.length;
        const up = monitors.filter(m=>m.status==='up').length;
        const down = total-up;
        const avgUptime = total ? (monitors.reduce((s,m)=>s+(m.uptime_30d||100),0)/total).toFixed(1) : 100;
        document.getElementById('statsGrid').innerHTML = `
            <div class="stat-card"><div class="stat-label">Всего мониторов</div><div class="stat-value">${total}</div></div>
            <div class="stat-card"><div class="stat-label">Работают</div><div class="stat-value status-up">${up}</div></div>
            <div class="stat-card"><div class="stat-label">Не работают</div><div class="stat-value status-down">${down}</div></div>
            <div class="stat-card"><div class="stat-label">Средний аптайм</div><div class="stat-value status-up">${avgUptime}%</div></div>
        `;
    }

    function renderTable() {
        const tbody = document.getElementById('monitorsTableBody');
        tbody.innerHTML = monitors.map(m => `
            <tr>
                <td><strong>${escapeHtml(m.name)}</strong></td>
                <td><span class="status-badge ${m.status}"></span> ${m.status==='up'?'UP':'DOWN'}</td>
                <td>${escapeHtml(m.target)}</td>
                <td>${m.response_ms||0} ms</td>
                <td><span class="status-badge up"></span> ${(m.uptime_30d||100).toFixed(1)}%</td>
                <td><button class="delete-btn" onclick="deleteMonitor(${m.id})">Удалить</button></td>
            </tr>
        `).join('');
    }

    async function deleteMonitor(id) {
        if(confirm('Удалить монитор?')) {
            await apiCall(`/api/monitors/${id}`, {method:'DELETE'});
            loadMonitors();
        }
    }

    async function addMonitor() {
        const name = document.getElementById('monName').value.trim();
        const target = document.getElementById('monTarget').value.trim();
        const type = document.getElementById('monType').value;
        if(!target) { alert('Введите цель'); return; }
        await apiCall('/api/monitors', {method:'POST', body:JSON.stringify({name: name||target, target, type, interval_sec:300})});
        closeModal();
        loadMonitors();
    }

    function escapeHtml(s) { return String(s).replace(/[&<>]/g, m=> m==='&'?'&amp;': m==='<'?'&lt;':'&gt;'); }

    const modal = document.getElementById('modal');
    document.getElementById('addMonitorBtn').onclick = () => modal.style.display = 'flex';
    document.getElementById('cancelModalBtn').onclick = () => modal.style.display = 'none';
    document.getElementById('saveModalBtn').onclick = addMonitor;
    modal.onclick = (e) => { if(e.target===modal) modal.style.display='none'; };

    // Chart
    const ctx = document.getElementById('uptimeChart').getContext('2d');
    chart = new Chart(ctx, {
        type: 'line',
        data: { labels: ['Пн','Вт','Ср','Чт','Пт','Сб','Вс'], datasets: [{ label: 'Аптайм, %', data: [99.2,99.5,98.7,99.9,100,99.3,99.8], borderColor: '#3b82f6', fill: true, backgroundColor: 'rgba(59,130,246,0.1)' }] },
        options: { responsive: true, maintainAspectRatio: true, plugins: { legend: { labels: { color: '#94a3b8' } } }, scales: { y: { grid: { color: '#1e293b' }, ticks: { color: '#94a3b8' } }, x: { ticks: { color: '#94a3b8' } } } }
    });

    loadMonitors();
</script>
</body>
</html>
"""

# ---------- МАРШРУТЫ ДЛЯ ФРОНТЕНДА ----------
@app.get("/")
async def root():
    return HTMLResponse(HTML_APP)

@app.get("/login")
async def login_page():
    return HTMLResponse(HTML_APP)  # в реальном приложении отдельная страница, но для простоты оставим так

@app.get("/dashboard")
async def dashboard_page():
    return HTMLResponse(HTML_APP)

@app.get("/monitors")
async def monitors_page():
    return HTMLResponse(HTML_APP)

@app.get("/incidents")
async def incidents_page():
    return HTMLResponse(HTML_APP)

@app.get("/status")
async def status_page():
    return HTMLResponse('<html><body><h1>Public Status</h1><div id="status"></div><script>fetch("/api/status").then(r=>r.json()).then(data=>document.getElementById("status").innerHTML=data.monitors.map(m=>`<div><b>${m.name}</b> ${m.status.toUpperCase()} ${m.response_ms}ms</div>`).join(""))</script></body></html>')

@app.get("/logout")
async def logout():
    return HTMLResponse('<script>localStorage.removeItem("token");window.location.href="/";</script>')

if __name__ == "__main__":
    import uvicorn
    print("🚀 Uppoint Monitor запущен: http://localhost:8000")
    print("🔐 Демо: demo@uppoint.com / demo123")
    uvicorn.run(app, host="0.0.0.0", port=8000)
