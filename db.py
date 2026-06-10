import aiosqlite
import time
import secrets
import os
import logging
from typing import Optional, Any

from config import settings

logging.basicConfig(level=logging.INFO)
DB_PATH = os.path.abspath(settings.SQLITE_DB)


async def init_db():
    logging.info(f"[db] init_db opening DB at {DB_PATH}")
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS api_keys (
                key TEXT PRIMARY KEY,
                email TEXT,
                created_at REAL,
                is_active INTEGER
            )
            """
        )
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS request_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT,
                endpoint TEXT,
                input TEXT,
                timestamp REAL,
                response_time_ms INTEGER
            )
            """
        )
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS cache (
                cache_key TEXT PRIMARY KEY,
                value TEXT,
                expires_at REAL
            )
            """
        )
        await db.commit()


async def create_api_key(email: str) -> str:
    key = secrets.token_urlsafe(32)
    now = time.time()
    logging.info(f"[db] create_api_key writing key={key} to {DB_PATH} for email={email}")
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO api_keys (key, email, created_at, is_active) VALUES (?, ?, ?, 1)",
            (key, email, now),
        )
        await db.commit()
    logging.info(f"[db] create_api_key committed key={key}")
    return key


async def get_api_key(key: str) -> Optional[dict]:
    logging.info(f"[db] get_api_key looking up key={key} in {DB_PATH}")
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute("SELECT key, email, created_at, is_active FROM api_keys WHERE key = ?", (key,))
        row = await cur.fetchone()
        if not row:
            logging.info(f"[db] get_api_key no row for key={key}")
            return None
        logging.info(f"[db] get_api_key found key={row[0]} active={row[3]}")
        return {"key": row[0], "email": row[1], "created_at": row[2], "is_active": bool(row[3])}


async def log_request(key: str, endpoint: str, input_text: str, response_time_ms: int):
    now = time.time()
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO request_log (key, endpoint, input, timestamp, response_time_ms) VALUES (?, ?, ?, ?, ?)",
            (key, endpoint, input_text, now, response_time_ms),
        )
        await db.commit()


async def fetch_history(key: str, page: int = 1, limit: int = 20):
    offset = (page - 1) * limit
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            "SELECT endpoint, input, timestamp, response_time_ms FROM request_log WHERE key = ? ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            (key, limit, offset),
        )
        rows = await cur.fetchall()
        return [dict(endpoint=r[0], input=r[1], timestamp=r[2], response_time_ms=r[3]) for r in rows]


async def fetch_stats(key: str) -> dict:
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute("SELECT COUNT(*) FROM request_log WHERE key = ?", (key,))
        total = (await cur.fetchone())[0]
        cur = await db.execute(
            "SELECT endpoint, COUNT(*) as c FROM request_log WHERE key = ? GROUP BY endpoint ORDER BY c DESC LIMIT 5",
            (key,),
        )
        top = await cur.fetchall()
        return {"total_requests": total, "top_endpoints": [{"endpoint": r[0], "count": r[1]} for r in top]}
