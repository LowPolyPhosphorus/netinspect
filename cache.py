import json
import time
import aiosqlite
import os
import logging
from typing import Optional, Any
from config import settings

logging.basicConfig(level=logging.INFO)
DB_PATH = os.path.abspath(settings.SQLITE_DB)


async def get_cache(cache_key: str) -> Optional[Any]:
    now = time.time()
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute("SELECT value, expires_at FROM cache WHERE cache_key = ?", (cache_key,))
        row = await cur.fetchone()
        if not row:
            return None
        value, expires_at = row
        if expires_at and expires_at < now:
            await db.execute("DELETE FROM cache WHERE cache_key = ?", (cache_key,))
            await db.commit()
            return None
        try:
            return json.loads(value)
        except Exception:
            return value


async def set_cache(cache_key: str, value: Any, ttl: int):
    expires_at = time.time() + ttl if ttl else None
    v = json.dumps(value)
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT OR REPLACE INTO cache (cache_key, value, expires_at) VALUES (?, ?, ?)",
            (cache_key, v, expires_at),
        )
        await db.commit()


async def clear_cache():
    logging.info(f"[cache] clearing cache table in {DB_PATH}")
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM cache")
        await db.commit()
