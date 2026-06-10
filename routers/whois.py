from fastapi import APIRouter, Depends, HTTPException
from routers.auth import get_api_key_dependency
from cache import get_cache, set_cache
from pydantic import BaseModel
import asyncio
import whois as pywhois
from config import settings

router = APIRouter(prefix="/whois")


class WhoisOut(BaseModel):
    domain: str
    registrar: str | None
    creation_date: str | None
    expiration_date: str | None
    updated_date: str | None
    name_servers: list | None
    status: list | None
    emails: list | None
    country: str | None


@router.get("/{domain}", response_model=WhoisOut)
async def whois_lookup(domain: str, api_key: str = Depends(get_api_key_dependency)):
    cache_key = f"whois:{domain}"
    cached = await get_cache(cache_key)
    if cached:
        return cached

    def blocking():
        return pywhois.whois(domain)

    try:
        w = await asyncio.to_thread(blocking)
    except Exception as e:
        raise HTTPException(status_code=502, detail={"error": "WHOIS lookup failed", "detail": str(e)})

    def _to_iso(val):
        if val is None:
            return None
        # if list, take first
        if isinstance(val, (list, tuple)):
            if not val:
                return None
            val = val[0]
        # if datetime-like                                                                                                                                                                                                                                                                                                                                                                                        
        try:
            from datetime import datetime
            if isinstance(val, datetime):
                return val.isoformat()
        except Exception:
            pass
        # if has isoformat
        if hasattr(val, "isoformat"):
            try:
                return val.isoformat()
            except Exception:
                return str(val)
        # otherwise return as string
        return str(val)

    out = {
        "domain": domain,
        "registrar": getattr(w, "registrar", None),
        "creation_date": _to_iso(getattr(w, "creation_date", None)),
        "expiration_date": _to_iso(getattr(w, "expiration_date", None)),
        "updated_date": _to_iso(getattr(w, "updated_date", None)),
        "name_servers": getattr(w, "name_servers", None),
        "status": getattr(w, "status", None),
        "emails": getattr(w, "emails", None),
        "country": getattr(w, "country", None),
    }
    await set_cache(cache_key, out, settings.CACHE_TTL_WHOIS)
    return out
