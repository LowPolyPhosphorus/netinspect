from fastapi import APIRouter, Depends, HTTPException
from routers.auth import get_api_key_dependency
from cache import get_cache, set_cache
from config import settings
import httpx
from pydantic import BaseModel
from typing import List
import asyncio

router = APIRouter(prefix="/http")


@router.get("/headers/{domain}")
async def headers(domain: str, api_key: str = Depends(get_api_key_dependency)):
    cache_key = f"headers:{domain}"
    cached = await get_cache(cache_key)
    if cached:
        return cached
    url = domain if domain.startswith("http") else f"https://{domain}"
    timeout = httpx.Timeout(settings.HTTP_TIMEOUT)
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        r = await client.get(url)
        out = {"domain": domain, "status_code": r.status_code, "headers": dict(r.headers)}
        await set_cache(cache_key, out, settings.CACHE_TTL_HEADERS)
        return out


@router.get("/redirects/{domain}")
async def redirects(domain: str, api_key: str = Depends(get_api_key_dependency)):
    url = domain if domain.startswith("http") else f"https://{domain}"
    timeout = httpx.Timeout(settings.HTTP_TIMEOUT)
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        r = await client.get(url)
        chain = [{"url": h.url, "status_code": h.status_code} for h in r.history]
        chain.append({"url": r.url, "status_code": r.status_code})
        out = {"domain": domain, "hops": len(chain), "chain": chain}
        await set_cache(f"redirects:{domain}", out, settings.CACHE_TTL_REDIRECTS)
        return out


@router.get("/security/{domain}")
async def security(domain: str, api_key: str = Depends(get_api_key_dependency)):
    h = await headers(domain, api_key)
    headers_map = h.get("headers", {})
    security_headers = [
        "content-security-policy",
        "x-frame-options",
        "strict-transport-security",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy",
    ]
    out = {}
    for hh in security_headers:
        out[hh] = {"present": hh in headers_map, "value": headers_map.get(hh)}
    return {"domain": domain, "security": out}


@router.get("/robots/{domain}")
async def robots(domain: str, api_key: str = Depends(get_api_key_dependency)):
    url = f"https://{domain}/robots.txt"
    timeout = httpx.Timeout(settings.HTTP_TIMEOUT)
    async with httpx.AsyncClient(timeout=timeout) as client:
        r = await client.get(url)
        return {"domain": domain, "status_code": r.status_code, "content": r.text}


@router.get("/performance/{domain}")
async def performance(domain: str, api_key: str = Depends(get_api_key_dependency)):
    url = domain if domain.startswith("http") else f"https://{domain}"
    timeout = httpx.Timeout(settings.HTTP_TIMEOUT)
    async with httpx.AsyncClient(timeout=timeout) as client:
        start = asyncio.get_event_loop().time()
        r = await client.get(url)
        end = asyncio.get_event_loop().time()
        # response_time in milliseconds
        response_time_ms = (end - start) * 1000.0
        ttfb_ms = None
        if hasattr(r, "elapsed") and r.elapsed is not None:
            try:
                ttfb_ms = r.elapsed.total_seconds() * 1000.0
            except Exception:
                ttfb_ms = None
        return {"domain": domain, "status_code": r.status_code, "response_time_ms": response_time_ms, "ttfb_ms": ttfb_ms, "content_length": len(r.content)}
