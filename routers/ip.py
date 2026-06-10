from fastapi import APIRouter, Depends, HTTPException
from routers.auth import get_api_key_dependency
from cache import get_cache, set_cache
from config import settings
import httpx
import asyncio

router = APIRouter(prefix="/ip")


@router.get("/{ip}")
async def ip_info(ip: str, api_key: str = Depends(get_api_key_dependency)):
    cache_key = f"ip:{ip}"
    cached = await get_cache(cache_key)
    if cached:
        return cached

    url = settings.IP_API_URL.format(ip=ip)
    timeout = httpx.Timeout(settings.HTTP_TIMEOUT)
    async with httpx.AsyncClient(timeout=timeout) as client:
        # simple retry with backoff
        delay = 0.5
        for attempt in range(4):
            try:
                r = await client.get(url)
                r.raise_for_status()
                data = r.json()
                if data.get("status") == "fail":
                    raise HTTPException(status_code=404, detail={"error": "IP lookup failed", "detail": data.get("message")})
                out = {
                    "ip": data.get("query") or ip,
                    "country": data.get("country"),
                    "country_code": data.get("countryCode"),
                    "region": data.get("regionName"),
                    "city": data.get("city"),
                    "zip": data.get("zip"),
                    "lat": data.get("lat"),
                    "lon": data.get("lon"),
                    "timezone": data.get("timezone"),
                    "isp": data.get("isp"),
                    "org": data.get("org"),
                    "asn": data.get("as"),
                    "is_proxy": data.get("proxy"),
                    "is_hosting": data.get("hosting"),
                    "is_mobile": data.get("mobile"),
                }
                await set_cache(cache_key, out, settings.CACHE_TTL_IP)
                return out
            except httpx.HTTPError as e:
                if attempt == 3:
                    raise HTTPException(status_code=502, detail={"error": "Upstream failure", "detail": str(e)})
                await asyncio.sleep(delay)
                delay *= 2


@router.get("/{ip}/blacklist")
async def ip_blacklist(ip: str, api_key: str = Depends(get_api_key_dependency)):
    # Simple DNSBL checks via DNS-over-HTTPS (using Google) - reverse IP
    rev = ".".join(reversed(ip.split(".")))
    blacklists = {
        "spamhaus": f"{rev}.zen.spamhaus.org",
        "sorbs": f"{rev}.dnsbl.sorbs.net",
    }
    timeout = httpx.Timeout(settings.HTTP_TIMEOUT)
    async with httpx.AsyncClient(timeout=timeout) as client:
        tasks = {}
        for name, host in blacklists.items():
            url = "https://dns.google/resolve"
            tasks[name] = client.get(url, params={"name": host, "type": "A"})
        res = await asyncio.gather(*tasks.values(), return_exceptions=True)
        out = {}
        for k, r in zip(tasks.keys(), res):
            if isinstance(r, Exception):
                out[k] = {"error": str(r)}
            else:
                j = r.json()
                out[k] = {"listed": bool(j.get("Answer"))}
        return {"ip": ip, "blacklist": out}


@router.get("/{ip}/tor")
async def ip_tor(ip: str, api_key: str = Depends(get_api_key_dependency)):
    # naive: check against a public Tor exit list snapshot via HTTP (could be slow)
    url = "https://check.torproject.org/exit-addresses"
    timeout = httpx.Timeout(settings.HTTP_TIMEOUT)
    async with httpx.AsyncClient(timeout=timeout) as client:
        r = await client.get(url)
        txt = r.text
        found = ip in txt
        return {"ip": ip, "is_tor_exit": found}
