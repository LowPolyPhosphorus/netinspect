from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from routers.auth import get_api_key_dependency
from cache import get_cache, set_cache
from config import settings
import httpx
import asyncio
from typing import List, Optional

router = APIRouter(prefix="/dns")


class DNSRecord(BaseModel):
    domain: str
    record_type: str
    records: List[str]


async def doh_query(name: str, rtype: str, url: str):
    params = {"name": name, "type": rtype}
    timeout = httpx.Timeout(settings.HTTP_TIMEOUT)
    async with httpx.AsyncClient(timeout=timeout) as client:
        r = await client.get(url, params=params)
        r.raise_for_status()
        return r.json()


@router.get("/{domain}", response_model=DNSRecord)
async def dns_lookup(domain: str, record_type: str = "A", api_key: str = Depends(get_api_key_dependency)):
    cache_key = f"dns:{domain}:{record_type}"
    cached = await get_cache(cache_key)
    if cached:
        return cached

    urls = [
        "https://dns.google/resolve",
        "https://cloudflare-dns.com/dns-query",
        "https://dns.opendns.com/dns-query",
    ]

    tasks = [doh_query(domain, record_type, u) for u in urls]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    records = []
    for res in results:
        if isinstance(res, Exception):
            continue
        ans = res.get("Answer") or res.get("answer") or []
        for a in ans:
            val = a.get("data") or a.get("rdata") or a
            records.append(val)

    out = {"domain": domain, "record_type": record_type, "records": records}
    await set_cache(cache_key, out, settings.CACHE_TTL_DNS)
    return out


@router.get("/{domain}/reverse")
async def reverse_lookup(domain: str, api_key: str = Depends(get_api_key_dependency)):
    # treat domain as IP and ask PTR
    cache_key = f"dns:reverse:{domain}"
    cached = await get_cache(cache_key)
    if cached:
        return cached
    url = "https://dns.google/resolve"
    res = await doh_query(domain, "PTR", url)
    records = [a.get("data") for a in (res.get("Answer") or [])]
    out = {"domain": domain, "records": records}
    await set_cache(cache_key, out, settings.CACHE_TTL_DNS)
    return out


@router.get("/{domain}/propagation")
async def propagation(domain: str, api_key: str = Depends(get_api_key_dependency)):
    urls = {
        "google": "https://dns.google/resolve",
        "cloudflare": "https://cloudflare-dns.com/dns-query",
        "opendns": "https://dns.opendns.com/dns-query",
    }
    tasks = {k: doh_query(domain, "A", u) for k, u in urls.items()}
    results = await asyncio.gather(*tasks.values(), return_exceptions=True)
    out = {}
    for k, res in zip(tasks.keys(), results):
        if isinstance(res, Exception):
            out[k] = {"error": str(res)}
        else:
            out[k] = [a.get("data") for a in (res.get("Answer") or [])]
    return {"domain": domain, "propagation": out}


@router.get("/{domain}/spf")
async def spf_lookup(domain: str, api_key: str = Depends(get_api_key_dependency)):
    cache_key = f"dns:spf:{domain}"
    cached = await get_cache(cache_key)
    if cached:
        return cached
    # fetch TXT via DOH
    res = await doh_query(domain, "TXT", "https://dns.google/resolve")
    txts = [a.get("data") for a in (res.get("Answer") or [])]
    spf = [t for t in txts if t and ("v=spf1" in t.lower() or "dkim" in t.lower() or "dmarc" in t.lower())]
    out = {"domain": domain, "spf": spf, "all_txt": txts}
    await set_cache(cache_key, out, settings.CACHE_TTL_WHOIS)
    return out


@router.get("/{domain}/dnssec")
async def dnssec_check(domain: str, api_key: str = Depends(get_api_key_dependency)):
    res = await doh_query(domain, "A", "https://dns.google/resolve")
    ad = res.get("AD") or res.get("ad") or False
    return {"domain": domain, "dnssec": bool(ad)}
