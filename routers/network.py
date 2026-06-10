from fastapi import APIRouter, Depends, HTTPException
from routers.auth import get_api_key_dependency
from cache import get_cache, set_cache
from config import settings
import asyncio
import socket
from fastapi.responses import StreamingResponse
import subprocess
import sys

router = APIRouter(prefix="/network")


@router.get("/ports/{host}")
async def port_scan(host: str, ports: str | None = None, api_key: str = Depends(get_api_key_dependency)):
    if ports:
        port_list = [int(p) for p in ports.split(",")]
    else:
        port_list = [int(p) for p in settings.PORT_SCAN_LIST.split(",")]

    async def check_port(p):
        try:
            conn = asyncio.open_connection(host, p)
            reader, writer = await asyncio.wait_for(conn, timeout=1)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return p, True
        except Exception:
            return p, False

    tasks = [check_port(p) for p in port_list]
    results = await asyncio.gather(*tasks)
    return {"host": host, "ports": {p: {"open": o} for p, o in results}}


@router.get("/ping/{host}")
async def ping(host: str, api_key: str = Depends(get_api_key_dependency)):
    # Use system ping for cross-platform
    count_flag = "-n" if sys.platform.startswith("win") else "-c"
    proc = await asyncio.create_subprocess_exec("ping", count_flag, "1", host, stdout=asyncio.subprocess.PIPE)
    out, _ = await proc.communicate()
    return {"host": host, "output": out.decode(errors="ignore")} 


@router.get("/traceroute/{host}")
async def traceroute(host: str, api_key: str = Depends(get_api_key_dependency)):
    # Stream traceroute output
    cmd = ["tracert", host] if sys.platform.startswith("win") else ["traceroute", host]

    async def stream():
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE)
        assert proc.stdout
        while True:
            line = await proc.stdout.readline()
            if not line:
                break
            yield line

    return StreamingResponse(stream(), media_type="text/plain")


@router.get("/whois/{ip}")
async def network_whois(ip: str, api_key: str = Depends(get_api_key_dependency)):
    # Simple placeholder BGP/ASN info via ip-api
    url = settings.IP_API_URL.format(ip=ip)
    import httpx
    async with httpx.AsyncClient(timeout=settings.HTTP_TIMEOUT) as client:
        r = await client.get(url)
        r.raise_for_status()
        data = r.json()
        return {"ip": ip, "bgp": data}
