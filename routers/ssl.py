from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from routers.auth import get_api_key_dependency
from config import settings
import asyncio
import subprocess
import tempfile
import ssl as _ssl
import socket
import datetime
from email.utils import parsedate_to_datetime
from typing import List

router = APIRouter(prefix="/ssl")


class SSLInfo(BaseModel):
    domain: str
    valid_until: str | None
    days_until_expiry: int | None
    is_expiring_soon: bool | None
    subject: dict | None
    issuer: dict | None


class ChainOut(BaseModel):
    domain: str
    chain: List[str]


class TLSInfo(BaseModel):
    domain: str
    protocol: str | None
    cipher: str | None


def _run_openssl_showcerts(host: str, timeout: int = 10) -> List[str]:
    cmd = ["openssl", "s_client", "-showcerts", "-connect", f"{host}:443", "-servername", host]
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
    out = proc.stdout or proc.stderr
    certs = []
    cur = []
    in_cert = False
    for line in out.splitlines():
        if "-----BEGIN CERTIFICATE-----" in line:
            in_cert = True
            cur = [line]
        elif "-----END CERTIFICATE-----" in line and in_cert:
            cur.append(line)
            certs.append("\n".join(cur))
            in_cert = False
        elif in_cert:
            cur.append(line)
    return certs


def _get_cert_expiry_from_pem(pem: str) -> str:
    # write to temp file and call openssl x509 -noout -enddate
    with tempfile.NamedTemporaryFile("w+", delete=False) as tf:
        tf.write(pem)
        tf.flush()
        path = tf.name
    proc = subprocess.run(["openssl", "x509", "-noout", "-enddate", "-in", path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out = proc.stdout.strip()
    if out.startswith("notAfter="):
        return out.split("=", 1)[1].strip()
    raise RuntimeError("Could not parse expiry")


def _get_subject_issuer_from_pem(pem: str) -> tuple:
    with tempfile.NamedTemporaryFile("w+", delete=False) as tf:
        tf.write(pem)
        tf.flush()
        path = tf.name
    proc = subprocess.run(["openssl", "x509", "-noout", "-subject", "-issuer", "-in", path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out = proc.stdout.strip().splitlines()
    subj = None
    issuer = None
    for line in out:
        if line.startswith("subject="):
            subj = line.split("=", 1)[1].strip()
        if line.startswith("issuer="):
            issuer = line.split("=", 1)[1].strip()
    return subj, issuer


def _get_tls_info(host: str, timeout: int = 10):
    ctx = _ssl.create_default_context()
    conn = socket.create_connection((host, 443), timeout=timeout)
    ss = ctx.wrap_socket(conn, server_hostname=host)
    try:
        cur = ss.cipher()
        protocol = ss.version()
        cipher = cur[0] if cur else None
    finally:
        try:
            ss.close()
        except Exception:
            pass
    return protocol, cipher


@router.get("/{domain}", response_model=SSLInfo)
async def ssl_info(domain: str, api_key: str = Depends(get_api_key_dependency)):
    loop = asyncio.get_running_loop()
    try:
        certs = await loop.run_in_executor(None, _run_openssl_showcerts, domain, 10)
    except subprocess.SubprocessError as e:
        raise HTTPException(status_code=502, detail={"error": "OpenSSL failure", "detail": str(e)})
    if not certs:
        raise HTTPException(status_code=404, detail={"error": "No certificate found", "detail": "Could not retrieve peer certificate"})

    # parse first cert expiry
    expiry_str = None
    days = None
    subj = None
    issuer = None
    try:
        expiry_str = await loop.run_in_executor(None, _get_cert_expiry_from_pem, certs[0])
        dt = parsedate_to_datetime(expiry_str)
        now = datetime.datetime.utcnow()
        if dt.tzinfo is not None:
            now = now.replace(tzinfo=dt.tzinfo)
        days = max(0, (dt - now).days)
    except Exception:
        expiry_str = None
        days = None

    try:
        subj, issuer = await loop.run_in_executor(None, _get_subject_issuer_from_pem, certs[0])
    except Exception:
        subj = None
        issuer = None

    is_expiring = False
    if days is not None:
        is_expiring = days <= 30

    return {"domain": domain, "valid_until": expiry_str, "days_until_expiry": days, "is_expiring_soon": is_expiring, "subject": subj, "issuer": issuer}


@router.get("/{domain}/chain", response_model=ChainOut)
async def cert_chain(domain: str, api_key: str = Depends(get_api_key_dependency)):
    loop = asyncio.get_running_loop()
    try:
        certs = await loop.run_in_executor(None, _run_openssl_showcerts, domain, 10)
    except Exception as e:
        raise HTTPException(status_code=502, detail={"error": "OpenSSL failure", "detail": str(e)})
    return {"domain": domain, "chain": certs}


@router.get("/{domain}/tls", response_model=TLSInfo)
async def tls_info(domain: str, api_key: str = Depends(get_api_key_dependency)):
    loop = asyncio.get_running_loop()
    try:
        proto, cipher = await loop.run_in_executor(None, _get_tls_info, domain, 10)
    except Exception as e:
        raise HTTPException(status_code=502, detail={"error": "TLS probe failed", "detail": str(e)})
    return {"domain": domain, "protocol": proto, "cipher": cipher}
