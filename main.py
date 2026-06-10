from fastapi import FastAPI, Depends, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from slowapi.middleware import SlowAPIMiddleware
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from fastapi.security import APIKeyHeader
from fastapi.openapi.utils import get_openapi
import uvicorn
import time

from config import settings
from db import init_db, fetch_history, fetch_stats
from cache import clear_cache

# routers
from routers import auth as auth_router
from routers import dns as dns_router
from routers import whois as whois_router
from routers import ip as ip_router
from routers import http as http_router
from routers import network as network_router


def _key_func(request: Request):
  return request.headers.get("X-API-Key") or get_remote_address(request)


limiter = Limiter(key_func=_key_func, default_limits=[settings.RATE_LIMIT])

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

app = FastAPI(
    title="netinspect",
    description="A network intelligence API.",
    version="1.0.0",
    docs_url=None,
    redoc_url="/redoc",
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
app.add_middleware(SlowAPIMiddleware)

app.include_router(auth_router.router)
app.include_router(dns_router.router)
app.include_router(whois_router.router)
app.include_router(ip_router.router)
app.include_router(http_router.router)
app.include_router(network_router.router)
from routers import ssl as ssl_router
app.include_router(ssl_router.router)

# expose limiter to middleware and handlers
app.state.limiter = limiter


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
  headers = getattr(exc, "headers", {}) or {}
  return JSONResponse(status_code=429, content={"error": "Too Many Requests", "detail": "Rate limit exceeded"}, headers=headers)


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
  if isinstance(exc.detail, dict):
    content = exc.detail
  else:
    content = {"error": str(exc.detail), "detail": ""}
  return JSONResponse(status_code=exc.status_code, content=content, headers=getattr(exc, "headers", {}) or {})


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
  return JSONResponse(status_code=422, content={"error": "Validation Error", "detail": str(exc)})


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
  return JSONResponse(status_code=500, content={"error": "Internal Server Error", "detail": str(exc)})

start_time = time.time()


@app.on_event("startup")
async def on_startup():
    await init_db()


@app.get("/health")
async def health():
    uptime = round(time.time() - start_time, 2)
    return {"uptime_s": uptime, "version": settings.VERSION}


@app.get("/changelog")
async def changelog():
    return {"version": settings.VERSION, "changes": ["Initial modular netinspect implementation"]}


@app.get("/me/history")
async def me_history(request: Request, page: int = 1, limit: int = 20, x_api_key: str = Depends(auth_router.get_api_key_dependency)):
    data = await fetch_history(x_api_key, page=page, limit=limit)
    return {"page": page, "limit": limit, "results": data}


@app.get("/me/stats")
async def me_stats(x_api_key: str = Depends(auth_router.get_api_key_dependency)):
    data = await fetch_stats(x_api_key)
    return data


@app.delete("/cache", include_in_schema=True)
async def delete_cache(x_api_key: str = Depends(auth_router.get_api_key_dependency)):
  """Clear all cache entries from the SQLite cache table (development helper)."""
  await clear_cache()
  return {"result": "cache_cleared"}


import asyncio


@app.get("/summary/{domain}")
async def summary(domain: str, api_key: str = Depends(auth_router.get_api_key_dependency)):
  """Run a parallel summary of DNS, WHOIS, HTTP headers and IP for a domain."""
  dns_task = dns_router.dns_lookup(domain, "A", api_key)
  whois_task = whois_router.whois_lookup(domain, api_key)
  headers_task = http_router.headers(domain, api_key)

  results = await asyncio.gather(dns_task, whois_task, headers_task, return_exceptions=True)
  dns_res, whois_res, headers_res = results

  ip_res = None
  try:
    if dns_res and isinstance(dns_res, dict):
      records = dns_res.get("records") or []
      first_ip = None
      for r in records:
        if isinstance(r, str) and any(ch.isdigit() for ch in r):
          first_ip = r.split()[0]
          break
      if first_ip:
        ip_res = await ip_router.ip_info(first_ip, api_key)
  except Exception:
    ip_res = None

  out = {"domain": domain, "dns": dns_res, "whois": whois_res, "http": headers_res, "ip": ip_res}
  return out


@app.get("/docs", include_in_schema=False)
async def custom_docs():
    html = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>netinspect API Reference</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;font-size:14px;line-height:1.6;color:#1a1f36;background:#fff;display:flex;min-height:100vh}

/* sidebar */
#sidebar{width:240px;min-width:240px;background:#0a2540;position:fixed;top:0;left:0;height:100vh;overflow-y:auto;padding:0 0 40px 0;z-index:100}
#sidebar-header{padding:20px 20px 16px;border-bottom:1px solid rgba(255,255,255,0.1)}
#sidebar-header .logo{color:#fff;font-size:16px;font-weight:700;letter-spacing:-0.3px;text-decoration:none;display:block}
#sidebar-header .version{color:rgba(255,255,255,0.4);font-size:11px;margin-top:2px}
.nav-section{padding:20px 0 4px}
.nav-label{color:rgba(255,255,255,0.35);font-size:10px;font-weight:700;letter-spacing:1px;text-transform:uppercase;padding:0 20px 6px}
.nav-link{display:block;color:rgba(255,255,255,0.65);text-decoration:none;padding:5px 20px;font-size:13px;transition:color 0.15s,background 0.15s}
.nav-link:hover,.nav-link.active{color:#fff;background:rgba(255,255,255,0.08)}

/* main */
#main{margin-left:240px;flex:1;padding:0}
.content-wrap{max-width:820px;padding:48px 56px 80px}

/* topbar */
#topbar{border-bottom:1px solid #e3e8ee;padding:14px 56px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;background:#fff;z-index:50}
#topbar .title{font-size:13px;color:#6b7c93;font-weight:500}
#topbar a{color:#5469d4;font-size:13px;text-decoration:none}
#topbar a:hover{text-decoration:underline}

/* sections */
.section{padding:48px 56px;border-bottom:1px solid #e3e8ee}
.section:last-child{border-bottom:none}
h1{font-size:28px;font-weight:700;color:#1a1f36;letter-spacing:-0.5px;margin-bottom:12px}
h2{font-size:20px;font-weight:700;color:#1a1f36;letter-spacing:-0.3px;margin-bottom:10px}
h3{font-size:14px;font-weight:700;color:#1a1f36;margin:28px 0 8px}
p{color:#3c4257;margin-bottom:14px;line-height:1.7}
p:last-child{margin-bottom:0}

/* base url box */
.base-url-box{background:#f7fafc;border:1px solid #e3e8ee;border-radius:6px;padding:14px 18px;margin:20px 0;font-family:"SF Mono","Fira Code",Consolas,monospace;font-size:13px;color:#1a1f36}
.base-url-box .label{font-size:10px;font-weight:700;letter-spacing:1px;text-transform:uppercase;color:#8898aa;margin-bottom:4px}

/* method badges */
.badge{display:inline-block;font-size:10px;font-weight:700;letter-spacing:0.5px;padding:2px 7px;border-radius:3px;text-transform:uppercase;margin-right:8px;vertical-align:middle}
.badge-get{background:#d1fae5;color:#065f46}
.badge-post{background:#dbeafe;color:#1e40af}
.badge-delete{background:#fee2e2;color:#991b1b}

/* endpoint blocks */
.endpoint{margin-bottom:32px;padding-bottom:32px;border-bottom:1px solid #f0f0f5}
.endpoint:last-child{border-bottom:none;margin-bottom:0;padding-bottom:0}
.endpoint-title{display:flex;align-items:center;margin-bottom:8px}
.endpoint-path{font-family:"SF Mono","Fira Code",Consolas,monospace;font-size:14px;font-weight:600;color:#1a1f36}
.endpoint-desc{color:#3c4257;font-size:13px;margin-bottom:12px;line-height:1.6}
.param-table{width:100%;border-collapse:collapse;font-size:12px;margin:10px 0 0}
.param-table th{text-align:left;padding:6px 10px;background:#f7fafc;color:#8898aa;font-size:10px;font-weight:700;letter-spacing:0.5px;text-transform:uppercase;border-bottom:1px solid #e3e8ee}
.param-table td{padding:8px 10px;border-bottom:1px solid #f0f0f5;color:#3c4257;vertical-align:top}
.param-table tr:last-child td{border-bottom:none}
.param-name{font-family:"SF Mono","Fira Code",Consolas,monospace;font-weight:600;color:#1a1f36;font-size:12px}
.param-type{color:#8898aa;font-size:11px}
.param-required{color:#e25950;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:0.5px}
.param-optional{color:#8898aa;font-size:10px;text-transform:uppercase;letter-spacing:0.5px}

/* code blocks */
pre.code{background:#0d1117;color:#c9d1d9;font-family:"SF Mono","Fira Code",Consolas,monospace;font-size:12px;line-height:1.6;padding:16px 20px;border-radius:6px;overflow-x:auto;margin:12px 0}
pre.code .c{color:#6a9955}
pre.code .s{color:#ce9178}
pre.code .k{color:#569cd6}
pre.code .p{color:#c9d1d9}
code{font-family:"SF Mono","Fira Code",Consolas,monospace;font-size:12px;background:#f0f0f5;padding:1px 5px;border-radius:3px;color:#1a1f36}

/* auth note */
.auth-note{display:inline-flex;align-items:center;gap:6px;background:#fef3c7;border:1px solid #fbbf24;border-radius:4px;padding:4px 10px;font-size:12px;color:#92400e;margin-bottom:16px}
.no-auth{display:inline-flex;align-items:center;gap:6px;background:#f0fdf4;border:1px solid #86efac;border-radius:4px;padding:4px 10px;font-size:12px;color:#166534;margin-bottom:16px}

/* rate limit callout */
.callout{background:#eff6ff;border-left:3px solid #5469d4;border-radius:0 6px 6px 0;padding:12px 16px;margin:16px 0;font-size:13px;color:#1e3a5f}

/* demo */
.demo-inputs{display:flex;flex-direction:column;gap:12px;margin:20px 0}
.demo-inputs label{font-size:12px;font-weight:600;color:#1a1f36;margin-bottom:4px;display:block}
.demo-inputs input{width:100%;padding:8px 12px;border:1px solid #e3e8ee;border-radius:5px;font-size:13px;color:#1a1f36;font-family:inherit;outline:none;transition:border-color 0.15s}
.demo-inputs input:focus{border-color:#5469d4;box-shadow:0 0 0 2px rgba(84,105,212,0.15)}
#run-btn{background:#5469d4;color:#fff;border:none;padding:9px 20px;border-radius:5px;font-size:13px;font-weight:600;cursor:pointer;transition:background 0.15s}
#run-btn:hover{background:#3d4fc0}
#run-btn:disabled{background:#a0aec0;cursor:not-allowed}
#demo-out{background:#0d1117;color:#c9d1d9;font-family:"SF Mono","Fira Code",Consolas,monospace;font-size:12px;line-height:1.6;padding:16px 20px;border-radius:6px;white-space:pre-wrap;margin-top:16px;min-height:60px;display:none}
#demo-out.visible{display:block}

/* register box */
.register-box{background:#f7fafc;border:1px solid #e3e8ee;border-radius:8px;padding:20px 24px;margin:20px 0}
.register-box p{margin-bottom:12px}
.register-row{display:flex;gap:10px;align-items:flex-end}
.register-row input{flex:1;padding:8px 12px;border:1px solid #e3e8ee;border-radius:5px;font-size:13px;color:#1a1f36;font-family:inherit;outline:none;transition:border-color 0.15s}
.register-row input:focus{border-color:#5469d4;box-shadow:0 0 0 2px rgba(84,105,212,0.15)}
#reg-btn{background:#5469d4;color:#fff;border:none;padding:9px 16px;border-radius:5px;font-size:13px;font-weight:600;cursor:pointer;white-space:nowrap;transition:background 0.15s}
#reg-btn:hover{background:#3d4fc0}
#reg-btn:disabled{background:#a0aec0;cursor:not-allowed}
.key-display{display:none;margin-top:14px;background:#f0fdf4;border:1px solid #86efac;border-radius:5px;padding:10px 14px;font-family:"SF Mono","Fira Code",Consolas,monospace;font-size:12px;color:#166534;word-break:break-all}
.key-display.visible{display:block}
.key-display .key-label{font-size:10px;font-weight:700;letter-spacing:0.5px;text-transform:uppercase;color:#16a34a;margin-bottom:4px}
#copy-key-btn{background:none;border:1px solid #86efac;color:#16a34a;border-radius:4px;padding:3px 8px;font-size:11px;cursor:pointer;margin-top:6px;font-weight:600}

/* dark mode */
body.dark{background:#0f172a;color:#e2e8f0}
body.dark #sidebar{background:#080f1e}
body.dark #main{background:#0f172a}
body.dark #topbar{background:#0f172a;border-color:#1e293b}
body.dark .section{border-color:#1e293b}
body.dark h1,body.dark h2,body.dark h3{color:#f1f5f9}
body.dark p,body.dark .endpoint-desc{color:#94a3b8}
body.dark .endpoint{border-color:#1e293b}
body.dark .base-url-box{background:#1e293b;border-color:#334155;color:#e2e8f0}
body.dark .base-url-box .label{color:#64748b}
body.dark .param-table th{background:#1e293b;color:#64748b;border-color:#334155}
body.dark .param-table td{border-color:#1e293b;color:#94a3b8}
body.dark .param-name{color:#e2e8f0}
body.dark .endpoint-path{color:#e2e8f0}
body.dark code{background:#1e293b;color:#c4b5fd}
body.dark .callout{background:#1e2d45;border-color:#6366f1;color:#a5b4fc}
body.dark .auth-note{background:#2d2006;border-color:#ca8a04;color:#fbbf24}
body.dark .no-auth{background:#052e16;border-color:#16a34a;color:#4ade80}
body.dark .footer{border-color:#1e293b;color:#475569}
body.dark .footer a{color:#818cf8}
body.dark #topbar .title{color:#475569}
body.dark #topbar a{color:#818cf8}
body.dark .demo-inputs label{color:#e2e8f0}
body.dark .demo-inputs input{background:#1e293b;border-color:#334155;color:#e2e8f0}
body.dark .demo-inputs input:focus{border-color:#6366f1;box-shadow:0 0 0 2px rgba(99,102,241,0.2)}
body.dark #demo-out{background:#080f1e}
body.dark .register-box{background:#1e293b;border-color:#334155}
body.dark .register-box p{color:#94a3b8}
body.dark .register-row input{background:#0f172a;border-color:#334155;color:#e2e8f0}
body.dark .register-row input:focus{border-color:#6366f1}
body.dark .key-display{background:#052e16;border-color:#16a34a;color:#4ade80}
body.dark .key-display .key-label{color:#4ade80}
body.dark #copy-key-btn{border-color:#16a34a;color:#4ade80}

/* toggle button */
#theme-toggle{background:none;border:1px solid rgba(255,255,255,0.2);color:rgba(255,255,255,0.7);border-radius:20px;padding:4px 12px;font-size:12px;cursor:pointer;transition:all 0.15s;font-family:inherit}
#theme-toggle:hover{background:rgba(255,255,255,0.08);color:#fff}

/* footer */
.footer{padding:24px 56px;color:#8898aa;font-size:12px;border-top:1px solid #e3e8ee}
.footer a{color:#5469d4;text-decoration:none}
</style>
</head>
<body>

<nav id="sidebar">
  <div id="sidebar-header">
    <a href="#overview" class="logo">netinspect</a>
    <div class="version">API v1.0.0</div>
  </div>
  <div class="nav-section">
    <div class="nav-label">Getting Started</div>
    <a class="nav-link" href="#overview">Overview</a>
    <a class="nav-link" href="#authentication">Authentication</a>
  </div>
  <div class="nav-section">
    <div class="nav-label">Endpoints</div>
    <a class="nav-link" href="#dns">DNS</a>
    <a class="nav-link" href="#whois">WHOIS</a>
    <a class="nav-link" href="#ssl">SSL / TLS</a>
    <a class="nav-link" href="#ip">IP Intelligence</a>
    <a class="nav-link" href="#http">HTTP Analysis</a>
    <a class="nav-link" href="#network">Network</a>
    <a class="nav-link" href="#summary">Summary</a>
  </div>
  <div class="nav-section">
    <div class="nav-label">Account</div>
    <a class="nav-link" href="#user">History &amp; Stats</a>
    <a class="nav-link" href="#meta">Health &amp; Meta</a>
  </div>
  <div class="nav-section">
    <div class="nav-label">Tools</div>
    <a class="nav-link" href="#demo">Interactive Demo</a>
    <a class="nav-link" href="/swagger" target="_blank">Swagger UI</a>
    <a class="nav-link" href="/redoc" target="_blank">ReDoc</a>
    <a class="nav-link" href="/openapi.json" target="_blank">OpenAPI JSON</a>
  </div>
</nav>

<div id="main">
  <div id="topbar">
    <span class="title">API Reference</span>
    <div style="display:flex;align-items:center;gap:16px">
      <button id="theme-toggle" onclick="toggleTheme()">Dark</button>
      <a href="/swagger" target="_blank">Swagger UI &rarr;</a>
    </div>
  </div>

  <div class="section" id="overview">
    <div class="content-wrap">
      <h1>netinspect API Reference</h1>
      <p>netinspect is a network intelligence REST API for inspecting domains and IP addresses. It covers DNS records, WHOIS registration data, SSL/TLS certificates, HTTP headers and security posture, IP geolocation and reputation, and network reachability. All responses are JSON.</p>
      <div class="base-url-box">
        <div class="label">Base URL</div>
        https://your-deployment-url
      </div>
      <p>All endpoints except <code>/register</code>, <code>/health</code>, <code>/changelog</code>, and <code>/docs</code> require an API key passed in the <code>X-API-Key</code> request header.</p>
    </div>
  </div>

  <div class="section" id="authentication">
    <div class="content-wrap">
      <h2>Authentication</h2>
      <p>Register for a free API key below. The key is stored in the server database and returned immediately. Once you have it, all authenticated endpoints on this page will use it automatically.</p>

      <h3>Get an API key</h3>
      <div class="no-auth">No authentication required</div>
      <div class="register-box">
        <p>Enter your email to register. A key will be generated and saved for you.</p>
        <div class="register-row">
          <input type="email" id="reg-email" placeholder="you@example.com" autocomplete="email"/>
          <button id="reg-btn">Register</button>
        </div>
        <div class="key-display" id="key-display">
          <div class="key-label">Your API Key</div>
          <div id="key-value"></div>
          <button id="copy-key-btn" onclick="copyKey()">Copy</button>
          <div style="margin-top:8px;font-size:11px;opacity:0.8">This key has been filled into the demo below automatically.</div>
        </div>
      </div>

      <h3>Using your key</h3>
      <p>Pass the key as the <code>X-API-Key</code> header on every authenticated request.</p>
      <pre class="code">curl https://your-deployment-url/summary/example.com \
  -H "X-API-Key: YOUR_KEY"</pre>
      <pre class="code"><span class="k">const</span> res = <span class="k">await</span> fetch(<span class="s">"https://your-deployment-url/summary/example.com"</span>, {
  headers: { <span class="s">"X-API-Key"</span>: <span class="s">"YOUR_KEY"</span> }
});
<span class="k">const</span> data = <span class="k">await</span> res.json();</pre>

      <div class="callout">Rate limit: 60 requests per minute per API key. Exceeding this returns <code>429 Too Many Requests</code> with a <code>Retry-After</code> header.</div>
    </div>
  </div>

  <div class="section" id="dns">
    <div class="content-wrap">
      <h2>DNS</h2>
      <p>Resolve DNS records for a domain using system resolvers and public DNS servers. All endpoints require authentication.</p>

      <div class="endpoint">
        <div class="endpoint-title"><span class="badge badge-get">GET</span><span class="endpoint-path">/dns/{domain}</span></div>
        <div class="auth-note">Requires X-API-Key</div>
        <p class="endpoint-desc">Resolves DNS records of the specified type for a domain. Returns a list of matching records as strings.</p>
        <table class="param-table">
          <tr><th>Parameter</th><th>In</th><th>Type</th><th>Required</th><th>Description</th></tr>
          <tr><td class="param-name">domain</td><td>path</td><td class="param-type">string</td><td><span class="param-required">required</span></td><td>Domain name to look up</td></tr>
          <tr><td class="param-name">record_type</td><td>query</td><td class="param-type">string</td><td><span class="param-optional">optional</span></td><td>Record type: A, AAAA, MX, TXT, CNAME, NS, SOA. Defaults to A.</td></tr>
        </table>
        <pre class="code">curl "https://your-deployment-url/dns/example.com?record_type=MX" \
  -H "X-API-Key: YOUR_KEY"</pre>
      </div>

      <div class="endpoint">
        <div class="endpoint-title"><span class="badge badge-get">GET</span><span class="endpoint-path">/dns/{domain}/reverse</span></div>
        <div class="auth-note">Requires X-API-Key</div>
        <p class="endpoint-desc">Performs a PTR (reverse DNS) lookup, resolving a hostname back from an IP address or domain.</p>
        <table class="param-table">
          <tr><th>Parameter</th><th>In</th><th>Type</th><th>Required</th><th>Description</th></tr>
          <tr><td class="param-name">domain</td><td>path</td><td class="param-type">string</td><td><span class="param-required">required</span></td><td>Domain or IP to reverse-look up</td></tr>
        </table>
      </div>

      <div class="endpoint">
        <div class="endpoint-title"><span class="badge badge-get">GET</span><span class="endpoint-path">/dns/{domain}/propagation</span></div>
        <div class="auth-note">Requires X-API-Key</div>
        <p class="endpoint-desc">Queries Google (8.8.8.8), Cloudflare (1.1.1.1), and OpenDNS (208.67.222.222) in parallel and compares their A record responses. Useful for checking whether a recent DNS change has propagated globally.</p>
        <table class="param-table">
          <tr><th>Parameter</th><th>In</th><th>Type</th><th>Required</th><th>Description</th></tr>
          <tr><td class="param-name">domain</td><td>path</td><td class="param-type">string</td><td><span class="param-required">required</span></td><td>Domain to check propagation for</td></tr>
        </table>
      </div>

      <div class="endpoint">
        <div class="endpoint-title"><span class="badge badge-get">GET</span><span class="endpoint-path">/dns/{domain}/spf</span></div>
        <div class="auth-note">Requires X-API-Key</div>
        <p class="endpoint-desc">Scans TXT records and parses SPF, DKIM, and DMARC entries. Useful for auditing email authentication configuration.</p>
        <table class="param-table">
          <tr><th>Parameter</th><th>In</th><th>Type</th><th>Required</th><th>Description</th></tr>
          <tr><td class="param-name">domain</td><td>path</td><td class="param-type">string</td><td><span class="param-required">required</span></td><td>Domain to scan email auth records for</td></tr>
        </table>
      </div>

      <div class="endpoint">
        <div class="endpoint-title"><span class="badge badge-get">GET</span><span class="endpoint-path">/dns/{domain}/dnssec</span></div>
        <div class="auth-note">Requires X-API-Key</div>
        <p class="endpoint-desc">Checks whether DNSSEC is enabled and the AD (Authenticated Data) flag is set in the resolver response.</p>
        <table class="param-table">
          <tr><th>Parameter</th><th>In</th><th>Type</th><th>Required</th><th>Description</th></tr>
          <tr><td class="param-name">domain</td><td>path</td><td class="param-type">string</td><td><span class="param-required">required</span></td><td>Domain to check DNSSEC status for</td></tr>
        </table>
      </div>
    </div>
  </div>

  <div class="section" id="whois">
    <div class="content-wrap">
      <h2>WHOIS</h2>
      <p>Query domain registration data from the domain's registrar. Dates are returned as ISO 8601 strings. Results are cached for 1 hour.</p>

      <div class="endpoint">
        <div class="endpoint-title"><span class="badge badge-get">GET</span><span class="endpoint-path">/whois/{domain}</span></div>
        <div class="auth-note">Requires X-API-Key</div>
        <p class="endpoint-desc">Returns registration data including registrar name, creation date, expiration date, last updated date, name servers, status flags, contact emails, and registrant country.</p>
        <table class="param-table">
          <tr><th>Parameter</th><th>In</th><th>Type</th><th>Required</th><th>Description</th></tr>
          <tr><td class="param-name">domain</td><td>path</td><td class="param-type">string</td><td><span class="param-required">required</span></td><td>Domain to query WHOIS data for</td></tr>
        </table>
        <pre class="code">curl https://your-deployment-url/whois/example.com \
  -H "X-API-Key: YOUR_KEY"

<span class="c">// Response</span>
{
  <span class="s">"domain"</span>: <span class="s">"example.com"</span>,
  <span class="s">"registrar"</span>: <span class="s">"RESERVED-Internet Assigned Numbers Authority"</span>,
  <span class="s">"creation_date"</span>: <span class="s">"1995-08-14T04:00:00"</span>,
  <span class="s">"expiration_date"</span>: <span class="s">"2024-08-13T04:00:00"</span>,
  <span class="s">"name_servers"</span>: [<span class="s">"a.iana-servers.net"</span>, <span class="s">"b.iana-servers.net"</span>]
}</pre>
      </div>
    </div>
  </div>

  <div class="section" id="ssl">
    <div class="content-wrap">
      <h2>SSL / TLS</h2>
      <p>These endpoints open a real TLS connection to the domain on port 443. Results are cached for 1 hour.</p>

      <div class="endpoint">
        <div class="endpoint-title"><span class="badge badge-get">GET</span><span class="endpoint-path">/ssl/{domain}</span></div>
        <div class="auth-note">Requires X-API-Key</div>
        <p class="endpoint-desc">Returns certificate details: subject, issuer, validity window, subject alternative names, and serial number. Also includes <code>days_until_expiry</code> and <code>is_expiring_soon</code> (true if under 30 days).</p>
        <table class="param-table">
          <tr><th>Parameter</th><th>In</th><th>Type</th><th>Required</th><th>Description</th></tr>
          <tr><td class="param-name">domain</td><td>path</td><td class="param-type">string</td><td><span class="param-required">required</span></td><td>Domain to inspect the certificate for</td></tr>
        </table>
      </div>

      <div class="endpoint">
        <div class="endpoint-title"><span class="badge badge-get">GET</span><span class="endpoint-path">/ssl/{domain}/chain</span></div>
        <div class="auth-note">Requires X-API-Key</div>
        <p class="endpoint-desc">Returns the full certificate chain as an array of PEM-encoded certificates, from the leaf certificate to the root CA.</p>
        <table class="param-table">
          <tr><th>Parameter</th><th>In</th><th>Type</th><th>Required</th><th>Description</th></tr>
          <tr><td class="param-name">domain</td><td>path</td><td class="param-type">string</td><td><span class="param-required">required</span></td><td>Domain to retrieve the cert chain for</td></tr>
        </table>
      </div>

      <div class="endpoint">
        <div class="endpoint-title"><span class="badge badge-get">GET</span><span class="endpoint-path">/ssl/{domain}/tls</span></div>
        <div class="auth-note">Requires X-API-Key</div>
        <p class="endpoint-desc">Returns the negotiated TLS protocol version (e.g. TLSv1.3) and cipher suite from the handshake with the server.</p>
        <table class="param-table">
          <tr><th>Parameter</th><th>In</th><th>Type</th><th>Required</th><th>Description</th></tr>
          <tr><td class="param-name">domain</td><td>path</td><td class="param-type">string</td><td><span class="param-required">required</span></td><td>Domain to check TLS handshake details for</td></tr>
        </table>
      </div>
    </div>
  </div>

  <div class="section" id="ip">
    <div class="content-wrap">
      <h2>IP Intelligence</h2>
      <p>Geolocation and reputation data for IP addresses. Geolocation data comes from ip-api.com. Results are cached for 24 hours.</p>

      <div class="endpoint">
        <div class="endpoint-title"><span class="badge badge-get">GET</span><span class="endpoint-path">/ip/{ip}</span></div>
        <div class="auth-note">Requires X-API-Key</div>
        <p class="endpoint-desc">Returns geolocation and network data for an IP address: country, region, city, ISP, ASN, timezone, and boolean flags for proxy detection, hosting provider, and mobile carrier.</p>
        <table class="param-table">
          <tr><th>Parameter</th><th>In</th><th>Type</th><th>Required</th><th>Description</th></tr>
          <tr><td class="param-name">ip</td><td>path</td><td class="param-type">string</td><td><span class="param-required">required</span></td><td>IPv4 or IPv6 address to look up</td></tr>
        </table>
        <pre class="code">curl https://your-deployment-url/ip/8.8.8.8 \
  -H "X-API-Key: YOUR_KEY"

<span class="c">// Response</span>
{
  <span class="s">"ip"</span>: <span class="s">"8.8.8.8"</span>,
  <span class="s">"country"</span>: <span class="s">"United States"</span>,
  <span class="s">"city"</span>: <span class="s">"Ashburn"</span>,
  <span class="s">"isp"</span>: <span class="s">"Google LLC"</span>,
  <span class="s">"asn"</span>: <span class="s">"AS15169 Google LLC"</span>,
  <span class="s">"is_proxy"</span>: false,
  <span class="s">"is_hosting"</span>: true
}</pre>
      </div>

      <div class="endpoint">
        <div class="endpoint-title"><span class="badge badge-get">GET</span><span class="endpoint-path">/ip/{ip}/blacklist</span></div>
        <div class="auth-note">Requires X-API-Key</div>
        <p class="endpoint-desc">Checks the IP against Spamhaus and SORBS DNSBL blocklists. Returns a listed/unlisted result per list. Useful for diagnosing email delivery problems or flagging abusive IPs.</p>
        <table class="param-table">
          <tr><th>Parameter</th><th>In</th><th>Type</th><th>Required</th><th>Description</th></tr>
          <tr><td class="param-name">ip</td><td>path</td><td class="param-type">string</td><td><span class="param-required">required</span></td><td>IP address to check against blocklists</td></tr>
        </table>
      </div>

      <div class="endpoint">
        <div class="endpoint-title"><span class="badge badge-get">GET</span><span class="endpoint-path">/ip/{ip}/tor</span></div>
        <div class="auth-note">Requires X-API-Key</div>
        <p class="endpoint-desc">Checks whether the IP appears in the Tor Project's published exit node list. Returns <code>is_tor_exit: true</code> if the IP is a known Tor exit node.</p>
        <table class="param-table">
          <tr><th>Parameter</th><th>In</th><th>Type</th><th>Required</th><th>Description</th></tr>
          <tr><td class="param-name">ip</td><td>path</td><td class="param-type">string</td><td><span class="param-required">required</span></td><td>IP address to check against the Tor exit list</td></tr>
        </table>
      </div>
    </div>
  </div>

  <div class="section" id="http">
    <div class="content-wrap">
      <h2>HTTP Analysis</h2>
      <p>These endpoints make real HTTP requests to the domain and inspect the response. Results are cached for 5 minutes.</p>

      <div class="endpoint">
        <div class="endpoint-title"><span class="badge badge-get">GET</span><span class="endpoint-path">/http/headers/{domain}</span></div>
        <div class="auth-note">Requires X-API-Key</div>
        <p class="endpoint-desc">Fetches the domain over HTTPS and returns all response headers along with the HTTP status code.</p>
        <table class="param-table">
          <tr><th>Parameter</th><th>In</th><th>Type</th><th>Required</th><th>Description</th></tr>
          <tr><td class="param-name">domain</td><td>path</td><td class="param-type">string</td><td><span class="param-required">required</span></td><td>Domain to fetch headers from</td></tr>
        </table>
      </div>

      <div class="endpoint">
        <div class="endpoint-title"><span class="badge badge-get">GET</span><span class="endpoint-path">/http/redirects/{domain}</span></div>
        <div class="auth-note">Requires X-API-Key</div>
        <p class="endpoint-desc">Follows the complete redirect chain from the domain and returns each hop with its URL and status code, plus total hop count. Useful for auditing HTTP-to-HTTPS redirects and redirect chains.</p>
        <table class="param-table">
          <tr><th>Parameter</th><th>In</th><th>Type</th><th>Required</th><th>Description</th></tr>
          <tr><td class="param-name">domain</td><td>path</td><td class="param-type">string</td><td><span class="param-required">required</span></td><td>Domain to follow redirects from</td></tr>
        </table>
      </div>

      <div class="endpoint">
        <div class="endpoint-title"><span class="badge badge-get">GET</span><span class="endpoint-path">/http/security/{domain}</span></div>
        <div class="auth-note">Requires X-API-Key</div>
        <p class="endpoint-desc">Audits security-related response headers and reports each as present or missing, along with its value if present. Covers Content-Security-Policy, X-Frame-Options, Strict-Transport-Security, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy.</p>
        <table class="param-table">
          <tr><th>Parameter</th><th>In</th><th>Type</th><th>Required</th><th>Description</th></tr>
          <tr><td class="param-name">domain</td><td>path</td><td class="param-type">string</td><td><span class="param-required">required</span></td><td>Domain to audit security headers for</td></tr>
        </table>
      </div>

      <div class="endpoint">
        <div class="endpoint-title"><span class="badge badge-get">GET</span><span class="endpoint-path">/http/robots/{domain}</span></div>
        <div class="auth-note">Requires X-API-Key</div>
        <p class="endpoint-desc">Fetches and returns the raw contents of the domain's robots.txt file. Returns a 404 error if the file does not exist.</p>
        <table class="param-table">
          <tr><th>Parameter</th><th>In</th><th>Type</th><th>Required</th><th>Description</th></tr>
          <tr><td class="param-name">domain</td><td>path</td><td class="param-type">string</td><td><span class="param-required">required</span></td><td>Domain to retrieve robots.txt from</td></tr>
        </table>
      </div>

      <div class="endpoint">
        <div class="endpoint-title"><span class="badge badge-get">GET</span><span class="endpoint-path">/http/performance/{domain}</span></div>
        <div class="auth-note">Requires X-API-Key</div>
        <p class="endpoint-desc">Measures total response time and time-to-first-byte (TTFB) in milliseconds by timing a real HTTP request to the domain.</p>
        <table class="param-table">
          <tr><th>Parameter</th><th>In</th><th>Type</th><th>Required</th><th>Description</th></tr>
          <tr><td class="param-name">domain</td><td>path</td><td class="param-type">string</td><td><span class="param-required">required</span></td><td>Domain to measure response time for</td></tr>
        </table>
      </div>
    </div>
  </div>

  <div class="section" id="network">
    <div class="content-wrap">
      <h2>Network</h2>
      <p>Port scanning and network path analysis using real socket connections and system utilities.</p>

      <div class="endpoint">
        <div class="endpoint-title"><span class="badge badge-get">GET</span><span class="endpoint-path">/network/ports/{host}</span></div>
        <div class="auth-note">Requires X-API-Key</div>
        <p class="endpoint-desc">Scans the specified ports and returns open/closed status for each using async socket connections. Defaults to common ports if none are specified.</p>
        <table class="param-table">
          <tr><th>Parameter</th><th>In</th><th>Type</th><th>Required</th><th>Description</th></tr>
          <tr><td class="param-name">host</td><td>path</td><td class="param-type">string</td><td><span class="param-required">required</span></td><td>Hostname or IP to scan</td></tr>
          <tr><td class="param-name">ports</td><td>query</td><td class="param-type">string</td><td><span class="param-optional">optional</span></td><td>Comma-separated port numbers, e.g. 22,80,443</td></tr>
        </table>
      </div>

      <div class="endpoint">
        <div class="endpoint-title"><span class="badge badge-get">GET</span><span class="endpoint-path">/network/ping/{host}</span></div>
        <div class="auth-note">Requires X-API-Key</div>
        <p class="endpoint-desc">Sends ICMP ping requests to the host and returns latency in milliseconds and packet loss percentage.</p>
        <table class="param-table">
          <tr><th>Parameter</th><th>In</th><th>Type</th><th>Required</th><th>Description</th></tr>
          <tr><td class="param-name">host</td><td>path</td><td class="param-type">string</td><td><span class="param-required">required</span></td><td>Hostname or IP to ping</td></tr>
        </table>
      </div>

      <div class="endpoint">
        <div class="endpoint-title"><span class="badge badge-get">GET</span><span class="endpoint-path">/network/traceroute/{host}</span></div>
        <div class="auth-note">Requires X-API-Key</div>
        <p class="endpoint-desc">Returns the network path to the host as a list of hops with their IP addresses and latency at each hop.</p>
        <table class="param-table">
          <tr><th>Parameter</th><th>In</th><th>Type</th><th>Required</th><th>Description</th></tr>
          <tr><td class="param-name">host</td><td>path</td><td class="param-type">string</td><td><span class="param-required">required</span></td><td>Hostname or IP to trace the route to</td></tr>
        </table>
      </div>

      <div class="endpoint">
        <div class="endpoint-title"><span class="badge badge-get">GET</span><span class="endpoint-path">/network/whois/{ip}</span></div>
        <div class="auth-note">Requires X-API-Key</div>
        <p class="endpoint-desc">Returns BGP and ASN information for the IP address, including the autonomous system number, name, and network range.</p>
        <table class="param-table">
          <tr><th>Parameter</th><th>In</th><th>Type</th><th>Required</th><th>Description</th></tr>
          <tr><td class="param-name">ip</td><td>path</td><td class="param-type">string</td><td><span class="param-required">required</span></td><td>IP address to retrieve BGP/ASN data for</td></tr>
        </table>
      </div>
    </div>
  </div>

  <div class="section" id="summary">
    <div class="content-wrap">
      <h2>Summary</h2>
      <p>Run multiple lookups in a single request. The summary endpoint is the fastest way to get a broad picture of a domain.</p>

      <div class="endpoint">
        <div class="endpoint-title"><span class="badge badge-get">GET</span><span class="endpoint-path">/summary/{domain}</span></div>
        <div class="auth-note">Requires X-API-Key</div>
        <p class="endpoint-desc">Runs DNS (A record), WHOIS, HTTP headers, and IP geolocation in parallel using <code>asyncio.gather</code> and returns all results in a single response. The IP lookup is performed against the first A record returned by DNS.</p>
        <table class="param-table">
          <tr><th>Parameter</th><th>In</th><th>Type</th><th>Required</th><th>Description</th></tr>
          <tr><td class="param-name">domain</td><td>path</td><td class="param-type">string</td><td><span class="param-required">required</span></td><td>Domain to run the full summary for</td></tr>
        </table>
        <pre class="code">curl https://your-deployment-url/summary/github.com \
  -H "X-API-Key: YOUR_KEY"

<span class="c">// Response</span>
{
  <span class="s">"domain"</span>: <span class="s">"github.com"</span>,
  <span class="s">"dns"</span>: { <span class="s">"domain"</span>: <span class="s">"github.com"</span>, <span class="s">"record_type"</span>: <span class="s">"A"</span>, <span class="s">"records"</span>: [<span class="s">"140.82.121.4"</span>] },
  <span class="s">"whois"</span>: { <span class="s">"registrar"</span>: <span class="s">"MarkMonitor Inc."</span>, <span class="s">"creation_date"</span>: <span class="s">"2007-10-09T18:20:50"</span>, ... },
  <span class="s">"http"</span>: { <span class="s">"status_code"</span>: 200, <span class="s">"headers"</span>: { ... } },
  <span class="s">"ip"</span>: { <span class="s">"country"</span>: <span class="s">"United States"</span>, <span class="s">"isp"</span>: <span class="s">"GitHub, Inc."</span>, ... }
}</pre>
      </div>
    </div>
  </div>

  <div class="section" id="user">
    <div class="content-wrap">
      <h2>History and Stats</h2>
      <p>View your request history and usage statistics. Both endpoints are scoped to your API key.</p>

      <div class="endpoint">
        <div class="endpoint-title"><span class="badge badge-get">GET</span><span class="endpoint-path">/me/history</span></div>
        <div class="auth-note">Requires X-API-Key</div>
        <p class="endpoint-desc">Returns a paginated log of all API requests made with your key. Each entry includes the endpoint called, the input domain or IP, timestamp, and response time in milliseconds.</p>
        <table class="param-table">
          <tr><th>Parameter</th><th>In</th><th>Type</th><th>Required</th><th>Description</th></tr>
          <tr><td class="param-name">page</td><td>query</td><td class="param-type">integer</td><td><span class="param-optional">optional</span></td><td>Page number. Defaults to 1.</td></tr>
          <tr><td class="param-name">limit</td><td>query</td><td class="param-type">integer</td><td><span class="param-optional">optional</span></td><td>Results per page. Defaults to 20.</td></tr>
        </table>
      </div>

      <div class="endpoint">
        <div class="endpoint-title"><span class="badge badge-get">GET</span><span class="endpoint-path">/me/stats</span></div>
        <div class="auth-note">Requires X-API-Key</div>
        <p class="endpoint-desc">Returns aggregate usage statistics for your API key: total request count, most queried domains, request counts broken down by endpoint, and average response time across all requests.</p>
      </div>
    </div>
  </div>

  <div class="section" id="meta">
    <div class="content-wrap">
      <h2>Health and Meta</h2>

      <div class="endpoint">
        <div class="endpoint-title"><span class="badge badge-get">GET</span><span class="endpoint-path">/health</span></div>
        <div class="no-auth">No authentication required</div>
        <p class="endpoint-desc">Returns server uptime in seconds and the current API version. Use this to check if the service is running.</p>
        <pre class="code">curl https://your-deployment-url/health

{ <span class="s">"uptime_s"</span>: 3821.45, <span class="s">"version"</span>: <span class="s">"1.0.0"</span> }</pre>
      </div>

      <div class="endpoint">
        <div class="endpoint-title"><span class="badge badge-get">GET</span><span class="endpoint-path">/changelog</span></div>
        <div class="no-auth">No authentication required</div>
        <p class="endpoint-desc">Returns the current API version and release notes.</p>
      </div>

      <div class="endpoint">
        <div class="endpoint-title"><span class="badge badge-delete">DELETE</span><span class="endpoint-path">/cache</span></div>
        <div class="auth-note">Requires X-API-Key</div>
        <p class="endpoint-desc">Clears all cached responses from the SQLite cache table. Intended for development use when you need fresh results immediately without waiting for TTLs to expire.</p>
      </div>
    </div>
  </div>

  <div class="section" id="demo">
    <div class="content-wrap">
      <h2>Interactive Demo</h2>
      <p>Run a live <code>/summary</code> lookup directly from this page. Register for an API key using the <code>POST /register</code> endpoint above, then paste it below.</p>
      <div class="demo-inputs">
        <div>
          <label for="demo-domain">Domain</label>
          <input type="text" id="demo-domain" placeholder="example.com" autocomplete="off" spellcheck="false"/>
        </div>
        <div>
          <label for="demo-key">API Key</label>
          <input type="text" id="demo-key" placeholder="Paste your key here" autocomplete="off" spellcheck="false"/>
        </div>
      </div>
      <button id="run-btn">Run Summary</button>
      <pre id="demo-out"></pre>
    </div>
  </div>

  <div class="footer">
    netinspect v1.0.0 &nbsp;&middot;&nbsp;
    <a href="/openapi.json">OpenAPI JSON</a> &nbsp;&middot;&nbsp;
    <a href="/swagger">Swagger UI</a> &nbsp;&middot;&nbsp;
    <a href="/redoc">ReDoc</a>
  </div>
</div>

<script>
(function(){
  // theme
  const saved = localStorage.getItem('ni-theme');
  if(saved === 'dark') applyDark();

  function applyDark(){
    document.body.classList.add('dark');
    const btn = document.getElementById('theme-toggle');
    if(btn) btn.textContent = 'Light';
  }
  function applyLight(){
    document.body.classList.remove('dark');
    const btn = document.getElementById('theme-toggle');
    if(btn) btn.textContent = 'Dark';
  }

  window.toggleTheme = function(){
    const isDark = document.body.classList.contains('dark');
    if(isDark){ applyLight(); localStorage.setItem('ni-theme','light'); }
    else { applyDark(); localStorage.setItem('ni-theme','dark'); }
  };

  // sidebar active link on scroll
  const links = document.querySelectorAll('.nav-link[href^="#"]');
  const sections = [];
  links.forEach(l => {
    const id = l.getAttribute('href').slice(1);
    const el = document.getElementById(id);
    if(el) sections.push({el, link: l});
  });
  window.addEventListener('scroll', function(){
    const y = window.scrollY + 80;
    let current = sections[0];
    for(const s of sections){ if(s.el.offsetTop <= y) current = s; }
    links.forEach(l => l.classList.remove('active'));
    if(current) current.link.classList.add('active');
  }, {passive:true});

  // shared key state
  let currentKey = '';

  // register
  const regBtn = document.getElementById('reg-btn');
  if(regBtn){
    regBtn.addEventListener('click', async function(){
      const email = document.getElementById('reg-email').value.trim();
      if(!email){ alert('Enter an email address.'); return; }
      regBtn.disabled = true;
      regBtn.textContent = 'Registering...';
      try{
        const res = await fetch(window.location.origin + '/register', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({email})
        });
        const data = await res.json();
        if(data.api_key){
          currentKey = data.api_key;
          document.getElementById('key-value').textContent = currentKey;
          document.getElementById('key-display').classList.add('visible');
          // auto-fill demo key
          const demoKey = document.getElementById('demo-key');
          if(demoKey) demoKey.value = currentKey;
        } else {
          alert('Registration failed: ' + JSON.stringify(data));
        }
      } catch(e){
        alert('Error: ' + String(e));
      } finally {
        regBtn.disabled = false;
        regBtn.textContent = 'Register';
      }
    });
  }

  window.copyKey = function(){
    navigator.clipboard.writeText(currentKey).catch(() => {});
    const btn = document.getElementById('copy-key-btn');
    if(btn){ btn.textContent = 'Copied!'; setTimeout(()=>{ btn.textContent='Copy'; }, 1500); }
  };

  // demo
  const btn = document.getElementById('run-btn');
  const out = document.getElementById('demo-out');
  if(btn){
    btn.addEventListener('click', async function(){
      const domain = document.getElementById('demo-domain').value.trim();
      const key = document.getElementById('demo-key').value.trim() || currentKey;
      if(!domain){ out.textContent = 'Enter a domain name.'; out.classList.add('visible'); return; }
      btn.disabled = true;
      btn.textContent = 'Running...';
      out.classList.add('visible');
      out.textContent = 'Fetching...';
      try{
        const res = await fetch(window.location.origin + '/summary/' + encodeURIComponent(domain), {
          headers: key ? {'X-API-Key': key} : {}
        });
        const data = await res.json();
        out.textContent = JSON.stringify(data, null, 2);
      } catch(e){
        out.textContent = 'Error: ' + String(e);
      } finally {
        btn.disabled = false;
        btn.textContent = 'Run Summary';
      }
    });
  }
})();
</script>
</body>
</html>"""
    return HTMLResponse(html)


@app.get("/swagger", include_in_schema=False)
async def swagger_ui():
    html = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>netinspect -- Swagger UI</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.17.14/swagger-ui.min.css"/>
<style>
  body { margin: 0; background: #0f172a; }
  .topbar { display: none !important; }
  #swagger-ui { max-width: 1100px; margin: 0 auto; padding: 24px 24px 60px; }
  .swagger-ui { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }

  /* page bg + info */
  .swagger-ui .information-container { background: #1e293b; border-radius: 8px; padding: 24px 28px; margin-bottom: 24px; }
  .swagger-ui .info .title { color: #f1f5f9; font-size: 24px; font-weight: 700; }
  .swagger-ui .info .description p { color: #94a3b8; }
  .swagger-ui .info a { color: #818cf8; }

  /* scheme container (authorize bar) */
  .swagger-ui .scheme-container { background: #1e293b; border-radius: 8px; padding: 16px 20px; margin-bottom: 16px; box-shadow: none; border: 1px solid #334155; }
  .swagger-ui .schemes > label { color: #94a3b8; }

  /* authorize button */
  .swagger-ui .btn.authorize { background: transparent; border: 1px solid #818cf8; color: #818cf8; border-radius: 6px; font-weight: 600; }
  .swagger-ui .btn.authorize:hover { background: rgba(129,140,248,0.1); }
  .swagger-ui .btn.authorize svg { fill: #818cf8; }

  /* operation blocks */
  .swagger-ui .opblock { border-radius: 6px; border: none; margin-bottom: 6px; box-shadow: none; }
  .swagger-ui .opblock .opblock-summary { border-radius: 6px; padding: 10px 16px; }
  .swagger-ui .opblock-summary-description { color: #cbd5e1; font-size: 13px; }
  .swagger-ui .opblock-summary-path { color: #e2e8f0; font-weight: 600; font-size: 13px; }

  /* GET */
  .swagger-ui .opblock.opblock-get { background: rgba(16,185,129,0.08); border-left: 3px solid #10b981; }
  .swagger-ui .opblock.opblock-get .opblock-summary { background: rgba(16,185,129,0.08); }
  .swagger-ui .opblock.opblock-get .opblock-summary-method { background: #10b981; border-radius: 4px; }
  /* POST */
  .swagger-ui .opblock.opblock-post { background: rgba(99,102,241,0.08); border-left: 3px solid #6366f1; }
  .swagger-ui .opblock.opblock-post .opblock-summary { background: rgba(99,102,241,0.08); }
  .swagger-ui .opblock.opblock-post .opblock-summary-method { background: #6366f1; border-radius: 4px; }
  /* DELETE */
  .swagger-ui .opblock.opblock-delete { background: rgba(239,68,68,0.08); border-left: 3px solid #ef4444; }
  .swagger-ui .opblock.opblock-delete .opblock-summary { background: rgba(239,68,68,0.08); }
  .swagger-ui .opblock.opblock-delete .opblock-summary-method { background: #ef4444; border-radius: 4px; }

  /* expanded body */
  .swagger-ui .opblock .opblock-body { background: #1e293b; border-top: 1px solid #334155; }
  .swagger-ui .opblock-description-wrapper p,
  .swagger-ui .opblock-external-docs-wrapper p,
  .swagger-ui table thead tr td,
  .swagger-ui table thead tr th { color: #94a3b8; }
  .swagger-ui .parameter__name { color: #e2e8f0; }
  .swagger-ui .parameter__type { color: #818cf8; }
  .swagger-ui textarea, .swagger-ui input[type=text], .swagger-ui input[type=password] {
    background: #0f172a; border: 1px solid #334155; color: #e2e8f0; border-radius: 4px;
  }
  .swagger-ui select { background: #0f172a; border: 1px solid #334155; color: #e2e8f0; border-radius: 4px; }

  /* response / code blocks */
  .swagger-ui .highlight-code { background: #0f172a; border-radius: 6px; }
  .swagger-ui .microlight { color: #94a3b8; }
  .swagger-ui .response-col_status { color: #34d399; }

  /* section headers */
  .swagger-ui .opblock-tag { color: #f1f5f9; border-bottom: 1px solid #334155; font-size: 16px; font-weight: 600; }
  .swagger-ui .opblock-tag:hover { background: rgba(255,255,255,0.03); border-radius: 4px; }

  /* models */
  .swagger-ui section.models { background: #1e293b; border-radius: 8px; border: 1px solid #334155; }
  .swagger-ui section.models h4 { color: #f1f5f9; }
  .swagger-ui .model-title { color: #e2e8f0; }
  .swagger-ui .model { color: #94a3b8; }
  .swagger-ui .prop-type { color: #818cf8; }

  /* modal */
  .swagger-ui .dialog-ux .modal-ux { background: #1e293b; border: 1px solid #334155; border-radius: 8px; }
  .swagger-ui .dialog-ux .modal-ux-header { background: #0f172a; border-bottom: 1px solid #334155; border-radius: 8px 8px 0 0; }
  .swagger-ui .dialog-ux .modal-ux-header h3 { color: #f1f5f9; }
  .swagger-ui .dialog-ux .modal-ux-content p { color: #94a3b8; }
  .swagger-ui .dialog-ux .modal-ux-content label { color: #cbd5e1; }
  .swagger-ui .auth-container input[type=text], .swagger-ui .auth-container input[type=password] {
    background: #0f172a; border: 1px solid #334155; color: #e2e8f0;
  }
  .swagger-ui .auth-btn-wrapper .btn { border-radius: 5px; font-weight: 600; }
  .swagger-ui .btn.cancel { border-color: #475569; color: #94a3b8; }
  .swagger-ui .btn { border-radius: 5px; }

  /* execute button */
  .swagger-ui .btn.execute { background: #6366f1; border-color: #6366f1; border-radius: 5px; font-weight: 600; }
  .swagger-ui .btn.execute:hover { background: #4f46e5; border-color: #4f46e5; }

  /* try it out */
  .swagger-ui .try-out__btn { border-color: #818cf8; color: #818cf8; border-radius: 5px; }

  /* general text */
  .swagger-ui, .swagger-ui .opblock-tag small { color: #94a3b8; }
  .swagger-ui .servers > label span, .swagger-ui .servers-title { color: #94a3b8; }

  /* custom top bar */
  #custom-topbar {
    background: #0f172a;
    border-bottom: 1px solid #1e293b;
    padding: 12px 24px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    position: sticky;
    top: 0;
    z-index: 999;
  }
  #custom-topbar .logo { color: #f1f5f9; font-size: 15px; font-weight: 700; text-decoration: none; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
  #custom-topbar a.back { color: #818cf8; font-size: 13px; text-decoration: none; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
  #custom-topbar a.back:hover { text-decoration: underline; }
</style>
</head>
<body>
<div id="custom-topbar">
  <a href="/docs" class="logo">netinspect <span style="color:#475569;font-weight:400;font-size:12px">v1.0.0</span></a>
  <a href="/docs" class="back">&larr; Back to Docs</a>
</div>
<div id="swagger-ui"></div>
<script src="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.17.14/swagger-ui-bundle.min.js"></script>
<script>
SwaggerUIBundle({
  url: "/openapi.json",
  dom_id: "#swagger-ui",
  presets: [SwaggerUIBundle.presets.apis, SwaggerUIBundle.SwaggerUIStandalonePreset],
  layout: "BaseLayout",
  deepLinking: true,
  displayRequestDuration: true,
  tryItOutEnabled: false,
  persistAuthorization: true,
});
</script>
</body>
</html>"""
    return HTMLResponse(html)


def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    schema = get_openapi(title=app.title, version=app.version, routes=app.routes)
    schema["components"]["securitySchemes"] = {
        "APIKeyHeader": {"type": "apiKey", "in": "header", "name": "X-API-Key"}
    }
    schema["security"] = [{"APIKeyHeader": []}]
    app.openapi_schema = schema
    return schema


app.openapi = custom_openapi


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)