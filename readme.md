# netinspect
Quick and modular network intelligence / domain analysis using a REST API built with FastAPI, outputting deep inspections on DNS, WHOIS, SSL/TLS, HTTP, IP, and networking information in a unified API engine.

## Things it does

**Modular Endpoint Routers:** Splits data into dedicated areas for DNS, WHOIS, SSL, IP, HTTP, and network analysis.

**Parallel Summaries:** Aggressive `GET /summary/{domain}` endpoint using `asyncio.gather` to pull DNS, WHOIS, HTTP headers, and IP geolocation profiles.

**Turnkey Key Authentication:** Persistent API key issuing via SQLite database storage with zero command-line configuration required.

**Rate Limiting:** Protection powered by slowapi to enforce clean usage limits (max 60 requests per minute per key).

## Stack

**Framework:** FastAPI (Python 3.10+)

**Async Engine:** Uvicorn + Asyncio

**Database and Cache:** SQLite3

**Core Inspection Engines:** dnspython, python-whois, ssl, socket, requests

## API Documentation Overview

### Authentication Flow

All requests (except `/register`, `/health`, and `/docs`) require a valid API token sent via the custom header.

**Register a Key:** Submit a POST request to `/register` with your email, or use the interface at `/docs`.

**Submit Requests:** Pass your token inside the `X-API-Key` request header.

```bash
curl -X GET "http://localhost:8000/summary/example.com" \
     -H "X-API-Key: your_generated_api_key_here"
```

## Core API Endpoints

### 1. DNS Resolution (`/dns`)

These endpoints resolve live records using parallelized lookups and native system sockets.

`GET /dns/{domain}?record_type=A`
Resolves specific DNS records for a target domain. Supported types include A, AAAA, MX, TXT, CNAME, NS, and SOA.

`GET /dns/{domain}/reverse`
Performs a PTR lookup to resolve a hostname backward from an IP address string.

`GET /dns/{domain}/propagation`
Queries Google, Cloudflare, and OpenDNS name systems in parallel to check if a new configuration has populated globally.

`GET /dns/{domain}/spf`
Scans TXT patterns to extract and validate SPF, DKIM, and DMARC records for email security auditing.

`GET /dns/{domain}/dnssec`
Verifies if DNS Security Extensions are active and checks for the Authenticated Data flag.

### 2. WHOIS Information (`/whois`)

`GET /whois/{domain}`
Extracts registration metrics including registrar metadata, name servers, status flags, and ownership contact emails. All timestamps are normalized to ISO 8601 format.

### 3. SSL/TLS Handshakes (`/ssl`)

`GET /ssl/{domain}`
Examines port 443 certificate parameters including subject, issuer, serial key identifiers, validity windows, and days until expiration.

`GET /ssl/{domain}/chain`
Fetches the full certificate authority chain as an array of structured PEM-encoded strings.

`GET /ssl/{domain}/tls`
Identifies the negotiated TLS protocol version along with the active cryptographic cipher suite.

### 4. IP Intelligence (`/ip`)

`GET /ip/{ip}`
Tracks geolocation data from trusted public registries. Returns country, region, city, ISP, autonomous system number, and flags detecting proxies, hosting providers, or mobile exit nodes.

`GET /ip/{ip}/blacklist`
Cross-references targets against active anti-spam databases like Spamhaus and SORBS DNSBL registries.

`GET /ip/{ip}/tor`
Verifies whether the IP address is found on the official list of active Tor exit relays.

### 5. HTTP Metrics (`/http`)

`GET /http/headers/{domain}`
Sends a request to the domain to capture raw HTTP response headers along with the server status code.

`GET /http/redirects/{domain}`
Traces redirection paths step by step, logging every hop URL and status code along the chain.

`GET /http/security/{domain}`
Checks for security headers like Content-Security-Policy, X-Frame-Options, Strict-Transport-Security, and Referrer-Policy.

`GET /http/robots/{domain}`
Downloads and exposes the raw contents of the domain's `robots.txt` file.

`GET /http/performance/{domain}`
Gathers speed diagnostics including connection response delays and time-to-first-byte (TTFB) in milliseconds.

### 6. Structural Routing and Meta (`/network` and `/meta`)

`GET /network/ports/{host}?ports=22,80,443`
Runs async port sweeps across targeted addresses to detect open or closed listener sockets.

`GET /network/ping/{host}`
Measures connection speeds by tracking ICMP packet latency and drop ratios.

`GET /network/traceroute/{host}`
Returns sequential hop pathways and node timings between the host and the server.

`GET /health`
Exposes API operational status alongside server uptime parsed to two decimal places.

`DELETE /cache`
Clears the local cache table within SQLite to force fresh data fetches during development.

## Example Response Profile

Calling the unified showcase endpoint (`GET /summary/{domain}`) builds a comprehensive snapshot:

```json
{
  "domain": "example.com",
  "dns": {
    "status": "success",
    "records": ["93.184.215.14"]
  },
  "whois": {
    "registrar": "RESERVED-Internet Assigned Numbers Authority",
    "creation_date": "1992-08-14T04:00:00Z",
    "expiration_date": "2026-08-13T04:00:00Z"
  },
  "http": {
    "status_code": 200,
    "server": "ECAcc (nyx/6C83)"
  },
  "ip_geolocation": {
    "ip": "93.184.215.14",
    "country": "United States",
    "isp": "EdgeCast Networks, Inc."
  }
}
```

## Getting Started Locally

### Prerequisites

Ensure Python 3.10 or newer is configured on your system.

### Installation

Clone your project workspace:

```bash
git clone https://github.com/yourusername/netinspect.git
cd netinspect
```

Install dependencies:

```bash
pip install fastapi uvicorn dnspython python-whois slowapi requests
```

Launch your development server:

```bash
python main.py
```

Or with standard Uvicorn commands:

```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

Open your browser and navigate to `http://localhost:8000/docs` to test endpoints via the custom dashboard.