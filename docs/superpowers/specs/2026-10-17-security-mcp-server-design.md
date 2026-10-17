# Security MCP Server — Design Spec

**Date:** 2026-10-17
**Status:** Approved
**Goal:** A read-only, agent-independent MCP server exposing three investigation tools (`check_ip`, `check_url`, `lookup_cve`) that any MCP-compatible client (OpenCode, Claude, GPT, …) can use via stdio.

## Interview Decisions (locked)

| # | Decision |
|---|----------|
| 1–3 | Multi-provider fan-out; every keyed provider optional; missing key → provider skipped and reported |
| 4 | In-memory TTL cache, 900s default (`CACHE_TTL` env), max 1000 entries |
| 5 | Per-provider token-bucket rate limiter |
| 6 | API keys from environment variables only; optional `.env` via python-dotenv; never logged |
| 7 | Missing key → skip + reason in `skipped` list |
| 8–9 | Local stdio process; OpenCode `"type": "local"` |
| 10 | Python ≥3.11 + FastMCP |
| 11–12 | Normalized record schema with rolled-up verdict + nested per-provider blocks and a `summary` |
| 13 | Strictly read-only: GET lookups only, no scan submission, no mutating verbs anywhere |
| 14 | `MOCK=1` returns canned provider payloads for keyless testing |

## Architecture

One FastMCP process. Each tool validates its input, consults the TTL cache, then fans out concurrently (`asyncio.gather`, `return_exceptions=True`) over the selected, available providers. Each provider result is normalized to a common record; a roll-up computes the worst-case consensus verdict/severity. Providers whose API key is absent (keyed ones only) are listed in `skipped`.

```
agent ──stdio──► server.py (FastMCP)
                   ├── core/{schemas,cache,ratelimit,http,verdict}.py
                   └── providers/  (base + registry + one module per API)
                        └── HTTPS GET only ──► AbuseIPDB, VirusTotal,
                            GreyNoise, Shodan, ip-api, urlscan, NVD, MITRE, OSV
```

## Tools

| Tool | Input | Validation |
|------|-------|------------|
| `check_ip` | `ip: str`, `providers: list[str] \| None` | `ipaddress.ip_address` |
| `check_url` | `url: str`, `providers: list[str] \| None` | http/https + netloc; reject localhost, `.local`, `.internal`, private/loopback/link-local literal IPs (SSRF guard) |
| `lookup_cve` | `cve_id: str`, `providers: list[str] \| None` | `^CVE-\d{4}-\d{4,}$` case-insensitive, uppercased |

### Output schema (all tools)

```json
{
  "input": "8.8.8.8",
  "type": "ip",
  "verdict": "benign",
  "severity": "low",
  "summary": "Consensus: benign across 4/4 responding providers.",
  "queried": ["abuseipdb", "virustotal", "greynoise", "ipapi"],
  "skipped": [{"provider": "shodan", "reason": "SHODAN_API_KEY not set"}],
  "results": [
    {
      "source": "abuseipdb",
      "ok": true,
      "verdict": "benign",
      "severity": "low",
      "summary": "Abuse confidence 0%, 0 reports/90d",
      "data": {},
      "error": null,
      "retrieved_at": "2026-10-17T12:00:00Z"
    }
  ],
  "retrieved_at": "2026-10-17T12:00:00Z"
}
```

Vocabularies: verdicts `benign|suspicious|malicious|unknown|error`; severities `none|low|medium|high|critical|unknown`.

## Providers

| Provider | Tool | Endpoint | Auth | Keyless |
|----------|------|----------|------|---------|
| ipapi | ip | `http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,isp,org,as,query` | no | yes |
| abuseipdb | ip | `https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90` | `Key` header | no |
| virustotal | ip/url | `GET /api/v3/ip_addresses/{ip}`; `GET /api/v3/urls/{base64url_nopad}` | `x-apikey` | no |
| greynoise | ip | `https://api.greynoise.io/v3/community/{ip}` | `key` header | no |
| shodan | ip | `https://api.shodan.io/shodan/host/{ip}?key={key}` | query | no |
| urlscan | url | `https://urlscan.io/api/v1/search/?q=page.url:"{url}"` | `api-key` header optional | search yes |
| nvd | cve | `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={id}` | `apiKey` optional | yes |
| mitre_cve | cve | `https://cveawg.mitre.org/api/cve/{id}` | no | yes |
| osv | cve | `https://api.osv.dev/v1/vulns/{id}` | no | yes |

**Dropped:** Google Safe Browsing — `threatMatches:find` is POST-only, incompatible with the read-only constraint.

### Normalization rules

- **abuseipdb:** confidence 0→benign/low, 1–74→suspicious (medium if ≥25 else low), ≥75→malicious/high; data: `abuseConfidenceScore, countryCode, isp, usageType, totalReports`.
- **virustotal IP/URL:** `last_analysis_stats.malicious>0`→malicious/high; `suspicious>0`→suspicious/medium; else benign/none; data trimmed (`reputation, mal, sus, country, as_owner` / `last_final_url, times_submitted, mal, sus`).
- **greynoise:** `malicious`→malicious/high; `noise`→suspicious/medium; `riot`→benign/low; else unknown/unknown; data: `noise, riot, classification, name, link`.
- **shodan:** always `unknown` verdict; severity none if no vulns, medium if vulns reported; data: `org, port, hostnames, vulns_count`.
- **ipapi:** benign/none; data: `country, regionName, city, isp, org, as`.
- **urlscan:** any hit with `verdicts.overall.malicious==true`→malicious/high; hits but not malicious→unknown/none; no hits→benign/none; data: `total, last_task_time, top_score, domains (≤5)`.
- **nvd / mitre_cve:** use CVSS v3.1 else v2; ≥9 critical, ≥7 high, ≥4 medium, >0 low, 0/absent none; verdict malicious if score≥7, suspicious if >0, else benign; data per plan (descriptions ≤500 chars, references ≤5).
- **osv:** CVSS from `severity[].score` if present else database_specific; unknown if absent; data: `summary(≤300), aliases, published, modified`.

### Roll-up

Worst verdict: malicious > suspicious > benign > unknown (empty → unknown with summary "No providers responded."). Worst severity: critical > high > medium > low > none > unknown. Summary: `Consensus: {verdict} across {ok}/{total} responding providers.`

## Core modules

- `core/schemas.py` — vocab tuples, `ProviderResult` dataclass, validators.
- `core/cache.py` — `TTLCache(ttl, maxsize)`, tuple keys including provider filter.
- `core/ratelimit.py` — `RateLimiter(rate, capacity=None)`, async `acquire()`, injectable clock.
- `core/http.py` — shared `httpx.AsyncClient`, 10s timeout, no redirects.
- `core/verdict.py` — `roll_up(results) -> (verdict, severity, summary)`.
- `providers/base.py` — `Provider` ABC (`name`, `tool`, `available()`, `fetch()`, `normalize()`, `mock_raw()`, final `run()`); `providers/__init__.py` — `PROVIDERS` registry, `for_tool(tool, only) -> (selected, skipped)`.
- `server.py` — `investigate(tool, value, providers)` orchestrator + FastMCP tools; `mock.py` — env loading (`MOCK`, `CACHE_TTL`, keys).

Rate limits (tokens/sec, self-imposed): abuseipdb 0.5, virustotal 0.15, greynoise 1, shodan 1, ipapi 0.66, urlscan 1, nvd 0.8, mitre 1, osv 1.

## Security constraints

- Only `httpx.get`; no mutating HTTP verbs anywhere in the tree.
- Input validation as specified; URL SSRF guard; CVE uppercasing.
- Keys from env only, never logged; errors name env vars, not values.
- One provider failure never fails the call (`ok:false` + `error`); HTTP 429 → one retry after bucket refill, then `rate_limited` error record.
- 10s per-provider timeout; `data` trimmed per rules above.

## OpenCode integration

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "security": {
      "type": "local",
      "command": ["python", "server.py"],
      "cwd": "security-mcp-server-read-only",
      "enabled": true,
      "environment": {
        "ABUSEIPDB_API_KEY": "{env:ABUSEIPDB_API_KEY}",
        "VT_API_KEY": "{env:VT_API_KEY}",
        "GREYNOISE_API_KEY": "{env:GREYNOISE_API_KEY}",
        "SHODAN_API_KEY": "{env:SHODAN_API_KEY}",
        "URLSCAN_API_KEY": "{env:URLSCAN_API_KEY}",
        "NVD_API_KEY": "{env:NVD_API_KEY}"
      }
    }
  }
}
```

## Testing

1. Unit tests per core module and per provider `normalize()` (canned raw payloads).
2. `MOCK=1` orchestration tests + `tests/smoke.py` MCP-client stdio smoke (tools/list = 3, each tool returns schema).
3. Live keyless check: `lookup_cve("CVE-2021-44228")` against NVD/MITRE/OSV.
4. Negative validation: bad IP, non-http scheme, private/localhost URLs, malformed CVE.
5. `npx @modelcontextprotocol/inspector python server.py` for manual inspection.
