# Security MCP Server (read-only)

A read-only security investigation MCP server exposing exactly three tools (`check_ip`, `check_url`, `lookup_cve`) to any MCP-compatible agent over stdio.

## Read-only guarantee

All three tools are strict lookups: every outbound call is an HTTP **GET**. There is no scan submission, no task/queue creation, and no write or mutating API call anywhere in the tree — the source contains zero mutating-verb call sites (no `httpx` POST/PUT/PATCH/DELETE, no `requests` dependency at all; `httpx` only). Google Safe Browsing was explicitly dropped from the provider set because its `threatMatches:find` endpoint is POST-only.

## Tools

| Tool | Description |
|------|-------------|
| `check_ip(ip, providers=None)` | IP reputation, abuse reports, and geolocation |
| `check_url(url, providers=None)` | URL/reputation lookup (SSRF-guarded: rejects localhost, `.local`, `.internal`, private/loopback/link-local IPs) |
| `lookup_cve(cve_id, providers=None)` | CVE severity/description lookup (normalized to upper-case `CVE-YYYY-NNNN+`) |

`providers` is an optional allow-list of provider names; omit it to query every available provider for that tool.

All tools return the same normalized shape:

```json
{
  "input": "8.8.8.8",
  "type": "ip",
  "verdict": "benign",
  "severity": "low",
  "summary": "Consensus: benign across 4/4 responding providers.",
  "queried": ["abuseipdb", "virustotal_ip", "greynoise", "ipapi"],
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

Vocabularies: `verdict` ∈ `benign|suspicious|malicious|unknown|error`; `severity` ∈ `none|low|medium|high|critical|unknown`.

## Providers

| Provider | Tool | Keyless? | Env var |
|----------|------|----------|---------|
| `ipapi` | `check_ip` | yes | — |
| `abuseipdb` | `check_ip` | no | `ABUSEIPDB_API_KEY` |
| `virustotal_ip` | `check_ip` | no | `VT_API_KEY` |
| `greynoise` | `check_ip` | no | `GREYNOISE_API_KEY` |
| `shodan` | `check_ip` | no | `SHODAN_API_KEY` |
| `urlscan` | `check_url` | yes (key optional) | `URLSCAN_API_KEY` (optional) |
| `virustotal_url` | `check_url` | no | `VT_API_KEY` |
| `nvd` | `lookup_cve` | yes (key optional) | `NVD_API_KEY` (optional) |
| `mitre_cve` | `lookup_cve` | yes | — |
| `osv` | `lookup_cve` | yes | — |

Every keyed provider is optional: if its API key is unset, the provider is not queried and appears in the response's `skipped` list with the reason (`<ENV_VAR> not set`). `urlscan` and `nvd` are queried keyless even when their optional key is absent, so they never appear in `skipped`.

## Setup

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
cp .env.example .env   # optional: fill in only the keys you have
```

API keys are read from the environment only (`.env` is loaded via python-dotenv if present) and are never logged.

For keyless, offline testing use mock mode — no network, no keys:

```bash
MOCK=1 .venv/bin/python server.py
```

## Add to OpenCode

Add this to your `opencode.json` / `opencode.jsonc` (a copy lives in `opencode.snippet.json`):

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "security": {
      "type": "local",
      "command": [".venv/bin/python", "server.py"],
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

Notes:

- `command` runs the **venv interpreter** (`.venv/bin/python`) with `server.py`, so the venv must already have `requirements.txt` installed. `cwd` is the server directory relative to where OpenCode is started.
- The `{env:...}` placeholders are OpenCode's env-var expansion — unset keys expand to empty and those providers are simply skipped.
- Optional inline-args alternative (no venv, deps resolved on the fly by `uv` or `pipx`):

  ```json
  "command": ["uv", "run", "--with", "fastmcp>=2.0", "--with", "httpx>=0.27", "--with", "python-dotenv>=1.0", "server.py"]
  ```

  (`pipx run --with fastmcp,httpx,python-dotenv server.py` works the same way.)

- The server is **agent-independent**: it speaks standard MCP over stdio, so Claude, GPT, OpenCode, or any other MCP client can connect — nothing here is OpenCode-specific beyond the config block above.

## Verify locally

```bash
MOCK=1 .venv/bin/python tests/smoke.py                 # stdio client: 3 tools + schema checks
npx @modelcontextprotocol/inspector .venv/bin/python server.py   # interactive inspector
.venv/bin/pytest -q                                    # unit tests (network tests deselected)
.venv/bin/pytest -q -m network -o addopts=""           # live keyless CVE lookup (needs internet)
```

## Agent usage examples

Once connected, just ask in chat:

- "Check 8.8.8.8 with the security tools."
- "Is https://example.com safe?"
- "Look up CVE-2021-44228."
- "Check 1.1.1.1 with only greynoise and shodan."
