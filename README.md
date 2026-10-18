# Security MCP Server (read-only)

A read-only, passive security investigation MCP server exposing exactly five tools to any MCP-compatible agent over stdio. Fast, reproducible lookups across IP, URL, domain, CVE, and file hashes with transparent results from multiple providers.

> Passive by design. No active scanning. No mutating API calls. No data submission.

[![Read-only](https://img.shields.io/badge/read--only-yes-green.svg)](https://github.com/shahjahanctg/security-mcp-server-read-only)
[![Tools](https://img.shields.io/badge/tools-5-blue.svg)](#tools)
[![Providers](https://img.shields.io/badge/providers-23-orange.svg)](#provider-matrix)
[![Python](https://img.shields.io/badge/python-3.11%2B-yellow.svg)](https://www.python.org/)

## What you get

- **IP reputation & abuse history**: Cross-check multiple sources for abuse confidence, reports, and known malicious activity.
- **Geolocation & ASN**: Get location, organization, ISP, and ASN context for IPs.
- **Passive open ports & service fingerprints**: Leverage Shodan InternetDB for historical/passive service exposure data (no active scanning).
- **Domain intelligence**: RDAP registration details, DNS records, subdomain discovery via Certificate Transparency (crt.sh), and passive DNS/OSINT signals.
- **Reverse DNS**: Resolve PTR records for IP addresses.
- **URL reputation**: Check URLs against multiple reputation providers (SSRF-guarded to prevent local/private targets).
- **CVE intelligence**: Get CVE descriptions, severity, exploit probability (EPSS), and CISA Known Exploited Vulnerabilities (KEV) status.
- **File hash reputation**: Look up MD5/SHA1/SHA256 hashes against reputation providers.
- **Transparent consensus**: Every response includes `verdict`, `severity`, `queried`, `skipped`, and per-provider results with retrieval timestamps.

## Read-only guarantee

All five tools perform strict lookups. Every outbound call is an **HTTP GET only** — there are **zero POST, PUT, PATCH, DELETE**, or any other mutating API calls anywhere in the codebase.
- No `requests` dependency; only `httpx` is used for HTTP calls.
- No scan submission, no task/queue creation, no writes.
- **Passive only — no active scanning, no OS fingerprinting.**
- SSRF protection: URL lookups reject localhost, `.local`, `.internal`, and private/loopback/link-local IP targets.
- API keys are read from environment only and are never logged.

## Tools

| Tool | Description |
|------|-------------|
| `check_ip(ip, providers=None)` | IP reputation, abuse reports, geolocation, ASN, passive service data, and reverse DNS across IP-focused providers. |
| `check_url(url, providers=None)` | URL reputation lookups (SSRF-guarded). Rejects localhost, `.local`, `.internal`, private/loopback/link-local IPs. |
| `lookup_cve(cve_id, providers=None)` | CVE severity, description, EPSS exploit probability, and CISA KEV status. Normalizes to `CVE-YYYY-NNNN+`. |
| `check_domain(domain, providers=None)` | Domain intelligence: RDAP registration, DNS records, subdomains via crt.sh CT logs, and OTX passive signals. |
| `check_hash(file_hash, providers=None)` | File hash reputation lookup (MD5, SHA1, or SHA256). |

`providers` is an optional allow-list of provider names; omit it to query every available provider for that tool.

## Normalized response

All tools return the same normalized shape for consistency:

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

**Vocabularies:** `verdict` ∈ `benign|suspicious|malicious|unknown|error`; `severity` ∈ `none|low|medium|high|critical|unknown`.

**How it decides:** Provider verdicts/severities are rolled up by consensus logic (see `core/verdict.py`) to produce a single overall verdict, severity, and summary. Individual provider behavior is defined in each provider module.

## Provider matrix

| Provider | Tool | Keyless? | Env var |
|----------|------|----------|---------|
| `ipapi` | `check_ip` | yes | — |
| `abuseipdb` | `check_ip` | no | `ABUSEIPDB_API_KEY` |
| `virustotal_ip` | `check_ip` | no | `VT_API_KEY` |
| `greynoise` | `check_ip` | no | `GREYNOISE_API_KEY` |
| `shodan` | `check_ip` | no | `SHODAN_API_KEY` |
| `ipinfo` | `check_ip` | yes | `IPINFO_TOKEN` (optional) |
| `internetdb` | `check_ip` | yes | — |
| `reverse_dns` | `check_ip` | yes | — |
| `otx_ip` | `check_ip` | yes | — |
| `urlscan` | `check_url` | yes (key optional) | `URLSCAN_API_KEY` (optional) |
| `virustotal_url` | `check_url` | no | `VT_API_KEY` |
| `nvd` | `lookup_cve` | yes (key optional) | `NVD_API_KEY` (optional) |
| `mitre_cve` | `lookup_cve` | yes | — |
| `osv` | `lookup_cve` | yes | — |
| `epss` | `lookup_cve` | yes | — |
| `cisa_kev` | `lookup_cve` | yes | — |
| `circl` | `lookup_cve` | yes | — |
| `rdap` | `check_domain` | yes | — |
| `dns` | `check_domain` | yes | — |
| `crtsh` | `check_domain` | yes | — |
| `otx_domain` | `check_domain` | yes | — |
| `virustotal_file` | `check_hash` | no | `VT_API_KEY` |
| `otx_file` | `check_hash` | yes | — |

Every keyed provider is optional: if its API key is unset, the provider is not queried and appears in the response's `skipped` list with reason `<ENV_VAR> not set`. Providers that accept optional keys (`urlscan`, `nvd`, `ipinfo`) are queried keyless when their key is absent, so they typically do not appear in `skipped`. Mock mode (`MOCK=1`) returns canned data and works with zero keys.

## Quickstart

### 1. Setup
```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
cp .env.example .env   # optional: fill in only the keys you have
```

### 2. Run in mock mode (offline, no keys)
```bash
MOCK=1 .venv/bin/python server.py
```

### 3. Run normally
```bash
.venv/bin/python server.py
```

API keys are read from the environment only (`.env` is loaded via python-dotenv if present) and are never logged.

## Add to your agent (MCP)

### OpenCode
Add to `opencode.json` (a copy is in `opencode.snippet.json`):

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
        "NVD_API_KEY": "{env:NVD_API_KEY}",
        "IPINFO_TOKEN": "{env:IPINFO_TOKEN}"
      }
    }
  }
}
```

Notes:
- `command` runs the **venv interpreter** (`.venv/bin/python`) with `server.py`; ensure the `.venv` has dependencies installed.
- Unset keys expand to empty via `{env:...}` and those providers are skipped. `IPINFO_TOKEN`, `URLSCAN_API_KEY`, and `NVD_API_KEY` are **optional**.
- **Alternative (inline deps):** `uv` or `pipx` can resolve deps on-the-fly:
  ```json
  "command": ["uv", "run", "--with", "fastmcp>=2.0", "--with", "httpx>=0.27", "--with", "python-dotenv>=1.0", "server.py"]
  ```
  (`pipx run --with fastmcp,httpx,python-dotenv server.py` also works.)
- **Agent-independent:** Speaks standard MCP over stdio — works with Claude, GPT, OpenCode, or any MCP client.

### Other agents
For Claude Desktop, Cline, Continue, RooCode, etc., configure this MCP server as a local stdio command pointing to `.venv/bin/python` and `server.py` in this repo.

## Connect any MCP client (HTTP)

Clients that cannot spawn a stdio command (or when you want one shared server for many clients) can connect over streamable HTTP with a bearer API key. stdio remains the default and is unchanged — HTTP mode is opt-in.

### 1. Start the server in HTTP mode

```bash
MCP_TRANSPORT=http .venv/bin/python server.py
```

The startup banner prints everything you need:

```
security MCP — streamable-http
  url:    http://127.0.0.1:8765/mcp
  key:    <generated access key>
  state:  ./.mcp_state.json
  config: python server.py config --client opencode|claude|cursor|cline|mcp-remote
```

- `url` is the endpoint clients call; `key` is the access key clients send as `Authorization: Bearer <key>`.
- The server also writes `./.mcp_state.json` (mode `0600`, gitignored) so the `config` command can read the current URL and key. It is deleted on clean shutdown and never used for authentication.

### 2. Generate client config

While the server is running, in a second terminal:

```bash
.venv/bin/python server.py config --client <name>   # one client
.venv/bin/python server.py config --all                 # all five at once
```

| Client | Config goes into |
|--------|------------------|
| `opencode` | `opencode.json` (`mcp.security`) |
| `claude` | `claude_desktop_config.json` or `.mcp.json` (`mcpServers`) |
| `cursor` | Cursor MCP settings (`mcpServers`) |
| `cline` | Cline MCP settings (`mcpServers`; same block for RooCode/Continue) |
| `mcp-remote` | A command for any stdio-only client: `npx -y mcp-remote "<url>" --header "Authorization: Bearer <key>"` |

If `config` reports the server is not running in HTTP mode, start it as in step 1 first.

### 3. Notes

- **Key lifecycle:** A fresh random key is generated on every HTTP start. Set `MCP_API_KEY=<value>` before starting to pin a stable key across restarts (recommended so client configs keep working).
- **LAN exposure:** Default bind is `127.0.0.1` (this machine only). To serve other machines on a trusted LAN/VPN, start with `MCP_HOST=0.0.0.0` — only do this behind a firewall you control; the server has no TLS and uses a single shared bearer key.
- **Provider keys are separate:** The MCP access key above is only for connecting clients. Provider API keys (`ABUSEIPDB_API_KEY`, `VT_API_KEY`, etc.) are still read from the server's own environment and are never sent to clients.
- **stdio unchanged:** Running `.venv/bin/python server.py` with no `MCP_TRANSPORT` behaves exactly as before, with no HTTP listener and no state file.

## Agent prompts / copy-paste examples

Every prompt below maps directly to one tool: `check_ip`, `check_domain`,
`lookup_cve`, `check_hash`, or `check_url`. Paste them as-is, or adapt the
values.

### Phishing / email triage

- `"Check the sender IP 45.124.15.34 from this phishing report"`
- `"Is https://accounts-example-login.com/verify a phishing site?"`
- `"I got a link to https://bit.ly/3x9Kq2m in an email — check its reputation"`
- `"Recon login-example-support.com — is this a typosquat of our domain?"`

### Vulnerability management

- `"Look up CVE-2021-44228 and tell me how serious it is"`
- `"Should we prioritize CVE-2024-3400 this week?"` (uses EPSS + KEV data)
- `"Check CVE-2023-4863 across all sources"`
- `"Any of these CVEs worth escalating: CVE-2021-44228, CVE-2024-3400?"`

### Malware / file-hash triage

- `"Check this sha256: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"`
- `"Is hash d41d8cd98f00b204e9800998ecf8427e known-bad?"` (md5 works too)
- `"A user uploaded this file — md5 44d88612fea8a8f36de82e1278abb02f, check it"`

### Domain / brand monitoring

- `"Recon example.com"` (full domain investigation)
- `"Check if example-secure.co is registered and how old it is"`
- `"Do a brand check on login-example.com and tell me the verdict"`

### URL / download safety

- `"Is https://example.com/some/path safe to open?"`
- `"Check this URL before I click: http://192.168.1.50:8080/update.exe"`
- `"Would you open this download link: https://example.org/getfile?id=92"`

### SOC / log review (batch — agent loops)

- `"Which of these IPs are known-bad: 45.124.15.34, 185.220.101.5, 91.219.236.19?"`
- `"Check every domain in this suspicious click list: a.com, b.net, c.io"`
- `"Triage these hashes from the incident report and rank by severity"`

### Best practices for prompt authors

- **One value per call.** Each tool checks exactly one IP/URL/CVE/domain/hash —
  for lists, ask the agent to check them "one by one and summarize"; it will loop.
- **Full inputs.** Include the scheme in URLs (`https://…`); hashes can be
  md5/sha1/sha256 — the tool detects the length.
- **Let the server pick providers** (default: all applicable) or pin for speed:
  `check this IP using only abuseipdb and greynoise`.
- **Read `verdict` with `severity` *and* `skipped` together.** `skipped` tells
  you which keyed providers were unavailable — never treat an empty result as
  "clean" without checking coverage.
- **Safe to run proactively.** The server is read-only (passive GETs only), so
  agents can check inputs without asking permission first.

## Verify locally

```bash
# Unit tests (offline, network tests deselected by default)
.venv/bin/pytest -q

# Smoke test — 5 tools against a stdio client (mock mode)
MOCK=1 .venv/bin/python tests/smoke.py

# Interactive MCP inspector (browser UI)
npx @modelcontextprotocol/inspector .venv/bin/python server.py

# Live network tests (require internet; always override addopts)
.venv/bin/pytest -q -m network -o addopts=""
```

## FAQ

**Why is `skipped` empty?** Your `.env` is loaded (or keys are exported), or you are in `MOCK=1` mode. `skipped` only lists keyed providers whose env var is unset — keyless providers always run.

**Why are some providers in `skipped`?** The key for that provider is not set. That is expected and safe: one provider's absence never fails the call. Every key is listed in the [provider matrix](#provider-matrix).

**Can it attack or scan anything?** No. Every request is a passive HTTP GET against a third-party lookup API. There is no active scanning, no OS fingerprinting, and no mutating API call anywhere in the tree.

**Rate limited?** Providers are internally rate-limited with a token bucket; a `429` raises `RateLimited` (distinct from a failed provider result). The server retries once via its limiter, and if still limited it returns a failed provider result with `error: "rate_limited"` — it never fails the whole call.
