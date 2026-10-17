# Security MCP Server Expansion — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add read-only `check_domain` and `check_hash` tools plus eleven providers, and enrich `check_ip`/`lookup_cve` with reverse-DNS, passive-DNS, passive open-port/service, EPSS and CISA-KEV data.

**Architecture:** Same single FastMCP process. Each tool validates input, checks the TTL cache, fans out over available providers, normalizes to the common record, and rolls up a consensus verdict. New providers follow the existing `Provider` ABC. A new `FeedCache` holds the large CISA-KEV feed.

**Tech Stack:** Python ≥3.11, `fastmcp`, `httpx`, `python-dotenv`, `pytest`, `pytest-asyncio`, `mcp` (tests).

**Spec:** `docs/superpowers/specs/2026-10-17-security-mcp-server-expansion-addendum.md` (created in Task 0). Base spec: `docs/superpowers/specs/2026-10-17-security-mcp-server-design.md`.

## Global Constraints

- Read-only: only `httpx.get`; no POST/PUT/PATCH/DELETE; no scan submission; **no active scanning, no OS fingerprinting**. RDAP may pass `follow_redirects=True` on its single GET.
- All keys optional env vars: `ABUSEIPDB_API_KEY`, `VT_API_KEY`, `GREYNOISE_API_KEY`, `SHODAN_API_KEY`, `URLSCAN_API_KEY`, `NVD_API_KEY`, `IPINFO_TOKEN`; plus `MOCK`, `CACHE_TTL` (default 900).
- Keys never logged; secret values redacted from errors (`core/redact.py`).
- Provider result shape unchanged: `{source, ok, verdict, severity, summary, data, error, retrieved_at}`; verdicts `benign|suspicious|malicious|unknown|error`; severities `none|low|medium|high|critical|unknown`.
- Tool output shape unchanged: `{input, type, verdict, severity, summary, queried, skipped, results, retrieved_at}`.
- New provider results follow the existing 404→`not_found_result`, 429→`RateLimited`, other non-404→raise convention.
- No `#` comments in source (project convention).
- After every task: run `.venv/bin/pytest -q`, commit, and `git push upstream main`. Repo remote is `upstream`.

## Review Focus

- **Domain validator must reject scheme/backslash/space/underscore and IP literals** — a bare `http://x` or `8.8.8.8` must not be accepted as a domain; test in Task 1.
- **`internetdb` 404 is normal** (many IPs have no snapshot) and must become `not_found`, not an error — test in Task 3.
- **CISA-KEV feed is fetched once and shared** across concurrent CVE lookups (lock-guarded, long TTL), and a feed-shaped but non-matching CVE yields `benign`/`none`, not an error — test in Task 4.
- **VT file 404** must produce `not_found`, and VT hash lookup uses the raw hash in the path (no base64) — test in Task 5.
- **`check_domain`/`check_hash` cache keys include `type`** so `("domain","x",…)` never collides with `("ip",…)` — test in Task 6.

---

### Task 0: Baseline & spec addendum

**Files:**
- Create: `docs/superpowers/specs/2026-10-17-security-mcp-server-expansion-addendum.md`
- Create: `docs/superpowers/plans/2026-10-17-security-mcp-server-expansion.md`

- [ ] Commit + push the pending hardening (already done: `core/redact.py`, `tests/test_redact.py`, `providers/base.py`, `server.py`, `opencode.json`).
- [ ] Write the spec addendum (Provider table, normalization rules, validators, feed cache, rates, security constraints, decisions E1–E7).
- [ ] Copy this plan to `docs/superpowers/plans/`.
- [ ] Commit + push.

### Task 1: Domain & hash validators

**Files:**
- Modify: `core/schemas.py`
- Test: `tests/test_validators.py`

**Interfaces — Produces:** `validate_domain(value: str) -> str`; `validate_hash(value: str) -> str`.

- [ ] **Step 1: Failing tests** — add to `tests/test_validators.py`:
  - `validate_domain("Example.COM.") == "example.com"`; `validate_domain("tekvision.com.bd") == "tekvision.com.bd"`.
  - Rejects (raise `ValueError`): `""`, `"http://example.com"`, `"example.com/path"`, `"exa mple.com"`, `"exam\\ple.com"`, `"localhost"`, `"printer.local"`, `"db.internal"`, `"8.8.8.8"`, `"nodot"`, `"-bad.example.com"`, `"exa_mple.com"`.
  - `validate_hash("D41D8CD98F00B204E9800998ECF8427E") == "d41d8cd98f00b204e9800998ecf8427e"`; accepts 40- and 64-hex; rejects `"xyz"`, short hash, non-hex.
- [ ] **Step 2: Run** → FAIL (function not defined).
- [ ] **Step 3: Implement** in `core/schemas.py` with the normalization and label regex from the addendum (`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`; hash regex `^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$`).
- [ ] **Step 4: Run** `.venv/bin/pytest -q` → PASS.
- [ ] **Step 5: Commit + push** `feat: add domain and hash validators`.

### Task 2: Domain providers

**Files:**
- Create: `providers/_otx.py`, `providers/rdap.py`, `providers/dns_records.py`, `providers/crtsh.py`, `providers/otx_domain.py`
- Modify: `providers/__init__.py`
- Test: `tests/test_domain_providers.py`

**Interfaces — Produces:** `Rdap`, `DnsRecords`, `CrtSh`, `OtxDomain` (each `name`, `tool="domain"`, `env_key=None`); `_otx.OTX_BASE`, `_otx.verdict_from_pulses(count) -> tuple[str,str]`, `_otx.fetch_otx(path) -> dict`.

- [ ] **Step 1: Failing tests** — canonical raw per provider → expected `verdict/severity/summary/data` keys; 404→`not_found`; 429→`RateLimited`; `mock_raw` non-empty; `available()` True. Include a `rdap` raw with a recent `registration` event asserting `suspicious`/`medium`, and an old one asserting `benign`/`none`.
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement** the four providers. `dns` fetch issues four GETs (A/MX/NS/TXT) and merges `{"A":[…],"MX":[…],"NS":[…],"TXT":[…]}`. `crtsh` splits `name_value` on newlines, de-dupes, filters to the domain, sorts, ≤50. `rdap` uses `follow_redirects=True`. `otx_domain` fetches `/general` and `/passive_dns` and merges. Register all four in `providers/__init__.py`.
- [ ] **Step 4: Run** `.venv/bin/pytest -q` → PASS.
- [ ] **Step 5: Commit + push** `feat: add domain recon providers`.

### Task 3: New IP providers

**Files:**
- Create: `providers/ipinfo.py`, `providers/internetdb.py`, `providers/reverse_dns.py`, `providers/otx_ip.py`
- Modify: `providers/__init__.py`
- Test: `tests/test_ip_providers.py`

**Interfaces — Produces:** `IpInfo`, `InternetDb`, `ReverseDns`, `OtxIp` (all `tool="ip"`; `env_key=None`).

- [ ] **Step 1: Failing tests** — canonical raws; `internetdb` raw with `vulns` → severity `medium`, verdict `unknown`, and a 404 → `not_found`; `reverse_dns` uses `ipaddress.ip_address("8.8.8.8").reverse_pointer`; `otx_ip` passive-DNS hostnames extracted; 429→`RateLimited`; `mock_raw` non-empty.
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement**. `ipinfo` appends `token=IPINFO_TOKEN` when set (keyless without it). `internetdb` GET `https://internetdb.shodan.io/{ip}`. `reverse_dns` queries `dns.google` with the reverse pointer, type PTR. `otx_ip` fetches `/general` + `/passive_dns`. Register all four.
- [ ] **Step 4: Run** `.venv/bin/pytest -q` → PASS.
- [ ] **Step 5: Commit + push** `feat: add ip recon providers`.

### Task 4: CVE providers & feed cache

**Files:**
- Create: `core/feed.py`, `providers/epss.py`, `providers/cisa_kev.py`, `providers/circl.py`
- Modify: `providers/__init__.py`
- Test: `tests/test_cve_providers.py`, `tests/test_feed.py`

**Interfaces — Produces:** `FeedCache(ttl, clock=time.monotonic)` with `async get(fetcher)`; `Epss`, `CisaKev`, `Circl` (`tool="cve"`, `env_key=None`).

- [ ] **Step 1: Failing tests** —
  - `test_feed.py`: `get` calls fetcher once across two calls within TTL; re-fetches after expiry (injected clock); concurrent `asyncio.gather` fetches once (counter==1).
  - `test_cve_providers.py`: EPSS raw `{"data":[{"epss":"0.97","percentile":"0.99","cve":…}]}` → severity `medium`; empty `data` → `not_found`. KEV raw with the CVE present → `malicious`/`high`, absent → `benign`/`none` (and feed fetched once across both). CIRCL canonical → `from_cvss` mapping; `None`/empty → `not_found`.
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement** `core/feed.py` (lock-guarded single-entry cache) and the three providers. `cisa_kev` uses a module-level `FeedCache(ttl=21600)` whose fetcher downloads the feed and builds a `{cveID: entry}` dict. Register the three.
- [ ] **Step 4: Run** `.venv/bin/pytest -q` → PASS.
- [ ] **Step 5: Commit + push** `feat: add cve intel providers and feed cache`.

### Task 5: Hash providers

**Files:**
- Modify: `providers/virustotal.py`, `providers/__init__.py`
- Create: `providers/otx_file.py`
- Test: `tests/test_hash_providers.py`

**Interfaces — Produces:** `VirusTotalFile` (`tool="hash"`, `env_key="VT_API_KEY"`), `OtxFile` (`tool="hash"`, `env_key=None`).

- [ ] **Step 1: Failing tests** — VT file raw `last_analysis_stats.malicious=3` → `malicious`/`high`; 404→`not_found`; a URL-encoded hash is passed verbatim in the path. OTX file raw pulse count>0 → `suspicious`/`medium`; `mock_raw` non-empty.
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement** `VirusTotalFile` in `providers/virustotal.py` (mirror `VirusTotalIP`) and `providers/otx_file.py`. Register both.
- [ ] **Step 4: Run** `.venv/bin/pytest -q` → PASS.
- [ ] **Step 5: Commit + push** `feat: add hash reputation providers`.

### Task 6: Server wiring

**Files:**
- Modify: `server.py`, `tests/smoke.py`, `tests/test_orchestration.py`

**Interfaces — Consumes:** all providers from Tasks 2–5. **Produces:** `check_domain(domain, providers=None)`, `check_hash(file_hash, providers=None)`.

- [ ] **Step 1: Failing tests** — in `test_orchestration.py`: `investigate("domain","example.com",["dns"])` under MOCK returns full shape with `type=="domain"`; `investigate("hash","d41d8cd98f00b204e9800998ecf8427e",["otx_file"])` → `type=="hash"`; invalid domain/hash raise `ValueError`; a `("domain",…,None)` cache entry does not satisfy `("hash",…)`. Update `smoke.py`: `_EXPECTED_TOOLS` = `{check_ip, check_url, lookup_cve, check_domain, check_hash}`, `len(names)==5`, add `check_domain(domain="example.com")` and `check_hash(file_hash="d41d8cd98f00b204e9800998ecf8427e")` calls.
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement** in `server.py`: import `validate_domain`, `validate_hash`; add to `_VALIDATORS`; add the 13 rate-limit entries from the addendum; add the two `@mcp.tool()` functions.
- [ ] **Step 4: Run** `.venv/bin/pytest -q` and `MOCK=1 .venv/bin/python tests/smoke.py` → PASS (5 tools).
- [ ] **Step 5: Commit + push** `feat: expose check_domain and check_hash tools`.

### Task 7: Docs, README revamp & live verification

**Files:**
- Modify: `README.md`, `.env.example`, `opencode.snippet.json`, `tests/test_live.py`

- [ ] **Step 1:** Rewrite `README.md` to be attractive and beginner-friendly: a one-line pitch, a capability table (5 tools), a "What you get" bullet list (reputation, geolocation, open ports & service fingerprints, subdomains, passive DNS, reverse DNS, CVE severity + EPSS + CISA-KEV), quickstart, provider table with keyless/keyed, and copy-paste agent prompts (`"Check 45.124.15.34"`, `"Recon example.com"`, `"Look up CVE-2021-44228"`, `"Check this sha256: …"`). Keep the read-only guarantee section and note "passive only — no scanning".
- [ ] **Step 2:** Add optional `IPINFO_TOKEN` to `.env.example` and the snippet environment block; note it is optional.
- [ ] **Step 3:** Add a `network`-marked live test: `investigate("domain","example.com",["rdap","dns","crtsh","otx_domain"])` has ≥2 ok.
- [ ] **Step 4:** Verification: `.venv/bin/pytest -q`; `MOCK=1 .venv/bin/python tests/smoke.py`; live `check_ip("45.124.15.34")`, `check_domain("tekvision.com.bd")`, `lookup_cve("CVE-2021-44228")`, `check_hash("d41d8cd98f00b204e9800998ecf8427e")`; grep tree for `httpx.post|put|patch|delete|requests` → zero.
- [ ] **Step 5: Commit + push** `docs: document expanded tools and providers`.
