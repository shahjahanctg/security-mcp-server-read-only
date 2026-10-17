# Security MCP Server Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a read-only stdio MCP server exposing `check_ip`, `check_url`, `lookup_cve` that fan out to multiple optional security APIs and return a normalized consensus record.

**Architecture:** Single FastMCP Python process. Each tool validates input, checks a TTL cache, then `asyncio.gather`s over configured providers (skipping those whose API keys are absent), normalizes each result to a common record, and rolls up a worst-case verdict. `MOCK=1` short-circuits HTTP with canned payloads.

**Tech Stack:** Python ≥3.11, `fastmcp`, `httpx`, `python-dotenv`, `pytest`, `pytest-asyncio`, `mcp` (client, tests only).

**Spec:** `docs/superpowers/specs/2026-10-17-security-mcp-server-design.md`

## Global Constraints

- Read-only: only `httpx.get` in the codebase; no POST/PUT/PATCH/DELETE; no scan-submission endpoints.
- All API keys optional env vars: `ABUSEIPDB_API_KEY`, `VT_API_KEY`, `GREYNOISE_API_KEY`, `SHODAN_API_KEY`, `URLSCAN_API_KEY`, `NVD_API_KEY`; plus `MOCK`, `CACHE_TTL` (default 900).
- Keys never logged; errors mention env-var names only.
- Tool output shape (all three tools): `{input, type, verdict, severity, summary, queried: [str], skipped: [{provider, reason}], results: [ProviderResult], retrieved_at}`.
- `ProviderResult`: `{source, ok, verdict, severity, summary, data, error, retrieved_at}`; verdicts ∈ benign|suspicious|malicious|unknown|error; severities ∈ none|low|medium|high|critical|unknown.
- Validators: `ipaddress.ip_address`; URL must be http/https with netloc and must not be `localhost`, `.local`/`.internal`, or a private/loopback/link-local literal IP (SSRF guard); CVE regex `^CVE-\d{4}-\d{4,}$` (case-insensitive, uppercased).
- Provider HTTP timeout 10s; one retry on HTTP 429 after rate-bucket wait, then `error="rate_limited"`.
- Per-provider self-imposed rate limits (tokens/sec): abuseipdb 0.5, virustotal 0.15, greynoise 1, shodan 1, ipapi 0.66, urlscan 1, nvd 0.8, mitre 1, osv 1.
- Roll-up: worst verdict across ok results (malicious > suspicious > benign > unknown); worst severity (critical > high > medium > low > none > unknown); summary `Consensus: {verdict} across {n}/{m} responding providers.`
- Normalized verdict mapping per provider — see spec § Providers.

## Review Focus

- **Private-IP URL bypass via DNS name** (`http://localhost/`): validator rejects `localhost`, `.local`, `.internal` suffixes — test in Task 1.
- **VT URL lookup uses base64url of the URL without padding** — wrong encoding yields 404 treated as benign; pin encoding test in Task 7.
- **NVD 404 (unknown CVE)** must produce a tool response with all providers `ok:false, error="not_found"`, not an exception — test in Task 8/9.
- **Rate-limiter per-provider, not global**: a slow provider must not stall others — test in Task 3/8.
- **Cache key includes provider filter** — `check_ip(ip)` vs `check_ip(ip, providers=["ipapi"])` must not collide — test in Task 2.

---

### Task 0: Spec & repo scaffold
**Files:** Create `pyproject.toml`, `.gitignore`, `.env.example`.
- [ ] Write `.env.example` listing all key names (empty values); `pyproject.toml` with deps + dev deps; `.gitignore` (`.env`, `__pycache__`, `.venv`, `.pytest_cache`).
- [ ] Create venv, `pip install -e ".[dev]"`; verify `python -c "import fastmcp, httpx"`.
- [ ] Commit spec, plan, scaffold.

### Task 1: Schemas & validators
**Files:** Create `core/__init__.py`, `core/schemas.py`, `tests/test_validators.py`.
**Interfaces — Produces:** `VERDICTS`, `SEVERITIES`; `@dataclass ProviderResult(source, ok, verdict, severity, summary, data, error, retrieved_at)`; `validate_ip(value)->str`, `validate_url(value)->str`, `validate_cve(value)->str` (raise `ValueError`).
- [ ] Failing tests: valid IPv4/IPv6 pass; `not-an-ip` fails; `https://example.com/a` passes; `ftp://x`, `file:///etc/passwd`, `http://localhost/`, `http://10.0.0.1/`, `http://169.254.169.254/` fail; `cve-2021-44228`→`CVE-2021-44228`; `CVE-21-1` fails.
- [ ] Run fail → implement → run pass → commit.

### Task 2: TTL cache
**Files:** Create `core/cache.py`, `tests/test_cache.py`.
**Interfaces — Produces:** `TTLCache(ttl=900.0, maxsize=1000)`; `get(key: tuple)->dict|None`; `set(key: tuple, value: dict)->None` (evict oldest on overflow; ignore expired).
- [ ] Failing tests: hit/miss; expiry (`ttl=0.01` + sleep); eviction; distinct keys `("ip","1.1.1.1",None)` vs `("ip","1.1.1.1",("ipapi",))`.
- [ ] Fail → implement → pass → commit.

### Task 3: Rate limiter
**Files:** Create `core/ratelimit.py`, `tests/test_ratelimit.py`.
**Interfaces — Produces:** `RateLimiter(rate, capacity=None, clock=time.monotonic)`; `async acquire()->None`.
- [ ] Failing tests: 3 immediate acquires at rate=1000/capacity=3 instant; 4th waits (rate=10/capacity=1, elapsed ≥ threshold); instances independent.
- [ ] Fail → implement → pass → commit.

### Task 4: HTTP client & verdict roll-up
**Files:** Create `core/http.py`, `core/verdict.py`, `tests/test_verdict.py`.
**Interfaces — Produces:** `get_client()->httpx.AsyncClient` (10s timeout, no redirects); `roll_up(results)->(verdict, severity, summary)`.
- [ ] Failing tests: malicious+benign→malicious; all unknown→unknown; empty→`("unknown","unknown","No providers responded.")`; summary format; severity ordering.
- [ ] Fail → implement → pass → commit.

### Task 5: Provider base + registry + mock plumbing
**Files:** Create `providers/__init__.py`, `providers/base.py`, `tests/test_registry.py`.
**Interfaces — Produces:** `Provider` ABC (`name`, `tool`, `available()`, `mock_raw()`, `async fetch()`, `normalize()`, final `async run()`); `PROVIDERS: list`; `for_tool(tool, only)->(selected, skipped)` (skipped reasons: `"{ENV} not set"`, `"unknown provider"`).
- [ ] Failing tests with fake provider: selection; missing key skip; unknown name skip; `MOCK=1` uses `mock_raw`; fetch exception → `ok=False` record.
- [ ] Fail → implement → pass → commit.

### Task 6: Keyless providers (ipapi, urlscan, nvd, mitre_cve, osv)
**Files:** Create the five provider modules + `tests/test_keyless_providers.py`; register in `providers/__init__.py`.
- [ ] Failing tests: `normalize(value, CANONICAL_RAW)` per mapping table; `available()` True without keys; `mock_raw` non-empty.
- [ ] Fail → implement → pass → commit.

### Task 7: Keyed providers (abuseipdb, virustotal, greynoise, shodan)
**Files:** Create the four modules + `tests/test_keyed_providers.py`; register.
- [ ] Failing tests: normalize canned raws; `available()` False without key; VT URL id encoding (`https://example.com/a b` → expected base64url nopad).
- [ ] Fail → implement → pass → commit.

### Task 8: Server orchestration + mock mode + smoke test
**Files:** Create `server.py`, `mock.py`, `tests/test_orchestration.py`, `tests/smoke.py`, `requirements.txt`.
**Interfaces — Produces:** `investigate(tool, value, providers)->dict`; `mcp = FastMCP("security")` with three tools; `if __name__=="__main__": mcp.run()`.
- [ ] Failing tests: `investigate("ip","1.2.3.4",["ipapi"])` under `MOCK=1` returns full shape with `queried==["ipapi"]`; cached second call same `retrieved_at`; invalid input → error.
- [ ] Fail → implement → pass → commit.
- [ ] `tests/smoke.py`: mcp client over stdio with `MOCK=1`; `tools/list` = 3; call each; assert keys.
- [ ] `MOCK=1 pytest && MOCK=1 python tests/smoke.py` → pass → commit.

### Task 9: Live keyless verification
**Files:** Create `tests/test_live.py` (`pytest.mark.network`, skip if unreachable).
- [ ] Test `investigate("cve","CVE-2021-44228",["nvd","mitre","osv"])` live: ≥2 ok; NVD severity critical. Run manually; commit.

### Task 10: Integration docs & OpenCode config
**Files:** Create `README.md`, `opencode.snippet.json`.
- [ ] README (setup, tool table, agent prompts, inspector, curl-equivalent, read-only guarantee); `opencode.snippet.json` (approved `mcp.security` local config).
- [ ] Final verification: `pytest` green; `MOCK=1 python tests/smoke.py` green; grep tree for mutating verbs → zero; commit.
