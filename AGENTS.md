# AGENTS.md — quick reference for OpenCode sessions

## Repo structure
- Entrypoint: `server.py` runs the FastMCP app exposing exactly **three tools**.
- All outbound calls are **HTTP GET only**; the source contains zero POST/PUT/PATCH/DELETE or mutating verbs. Keyless, offline testing uses `MOCK=1`.

## Setup (fast)
```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```
Keyless / offline: `MOCK=1 .venv/bin/python server.py`

## Running code
### Lint / type / test order
Default `pyproject.toml` sets `addopts = "-m 'not network'"`. To run network tests (live keyless), override: `.venv/bin/pytest -q -m network -o addopts=""`

### Run a single test
```bash
.venv/bin/pytest -q tests/<file>.py::TestClass::test_method
```

### Smoke test (stdio client, mock)
```bash
MOCK=1 .venv/bin/python tests/smoke.py
```

### Interactive inspector (stdio server)
```bash
npx @modelcontextprotocol/inspector .venv/bin/python server.py
```

### Full test suite
```bash
.venv/bin/pytest -q   # skips network tests
```

## Key conventions
- **Environment keys**: `ABUSEIPDB_API_KEY`, `VT_API_KEY`, `GREYNOISE_API_KEY`, `SHODAN_API_KEY`, `URLSCAN_API_KEY`, `NVD_API_KEY`. Missing keys → provider is **skipped** and reported in `skipped`.
- **Provider styles**:
  - *Keyless* (ipapi, mitre_cve, osv, urlscan) → queried even if their optional key is unset.
  - *Keyed* (abuseipdb, virustotal_ip, greynoise, shodan, virustotal_url, nvd) → skipped if the env var is missing.
- **Normalization**: Tool results always contain `verdict`, `severity`, `results`, `queried`, `skipped`, `retrieved_at`.
- **Rate limiting**: Per-provider token-bucket is internally enforced; 429 raises `RateLimited`, not a failure result.
- **One provider failure does NOT fail the call**; it's reported in results as a failed provider with `ok: false`.

## Testing quirks
- Use `@pytest.mark.network` for live tests. Always override addopts when running them.
- In `mock` mode (`MOCK=1`), all providers return canned data from their `mock_raw`.
- Most providers fetch live only if `MOCK != "1"`.
- `shodan` is keyless, uses the **InternetDB** passive API (no direct Shodan key needed), runs weekly snapshots, no banners.
- `greynoise` and `shodan` block `localhost` / `.local` / private and loopback IPs during SSRF-guarded lookups.
- `urlscan` and `nvd` providers respect optional key but still are queried keyless when key is unset.

## How to wire into OpenCode
OpenCode config (`opencode.json`):
```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "security": {
      "type": "local",
      "command": [".venv/bin/python", "server.py"],
      "enabled": true
    }
  }
}
```
**Critical**: The command runs the **venv interpreter**, not the global python. Ensure the `.venv` has requirements.txt installed before starting OpenCode. Optionally, use uv/pipx inline (see README).

## Commit and push discipline
After each task, run:
```bash
git add -A
git commit -m "feat: <short summary>"
git push upstream main   # remote is named "upstream"
```

## Working in isolation
If you need to isolate a feature or test, use a **git worktree**: `git worktree add ../somedir main`. Keep the SDD ledger in `.superpowers/` — it tracks plan status and is gitignored.

## Fallback on undecidable
- If docs conflict with code, trust the executable source.
- For architecture/ownership, inspect a few representative code files and look for the real entrypoint (server.py) and module registrations (providers/__init__.py).

## When to ask the user
Only ask if the repo lacks something important (e.g., undocumented conventions, branch/PR/release expectations, missing setup prerequisites). Everything else is documented above.

---
*Created from inspecting the repo’s highest-value docs, commands, and conventions. All claims are verified by the codebase (scripts, README, config, tests).*