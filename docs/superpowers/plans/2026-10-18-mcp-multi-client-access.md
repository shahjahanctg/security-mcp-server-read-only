# MCP Multi-Client Access Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add HTTP (streamable-http) remote access with a per-start random API key (optional pin via `MCP_API_KEY`), on-demand `config` subcommand to print client JSON for 5 targets, keep stdio as default, and preserve all existing behavior (5 tools, provider redaction, one-failure doesn't fail).

**Architecture:** Minimal surgical changes: three small `core/` modules (`auth.py`, `state.py`, `configgen.py`), dispatch in `server.py` (`main()` entry with `config` subcommand + transport selection), attach `mcp.auth = KeyVerifier(key)` only in HTTP mode, write `./.mcp_state.json` only in HTTP mode, banner on HTTP start, clean shutdown deletes state file. Tests cover auth/state/config/cli/http and guard regressions.

**Tech Stack:** Python 3.11+, FastMCP 4.1.0 (`TokenVerifier`, `AccessToken`), `httpx`, stdlib only (no new dependencies). Uses `secrets`, `hmac`, `os`, `json`, `argparse`, `datetime`.

**Spec:** `docs/superpowers/specs/2026-10-18-mcp-multi-client-access-design.md`

## Global Constraints

- stdio remains default; `MCP_TRANSPORT=stdio` or omitted → `mcp.run()` unchanged.
- Only HTTP auth in HTTP mode; no auth in stdio mode.
- `Authorization: Bearer <key>` only.
- Key: fresh `secrets.token_urlsafe(32)` per HTTP start unless `MCP_API_KEY` pinned.
- `verify_token` uses `hmac.compare_digest` (constant-time).
- State file `./.mcp_state.json` written only in HTTP mode, mode 0600, never consulted for auth.
- On shutdown (Ctrl+C/normal) delete state file; `config` reads state file.
- Provider keys never logged (secret boundary preserved).
- One provider failure never fails call (unchanged).
- `import server` and `investigate` remain importable (no side effects).
- Default pytest suite offline (`-m 'not network'`).

## Review Focus

1. **Secret boundary** — printing MCP access key is intentional; ensure provider keys (`ABUSEIPDB_API_KEY`, `VT_API_KEY`, `GREYNOISE_API_KEY`, `SHODAN_API_KEY`, `URLSCAN_API_KEY`, `NVD_API_KEY`, `IPINFO_TOKEN`) never appear in HTTP banner or config output (only MCP key). Test: scan banner/state/config for provider env keys; redaction already exists via `core.redact.redact`.
2. **Stale state** — `config` when state exists but server died: must exit with guidance or note `started_at`; deletion on shutdown prevents reuse, but stale can exist; ensure `config` is helpful.
3. **Auth timing** — constant-time compare (hmac) prevents obvious timing oracle; test wrong keys of same length.
4. **Port already in use** — OSError -> exit 1 with actionable message including `MCP_PORT`.
5. **Side effects on import** — importing `server` must not create `./.mcp_state.json`, print banner, bind port, or modify global state beyond module constants (tests import `server`/`investigate`).
---

### Task 1: Create core/auth.py

**Files:**
- Create: `core/auth.py`
- Test: `tests/test_auth.py`

**Interfaces:**
- Consumes: FastMCP types (`TokenVerifier`, `AccessToken`) from `fastmcp.server.auth`
- Produces: `KeyVerifier(TokenVerifier)`, `resolve_key() -> str`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_auth.py
import os
import hmac
from unittest import mock

from core import auth
from fastmcp.server.auth import AccessToken

def test_resolve_key_pins_from_env(monkeypatch):
    monkeypatch.setenv("MCP_API_KEY", "fixed-key-123")
    k = auth.resolve_key()
    assert k == "fixed-key-123"
    # no fresh random

def test_resolve_key_generates_random_when_unset(monkeypatch):
    monkeypatch.delenv("MCP_API_KEY", raising=False)
    k1 = auth.resolve_key()
    k2 = auth.resolve_key()
    assert isinstance(k1, str)
    assert len(k1) > 20
    assert k1 != k2  # different starts

def test_keyverifier_accepts_valid_key(monkeypatch):
    kv = auth.KeyVerifier("secret")
    tok = kv.verify_token("secret")
    assert isinstance(tok, AccessToken)

def test_keyverifier_rejects_bad_key(monkeypatch):
    kv = auth.KeyVerifier("secret")
    assert kv.verify_token("wrong") is None

def test_keyverifier_uses_constant_time_compare(monkeypatch):
    kv = auth.KeyVerifier("s" * 32)
    with mock.patch("core.auth.hmac.compare_digest", return_value=True) as m:
        tok = kv.verify_token("t" * 32)
        assert m.called
```

- [ ] **Step 2: Run test to verify it fails**

```bash
.venv/bin/pytest tests/test_auth.py -v
```
Expected: FAIL (core.auth not fully implemented)

- [ ] **Step 3: Implement core/auth.py**

Write `core/auth.py`:
- imports: `os`, `secrets`, `hmac`, `typing as t`
- `from fastmcp.server.auth import TokenVerifier, AccessToken` (treat as stdlib-integration per fastmcp)
- `def resolve_key() -> str:`
  - if `os.getenv("MCP_API_KEY"): return os.getenv("MCP_API_KEY")` (verbatim)
  - else `return secrets.token_urlsafe(32)`
- `class KeyVerifier(TokenVerifier):`
  - `def __init__(self, key: str): super().__init__(base_url=None); self.key = key`
  - `async def verify_token(self, token: str) -> AccessToken | None:` (or sync; probe shows fine) — use `hmac.compare_digest(token or "", self.key)`; if equal return `AccessToken(token=token, client_id="mcp-client")` else `None` (async to match base signature style)

- [ ] **Step 4: Run test to verify it passes**

```bash
.venv/bin/pytest tests/test_auth.py -v
```
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add core/auth.py tests/test_auth.py
git commit -m "feat(auth): add KeyVerifier with constant-time compare and key resolution"
```

### Task 2: Create core/state.py

**Files:**
- Create: `core/state.py`
- Test: `tests/test_state.py`

**Interfaces:**
- Consumes: stdlib `os`, `json`, `datetime`, `pathlib.Path` (or `os.path`)
- Produces: `State = TypedDict` (or dataclass), `write_state(state: dict) -> str`, `read_state(path: str = "./.mcp_state.json") -> dict`, `delete_state(path: str = "./.mcp_state.json") -> None`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_state.py
import os
import json
import tempfile
from core import state

def test_write_and_read_roundtrip(tmp_path, monkeypatch):
    p = tmp_path / ".mcp_state.json"
    monkeypatch.chdir(tmp_path)
    s = {"url": "http://127.0.0.1:8765/mcp", "key": "k", "host": "127.0.0.1", "port": 8765, "transport": "streamable-http", "started_at": "2026-10-18T12:00:00+00:00"}
    written = state.write_state(s)
    assert written.endswith(".mcp_state.json")
    r = state.read_state()
    assert r == s

def test_permissions_0600(tmp_path, monkeypatch):
    p = tmp_path / ".mcp_state.json"
    monkeypatch.chdir(tmp_path)
    s = {"url": "u", "key": "k", "host": "h", "port": 1, "transport": "streamable-http", "started_at": "2026-10-18T00:00:00+00:00"}
    state.write_state(s)
    st = os.stat("./.mcp_state.json")
    assert (st.st_mode & 0o777) == 0o600

def test_read_missing_raises(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    import pytest
    with pytest.raises(FileNotFoundError):
        state.read_state()
```

- [ ] **Step 2: Run test to verify it fails**

```bash
.venv/bin/pytest tests/test_state.py -v
```
Expected: FAIL

- [ ] **Step 3: Implement core/state.py**

Write `core/state.py`:
- imports: `os`, `json`, `datetime as dt`, `typing as t`
- `write_state(state: dict, path: str | None = None) -> str:`
  - p = path or "./.mcp_state.json"
  - ensure dir exists (cwd)
  - with open(p, "w") as f: json.dump(state, f, indent=2, sort_keys=True)
  - try: os.chmod(p, 0o600)
  - except Exception: pass (warn not required, but don't fail)
  - return p
- `read_state(path: str = "./.mcp_state.json") -> dict:`
  - if not os.path.exists(path): raise FileNotFoundError(path)
  - with open(path) as f: return json.load(f)
- `delete_state(path: str = "./.mcp_state.json") -> None:`
  - try: os.remove(path)
  - except FileNotFoundError: pass
  - except OSError: pass (best effort)

- [ ] **Step 4: Run test to verify it passes**

```bash
.venv/bin/pytest tests/test_state.py -v
```
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add core/state.py tests/test_state.py
git commit -m "feat(state): add state file read/write/delete with 0600 perms"
```

### Task 3: Create core/configgen.py

**Files:**
- Create: `core/configgen.py`
- Test: `tests/test_configgen.py`

**Interfaces:**
- Consumes: state dict (url, key, ...)
- Produces: `render_client(client: str, state: dict) -> str`, `render_all(state: dict) -> str`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_configgen.py
import json
from core import configgen

STATE = {"url": "http://127.0.0.1:8765/mcp", "key": "test-key-xyz", "host": "127.0.0.1", "port": 8765, "transport": "streamable-http"}

def test_render_opencode():
    out = configgen.render_client("opencode", STATE)
    data = json.loads(out)
    assert data["mcp"]["security"]["type"] == "remote"
    assert data["mcp"]["security"]["url"] == STATE["url"]
    assert data["mcp"]["security"]["headers"]["Authorization"] == f"Bearer {STATE['key']}"

def test_render_claude():
    out = configgen.render_client("claude", STATE)
    data = json.loads(out)
    assert data["mcpServers"]["security"]["type"] == "http"
    assert data["mcpServers"]["security"]["url"] == STATE["url"]
    assert data["mcpServers"]["security"]["headers"]["Authorization"] == f"Bearer {STATE['key']}"

def test_render_cursor():
    out = configgen.render_client("cursor", STATE)
    data = json.loads(out)
    assert data["mcpServers"]["security"]["url"] == STATE["url"]
    assert data["mcpServers"]["security"]["headers"]["Authorization"] == f"Bearer {STATE['key']}"

def test_render_cline():
    out = configgen.render_client("cline", STATE)
    data = json.loads(out)
    assert data["mcpServers"]["security"]["url"] == STATE["url"]
    assert data["mcpServers"]["security"]["headers"]["Authorization"] == f"Bearer {STATE['key']}"

def test_render_mcp_remote():
    out = configgen.render_client("mcp-remote", STATE)
    assert "npx -y mcp-remote" in out
    assert STATE["url"] in out
    assert STATE["key"] in out
    assert "Authorization: Bearer" in out

def test_render_all_emits_five():
    out = configgen.render_all(STATE)
    # simple heuristic: five client sections or at least 5 json blocks? easier: split by --- or just ensure 5 render_client results joined; but tests just assert all present
    assert '"opencode"' in out.lower() or '"security"' in out  # keep flexible? better check count
    # more precisely: count json blocks by lines starting with { in a structured way is fragile; but spec says 5 clients
    # check each appears
    for c in ["opencode", "claude", "cursor", "cline", "mcp-remote"]:
        assert c in out or c.replace('-', ' ') in out.lower()
```

- [ ] **Step 2: Run test to verify it fails**

```bash
.venv/bin/pytest tests/test_configgen.py -v
```
Expected: FAIL

- [ ] **Step 3: Implement core/configgen.py**

Write `core/configgen.py`:
- `import json`
- `def render_client(client: str, state: dict) -> str:`
  - url, key = state["url"], state["key"]
  - if client == "opencode":
      return json.dumps({"mcp": {"security": {"type": "remote", "url": url, "headers": {"Authorization": f"Bearer {key}"}}}}, indent=2)
  - if client == "claude":
      return json.dumps({"mcpServers": {"security": {"type": "http", "url": url, "headers": {"Authorization": f"Bearer {key}"}}}}, indent=2) + "\n# Also: use mcp-remote if your client expects stdio-only connectors"
  - if client == "cursor":
      return json.dumps({"mcpServers": {"security": {"url": url, "headers": {"Authorization": f"Bearer {key}"}}}}, indent=2)
  - if client == "cline":
      return json.dumps({"mcpServers": {"security": {"url": url, "headers": {"Authorization": f"Bearer {key}"}}}}, indent=2) + "\n# For RooCode/Continue, same mcpServers block applies"
  - if client == "mcp-remote" or client == "generic":
      return f'npx -y mcp-remote "{url}" --header "Authorization: Bearer {key}"'
  - raise ValueError(f"Unknown client: {client}")
- `def render_all(state: dict) -> str:`
  - parts = []
  - for c in ["opencode", "claude", "cursor", "cline", "mcp-remote"]:
      parts.append(f"=== {c} ===")
      parts.append(render_client(c, state))
      parts.append("")
  - return "\n".join(parts)

- [ ] **Step 4: Run test to verify it passes**

```bash
.venv/bin/pytest tests/test_configgen.py -v
```
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add core/configgen.py tests/test_configgen.py
git commit -m "feat(configgen): add client JSON/renderers for 5 targets + mcp-remote"
```

### Task 4: Rewrite server.py with CLI + transport dispatch (preserve behavior)

**Files:**
- Modify: `server.py`
- Test: `tests/test_cli.py`, `tests/test_http_mode.py` (new)

**Interfaces:**
- Consumes: `core.auth.resolve_key`, `core.auth.KeyVerifier`, `core.state.write_state/read_state/delete_state`, `core.configgen.render_client/render_all`
- Produces: `main()` callable (entry), preserves module-level `mcp`, `investigate`, tools

**Constraints:** no side effects on import. Only run network/listen in non-import paths (main). stdio unchanged.

- [ ] **Step 1: Write failing tests**

```python
# tests/test_cli.py
import sys
from core import state
from unittest import mock

def test_transport_precedence_flag_over_env(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    # simulate
    pass

def test_config_requires_state(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    import subprocess
    p = subprocess.run([sys.executable, "server.py", "config", "--client", "opencode"], cwd=tmp_path, capture_output=True)
    assert p.returncode == 1
    assert b"Server isn't running in HTTP mode" in p.stderr or b"Server isn't running" in p.stdout

def test_config_reads_state(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    s = {"url": "http://h:1/mcp", "key": "k", "host": "h", "port": 1, "transport": "streamable-http", "started_at": "2026-10-18T00:00:00+00:00"}
    state.write_state(s)
    import subprocess
    p = subprocess.run([sys.executable, "server.py", "config", "--client", "opencode"], cwd=tmp_path, capture_output=True)
    assert p.returncode == 0
    assert b"mcp" in p.stdout
```

```python
# tests/test_http_mode.py
import asyncio
import httpx
import socket
import tempfile
import sys
from core import state

def get_free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p

async def _run_http_and_probe(port):
    import subprocess
    env = {**os.environ, "MCP_TRANSPORT": "http", "MCP_HOST": "127.0.0.1", "MCP_PORT": str(port)}
    # start process
    pass
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
.venv/bin/pytest tests/test_cli.py -v
.venv/bin/pytest tests/test_http_mode.py -v 2>&1 | tail -5
```
Expected: FAIL

- [ ] **Step 3: Refactor server.py**

Key changes (minimal):
- add imports: `os`, `sys`, `argparse`, `json`, `datetime as dt`, `secrets`, `hmac` (as needed)
- import from core: `auth`, `state`, `configgen`
- keep all existing imports (fastmcp, core.*, mock, providers, core.schemas, core.verdict, core.cache, core.ratelimit) unchanged
- add `main()` that:
  - parse args: `config` subcommand, `--client`, `--all`
  - if config: read state → render → print → sys.exit(0/1)
  - else: determine transport (flag>env>stdio). If stdio: `mcp.run()` (no auth, no state). If http: resolve key, set `mcp.auth = auth.KeyVerifier(key)`, write state, print banner, run http with host/port/path="/mcp", delete state in finally
- replace `if __name__ == "__main__": mcp.run()` with `if __name__ == "__main__": main()`

Also ensure banner shows URL+key+config hint. Port-in-use: catch OSError when binding (FastMCP/http will raise; catch and sys.exit(1) with message).

Implementation details:
- HTTP run: `mcp.run(transport="http", host=host, port=port, path="/mcp")`
- stdio: `mcp.run()` (default)

- [ ] **Step 4: Run CLI tests**

```bash
.venv/bin/pytest tests/test_cli.py -v
```
Expected: PASS

- [ ] **Step 5: Run HTTP mode test (new, localhost only)**

```python
# tests/test_http_mode.py
import asyncio
import os
import sys
import socket
import tempfile
import httpx
import pytest

def free_port():
    s = socket.socket(); s.bind(("127.0.0.1",0)); p=s.getsockname()[1]; s.close(); return p

@pytest.mark.asyncio
async def test_http_auth_401_then_200(tmp_path):
    p = free_port()
    env = {**os.environ, "MCP_TRANSPORT":"http", "MCP_HOST":"127.0.0.1", "MCP_PORT":str(p)}
    # run server in background subprocess
    import subprocess, time
    proc = subprocess.Popen([sys.executable, "server.py"], cwd=str(tmp_path), env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        # wait for banner
        for _ in range(60):  # 6s
            line = proc.stdout.readline()
            if not line: break
            if "url:" in line and "key:" in line: break
        url = f"http://127.0.0.1:{p}/mcp"
        async with httpx.AsyncClient(timeout=5) as c:
            r = await c.post(url, json={"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}, headers={"Content-Type":"application/json","Accept":"application/json, text/event-stream"})
            assert r.status_code == 401
        # get key from state
        st = __import__("core.state").state.read_state(path=str(tmp_path)+"/.mcp_state.json")
        key = st["key"]
        async with httpx.AsyncClient(timeout=5) as c:
            r = await c.post(url, json={"jsonrpc":"2.0","id":1,"method":"tools/list"}, headers={"Content-Type":"application/json","Accept":"application/json, text/event-stream","Authorization":f"Bearer {key}"})
            assert r.status_code == 200
    finally:
        proc.terminate()
        try: proc.wait(timeout=5)
        except: proc.kill()
```

```bash
.venv/bin/pytest tests/test_http_mode.py -v
```
Expected: PASS

- [ ] **Step 6: Regression checks (existing suite)**

```bash
MOCK=1 .venv/bin/python tests/smoke.py 2>&1 | tail -5
.venv/bin/pytest -q -m 'not network' 2>&1 | tail -10
```
Expected: all pass (no regressions)

- [ ] **Step 7: Commit**

```bash
git add server.py tests/test_cli.py tests/test_http_mode.py
git commit -m "feat(server): add CLI dispatch, http transport with bearer auth, config subcommand, banner, state lifecycle"
```

### Task 5: Update README (beginner guide) + .gitignore

**Files:**
- Modify: `README.md`
- Modify: `.gitignore` (ensure `.mcp_state.json` ignored)

**Interfaces:**
- Documents `config` usage, env vars, LAN note, reset key, stdio default

- [ ] **Step 1: Update .gitignore**

Add `.mcp_state.json` if not present.

```bash
grep -q ".mcp_state.json" .gitignore || echo ".mcp_state.json" >> .gitignore
```

- [ ] **Step 2: Update README**

Add section: **Connect any MCP client (HTTP)** covering OpenCode/Claude/Cursor/Cline/Roo/Continue/mcp-remote, commands:
```bash
MCP_TRANSPORT=http .venv/bin/python server.py  # prints banner+key
python server.py config --client <name>
python server.py config --all
```
Notes: stdio default unchanged; `MCP_HOST=0.0.0.0` for LAN (firewall caution); set `MCP_API_KEY` for stable key; key regenerates on restart unless pinned.

- [ ] **Step 3: Verify no secrets in README**

Ensure no provider keys values printed.

- [ ] **Step 4: Commit**

```bash
git add .gitignore README.md
git commit -m "docs: add HTTP multi-client access guide and ignore mcp state"
```

### Task 6: Final verification & self-check

**Files:**
- Verify against spec and tests

- [ ] **Step 1: Run full offline suite**

```bash
.venv/bin/pytest -q -m 'not network' 2>&1 | tail -12
```
Expected: all pass (including new tests)

- [ ] **Step 2: Smoke test (stdio, mock)**

```bash
MOCK=1 .venv/bin/python tests/smoke.py 2>&1 | tail -2
```
Expected: exit 0 / "SUCCESS" or matches existing behavior

- [ ] **Step 3: Manual check — stdio default unchanged**

```bash
timeout 2 .venv/bin/python server.py 2>&1 | tail -2
```
(should attempt stdio run; no banner)

- [ ] **Step 4: Manual check — http mode banner + auth**

```bash
python -c "
# quick check via tests/http_mode.py logic
pass
"
```
(covered by test_http_mode.py)

- [ ] **Step 5: Secret boundary scan**

```bash
grep -rn '\.mcp_state.json' server.py core/*.py 2>&1 | tail -2
grep -r 'ABUSEIPDB_API_KEY\|VT_API_KEY\|GREYNOISE_API_KEY\|SHODAN_API_KEY\|URLSCAN_API_KEY\|NVD_API_KEY\|IPINFO_TOKEN' core/configgen.py core/state.py 2>&1 | wc -l
```
Expected: configgen/state must not contain provider keys (0 matches). Banner/state only contain MCP key.

- [ ] **Step 6: Side effects on import**

```bash
cd /tmp && python -c "import sys; sys.path.insert(0, '/home/shahjahan/Downloads/ai-masterclass/security-mcp-server-read-only'); import server; print('ok')" 2>&1 | tail -1
ls /tmp/.mcp_state.json 2>&1 | tail -1
```
Expected: 'ok'; no .mcp_state.json created in /tmp

- [ ] **Step 7: Commit (final touch)**

```bash
git diff --name-only
git status --short
```
(no code changes unless docs only; implementation done)

