# MCP Multi-Client Access — Design Spec

**Date:** 2026-10-18
**Status:** Draft
**Base:** server.py (5 tools: check_ip, check_url, lookup_cve, check_domain, check_hash)

## Goal

Enable the security MCP server to be usable by any MCP client (not just those that can spawn it via `stdio`) over HTTP with a randomly generated API key per start (pinned via env if desired), print ready-to-paste JSON for 5 target clients, and keep stdio as the default (no breaking changes).

## Questions & Locked Decisions

| # | Question | Answer (locked) |
|---|---|---|
| Q1 | Deployment reach | Localhost only + private LAN/VPN |
| Q2 | Transports | streamable-http (opt-in), stdio (keep as default) — no SSE planned now |
| Q3 | Auth enforcement | Bearer header only: `Authorization: Bearer <key>` |
| Q4 | Key lifecycle | Regenerate each start, unless `MCP_API_KEY` is pinned |
| Q5 | Config access | On-demand `config` subcommand |
| Q6 | Target clients | OpenCode, Claude, Cursor, Cline/Roo/Continue, Generic / mcp-remote |
| Q7 | Key discovery for config | State file (`./.mcp_state.json`) read by `config` command (never used for auth) |
| Q8 | Startup output (HTTP mode) | Banner with URL + key + config hint |

## Non-Goals (YAGNI)

- SSE transport
- TLS (localhost/LAN; users can add reverse proxy if needed)
- OAuth flow, multi-user keys, live key rotation while running
- PID tracking
- Public internet exposure hardening beyond binding control

## CLI & Entry

- stdio default: `MCP_TRANSPORT=stdio` (or omitted) → `mcp.run()` unchanged
- http mode: `MCP_TRANSPORT=http` → start HTTP server on `MCP_HOST` (default `127.0.0.1`), `MCP_PORT` (default `8765`), path `/mcp`
- Subcommand: `python server.py config --client <name>` or `python server.py config --all`
- Precedence: `--transport` flag > `MCP_TRANSPORT` env > `stdio`

## New Modules

| Module | Responsibility |
|---|---|
| `core/auth.py` | `KeyVerifier(TokenVerifier)`, `resolve_key()` |
| `core/state.py` | read/write/delete `./.mcp_state.json`, permission `0600` on write |
| `core/configgen.py` | render JSON blocks for all 5 clients + generic mcp-remote command |

## Auth

- `resolve_key()`:
  1. if `MCP_API_KEY` set → return it (stable)
  2. else → return `secrets.token_urlsafe(32)` (fresh)
- `KeyVerifier.verify_token(token: str)` → `AccessToken(token, client_id="mcp-client")` if `hmac.compare_digest(token, self.key)` else `None`
- Only attached when `transport == "http"`: `mcp.auth = KeyVerifier(key)` right before `run_async`/`run`
- 401 on missing/bad token before any tool execution (fastmcp enforces)

## State File (`./.mcp_state.json`)

```json
{
  "url": "http://{host}:{port}/mcp",
  "key": "<live key>",
  "host": "{host}",
  "port": {port},
  "transport": "streamable-http",
  "started_at": "<UTC ISO8601>"
}
```

- Written after successful bind in HTTP mode
- `os.chmod(path, 0o600)`
- Overwritten on each HTTP start
- Read-only by `config` command; never consulted for auth
- Deleted on clean shutdown (`finally`); stale file is harmless

## Banner (HTTP mode)

```
security MCP — streamable-http
  url:    http://{host}:{port}/mcp
  key:    {key}
  state:  ./.mcp_state.json
  config: python server.py config --client opencode|claude|cursor|cline|mcp-remote
```

## Config Generation

`config` command reads state file. If missing → exit 1 with guidance to start in HTTP mode.

Targets:
- **opencode** → `mcp.security = {"type":"remote","url":url,"headers":{"Authorization":"Bearer <key>"}}`
- **claude** → `mcpServers.security = {"type":"http","url":url,"headers":{…}}` (labels mcp-remote fallback)
- **cursor** → `mcpServers.security = {"url":url,"headers":{…}}`
- **cline** → `mcpServers.security = {"url":url,"headers":{…}}` (Roo/Continue variants noted)
- **mcp-remote** → `npx -y mcp-remote <url> --header "Authorization: Bearer <key>"`

`--all` emits all five. Output includes paste destinations.

## Error Handling

| Case | Action |
|---|---|
| Port in use | exit 1: "Port {port} is in use — set `MCP_PORT=<other>`" |
| Unknown transport/client | exit 2 with allowed values |
| State file unwritable | warn; continue serving (banner still shows URL+key) |
| Ctrl+C / normal shutdown | delete state file in `finally` |
| `config` missing state | exit 1 with start guidance |

## Testing

- `tests/test_auth.py` — env pin vs random, length/uniqueness, accept/reject, constant-time compare
- `tests/test_state.py` — roundtrip, schema, 0600, missing file error
- `tests/test_configgen.py` — 5 clients valid JSON with URL+Bearer, `--all`
- `tests/test_cli.py` — transport precedence, config dispatch, exit codes
- `tests/test_http_mode.py` — localhost ephemeral: 401 no auth, 401 bad, 200 OK with valid key (reaches tool). Runs in default non-network suite
- Regression: existing smoke + tests unchanged; stdio behavior untouched

## Backward Compatibility

- `mcp.run()` called with no args in stdio mode (unchanged)
- `import server` and `investigate` remain importable (no side effects)
- All existing 5 tools unchanged
- Provider keys never logged (secret boundary preserved)
- One provider failure never fails call (unchanged)
