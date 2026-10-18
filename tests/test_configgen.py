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
    for c in ["opencode", "claude", "cursor", "cline", "mcp-remote"]:
        assert c in out
