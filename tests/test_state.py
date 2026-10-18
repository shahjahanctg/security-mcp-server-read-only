import os
import json
import tempfile
from core import state

def test_write_and_read_roundtrip(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    s = {"url": "http://127.0.0.1:8765/mcp", "key": "k", "host": "127.0.0.1", "port": 8765, "transport": "streamable-http", "started_at": "2026-10-18T12:00:00+00:00"}
    written = state.write_state(s)
    assert written.endswith(".mcp_state.json")
    r = state.read_state()
    assert r == s

def test_permissions_0600(tmp_path, monkeypatch):
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
