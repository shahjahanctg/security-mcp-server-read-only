import sys
import os
from pathlib import Path
from core import state

SERVER = str(Path(__file__).resolve().parent.parent / "server.py")

def test_config_requires_state(tmp_path):
    import subprocess
    p = subprocess.run([sys.executable, SERVER, "config", "--client", "opencode"], cwd=tmp_path, capture_output=True)
    assert p.returncode == 1
    out = (p.stdout + p.stderr).decode("utf-8", errors="ignore")
    assert "Server isn't running in HTTP mode" in out

def test_config_reads_state(tmp_path):
    s = {"url": "http://h:1/mcp", "key": "k", "host": "h", "port": 1, "transport": "streamable-http", "started_at": "2026-10-18T00:00:00+00:00"}
    state.write_state(s, path=str(tmp_path / ".mcp_state.json"))
    import subprocess
    p = subprocess.run([sys.executable, SERVER, "config", "--client", "opencode"], cwd=tmp_path, capture_output=True)
    assert p.returncode == 0, p.stderr
    out = p.stdout.decode("utf-8", errors="ignore")
    assert "mcp" in out
