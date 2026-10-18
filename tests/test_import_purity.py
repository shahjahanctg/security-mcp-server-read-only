import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = str(Path(__file__).resolve().parent.parent)


def test_import_server_has_no_side_effects(tmp_path):
    env = dict(os.environ, PYTHONPATH=REPO_ROOT)
    p = subprocess.run(
        [sys.executable, "-c", "import server"],
        cwd=tmp_path,
        capture_output=True,
        env=env,
    )
    assert p.returncode == 0, p.stderr
    out = (p.stdout + p.stderr).decode("utf-8", errors="ignore")
    assert "streamable-http" not in out
    assert "url:" not in out
    assert not (tmp_path / ".mcp_state.json").exists()
