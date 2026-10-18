import asyncio
import os
import sys
import socket
import time
from pathlib import Path

import httpx
import pytest

SERVER = str(Path(__file__).resolve().parent.parent / "server.py")


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


@pytest.mark.asyncio
async def test_http_auth_401_then_200(tmp_path):
    port = free_port()
    env = {**os.environ, "MCP_TRANSPORT": "http", "MCP_HOST": "127.0.0.1", "MCP_PORT": str(port), "MCP_API_KEY": "test-live-key-abc"}
    import subprocess

    proc = subprocess.Popen(
        [sys.executable, SERVER],
        cwd=str(tmp_path),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        deadline = time.time() + 15
        while time.time() < deadline:
            if (tmp_path / ".mcp_state.json").exists():
                break
            time.sleep(0.1)
        else:
            out = proc.stdout.read() if proc.poll() is not None else ""
            raise AssertionError(f"server did not start; output: {out}")

        url = f"http://127.0.0.1:{port}/mcp"
        async with httpx.AsyncClient(timeout=5) as c:
            r = await c.post(
                url,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {},
                        "clientInfo": {"name": "t", "version": "1"},
                    },
                },
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json, text/event-stream",
                },
            )
            assert r.status_code == 401

        async with httpx.AsyncClient(timeout=5) as c:
            r = await c.post(
                url,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {},
                        "clientInfo": {"name": "t", "version": "1"},
                    },
                },
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json, text/event-stream",
                    "Authorization": "Bearer wrong-key",
                },
            )
            assert r.status_code == 401

        async with httpx.AsyncClient(timeout=5) as c:
            r = await c.post(
                url,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {},
                        "clientInfo": {"name": "t", "version": "1"},
                    },
                },
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json, text/event-stream",
                    "Authorization": "Bearer test-live-key-abc",
                },
            )
            assert r.status_code == 200, r.status_code
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
            proc.wait(timeout=5)


@pytest.mark.asyncio
async def test_state_removed_on_shutdown(tmp_path):
    port = free_port()
    env = {**os.environ, "MCP_TRANSPORT": "http", "MCP_HOST": "127.0.0.1", "MCP_PORT": str(port), "MCP_API_KEY": "test-live-key-abc"}
    import subprocess

    proc = subprocess.Popen(
        [sys.executable, SERVER],
        cwd=str(tmp_path),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        deadline = time.time() + 15
        while time.time() < deadline:
            if (tmp_path / ".mcp_state.json").exists():
                break
            time.sleep(0.1)
        else:
            raise AssertionError("server did not start")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
            proc.wait(timeout=5)
    time.sleep(0.3)
    assert not (tmp_path / ".mcp_state.json").exists()
