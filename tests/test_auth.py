import os
import hmac
from unittest import mock

from core import auth
from fastmcp.server.auth import AccessToken
import asyncio

def test_resolve_key_pins_from_env(monkeypatch):
    monkeypatch.setenv("MCP_API_KEY", "fixed-key-123")
    k = auth.resolve_key()
    assert k == "fixed-key-123"

def test_resolve_key_generates_random_when_unset(monkeypatch):
    monkeypatch.delenv("MCP_API_KEY", raising=False)
    k1 = auth.resolve_key()
    k2 = auth.resolve_key()
    assert isinstance(k1, str)
    assert len(k1) > 20
    assert k1 != k2

def test_keyverifier_accepts_valid_key(monkeypatch):
    kv = auth.KeyVerifier("secret")
    tok = asyncio.run(kv.verify_token("secret"))
    assert isinstance(tok, AccessToken)

def test_keyverifier_rejects_bad_key(monkeypatch):
    kv = auth.KeyVerifier("secret")
    tok = asyncio.run(kv.verify_token("wrong"))
    assert tok is None

def test_keyverifier_uses_constant_time_compare(monkeypatch):
    kv = auth.KeyVerifier("s" * 32)
    with mock.patch("core.auth.hmac.compare_digest", return_value=True) as m:
        tok = asyncio.run(kv.verify_token("t" * 32))
        assert m.called
