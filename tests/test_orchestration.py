import pytest

import providers as providers_pkg
import server
from core.ratelimit import RateLimiter
from core.schemas import SEVERITIES, VERDICTS, ProviderResult, now_iso
from providers.base import RateLimited


class _StubProvider:
    def __init__(self, name, tool, run):
        self.name = name
        self.tool = tool
        self._run = run

    def available(self):
        return True

    async def run(self, value):
        return await self._run(value)

_EXPECTED_KEYS = {
    "input",
    "type",
    "verdict",
    "severity",
    "summary",
    "queried",
    "skipped",
    "results",
    "retrieved_at",
}

_IP_KEYS = (
    "ABUSEIPDB_API_KEY",
    "VT_API_KEY",
    "GREYNOISE_API_KEY",
    "SHODAN_API_KEY",
)


@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch):
    monkeypatch.setenv("MOCK", "1")
    for key in _IP_KEYS:
        monkeypatch.setenv(key, "test-key")
    server._CACHE._entries.clear()
    server._LIMITERS.clear()
    yield
    server._CACHE._entries.clear()
    server._LIMITERS.clear()


async def test_investigate_ipapi_shape():
    response = await server.investigate("ip", "1.2.3.4", ["ipapi"])
    assert set(response) == _EXPECTED_KEYS
    assert response["input"] == "1.2.3.4"
    assert response["type"] == "ip"
    assert response["queried"] == ["ipapi"]
    assert response["skipped"] == []
    assert response["results"][0]["source"] == "ipapi"
    assert response["results"][0]["ok"] is True
    assert response["verdict"] in VERDICTS
    assert response["severity"] in SEVERITIES


async def test_cache_hit_and_distinct_key():
    first = await server.investigate("ip", "1.2.3.4", ["ipapi"])
    second = await server.investigate("ip", "1.2.3.4", ["ipapi"])
    assert first["retrieved_at"] == second["retrieved_at"]

    unfiltered = await server.investigate("ip", "1.2.3.4")
    assert unfiltered["retrieved_at"] != first["retrieved_at"]
    assert set(unfiltered["queried"]) > set(first["queried"])
    assert "ipapi" in unfiltered["queried"]


@pytest.mark.parametrize(
    "tool,value",
    [
        ("ip", "not-an-ip"),
        ("url", "ftp://x"),
        ("cve", "CVE-21-1"),
    ],
)
async def test_invalid_inputs_raise_value_error(tool, value):
    with pytest.raises(ValueError):
        await server.investigate(tool, value)


async def test_unknown_provider():
    response = await server.investigate("ip", "1.2.3.4", ["nope"])
    assert response["queried"] == []
    assert {"provider": "nope", "reason": "unknown provider"} in response["skipped"]
    assert response["verdict"] == "unknown"


async def test_run_with_limit_retry_exception_caught():
    server._LIMITERS["flaky"] = RateLimiter(1000.0)
    calls = {"n": 0}

    async def _run(value):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RateLimited("first attempt")
        raise RuntimeError("boom on retry")

    provider = _StubProvider("flaky", "ip", _run)
    result = await server._run_with_limit(provider, "1.2.3.4")
    assert calls["n"] == 2
    assert result.ok is False
    assert result.verdict == "error"
    assert result.error == "boom on retry"


async def test_investigate_survives_provider_retry_exception(monkeypatch):
    server._LIMITERS["flaky"] = RateLimiter(1000.0)
    calls = {"n": 0}

    async def _flaky(value):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RateLimited("first attempt")
        raise RuntimeError("boom on retry")

    async def _good(value):
        return ProviderResult(
            source="good",
            ok=True,
            verdict="benign",
            severity="none",
            summary="good",
            data={},
            error=None,
            retrieved_at=now_iso(),
        )

    flaky = _StubProvider("flaky", "ip", _flaky)
    good = _StubProvider("good", "ip", _good)
    monkeypatch.setattr(providers_pkg, "PROVIDERS", [flaky, good])

    response = await server.investigate("ip", "1.2.3.4", ["flaky", "good"])
    assert set(response) == _EXPECTED_KEYS
    assert response["queried"] == ["flaky", "good"]
    assert response["results"][0]["ok"] is False
    assert response["results"][0]["error"] == "boom on retry"
    assert response["results"][1]["ok"] is True
    assert response["results"][1]["source"] == "good"


async def test_lookup_cve_nvd_mock():
    response = await server.lookup_cve("CVE-2021-44228", ["nvd"])
    assert response["type"] == "cve"
    assert response["queried"] == ["nvd"]
    result = response["results"][0]
    assert result["ok"] is True
    assert result["severity"] == "critical"
    assert result["summary"] == "CVSS 9.8"
    assert response["severity"] == "critical"
    assert response["verdict"] == "malicious"
