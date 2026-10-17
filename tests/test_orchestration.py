import pytest

import server
from core.schemas import SEVERITIES, VERDICTS

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
