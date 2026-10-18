import asyncio

import httpx
import pytest

from server import investigate

_NETWORK_MARKERS = (
    "connect",
    "timed out",
    "timeout",
    "unreachable",
    "name or service",
    "temporary failure",
    "getaddrinfo",
    "resolve",
    "network",
)


def _is_network_unavailable(errors: str) -> bool:
    text = errors.lower()
    return any(marker in text for marker in _NETWORK_MARKERS)


def test_is_network_unavailable_matches_transport_errors():
    assert _is_network_unavailable("All connection attempts failed")
    assert _is_network_unavailable("timed out")
    assert _is_network_unavailable("[Errno -2] Name or service not known")
    assert _is_network_unavailable("Network is unreachable")
    assert _is_network_unavailable("Temporary failure in name resolution")
    assert not _is_network_unavailable("500 Internal Server Error")
    assert not _is_network_unavailable("invalid json response")


@pytest.mark.network
def test_live_cve_log4shell_keyless(monkeypatch):
    monkeypatch.delenv("MOCK", raising=False)
    monkeypatch.delenv("NVD_API_KEY", raising=False)

    try:
        response = asyncio.run(
            investigate("cve", "CVE-2021-44228", ["nvd", "mitre_cve", "osv"])
        )
    except httpx.HTTPError:
        pytest.skip("network unavailable")

    if all(not r["ok"] for r in response["results"]):
        errors = " ".join(r["error"] or "" for r in response["results"])
        if _is_network_unavailable(errors):
            pytest.skip("network unavailable")

    results = {r["source"]: r for r in response["results"]}
    assert sum(1 for r in response["results"] if r["ok"]) >= 2
    assert results["nvd"]["ok"] is True
    assert results["nvd"]["severity"] == "critical"
    assert results["nvd"]["verdict"] == "malicious"
    assert results["mitre_cve"]["ok"] is True
    assert results["mitre_cve"]["severity"] == "unknown"
    assert response["severity"] == "critical"
    assert response["verdict"] == "malicious"


@pytest.mark.network
def test_live_domain_example_com_keyless(monkeypatch):
    monkeypatch.delenv("MOCK", raising=False)

    try:
        response = asyncio.run(
            investigate(
                "domain", "example.com", ["rdap", "dns", "crtsh", "otx_domain"]
            )
        )
    except httpx.HTTPError:
        pytest.skip("network unavailable")

    if all(not r["ok"] for r in response["results"]):
        errors = " ".join(r["error"] or "" for r in response["results"])
        if _is_network_unavailable(errors):
            pytest.skip("network unavailable")

    assert response["type"] == "domain"
    assert response["input"] == "example.com"
    assert sum(1 for r in response["results"] if r["ok"]) >= 2
    assert response["verdict"] in ("benign", "suspicious", "malicious", "unknown")
