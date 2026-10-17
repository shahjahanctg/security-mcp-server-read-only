import asyncio

import httpx
import pytest

from server import investigate

pytestmark = pytest.mark.network


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
        errors = " ".join(r["error"] or "" for r in response["results"]).lower()
        if "connect" in errors or "timed out" in errors:
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
