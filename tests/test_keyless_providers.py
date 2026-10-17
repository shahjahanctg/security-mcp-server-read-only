import httpx
import pytest

from providers import PROVIDERS
from providers._cvss import from_cvss, from_qualitative
from providers.base import RateLimited, not_found_result
from providers.ipapi import IpApi
from providers.mitre_cve import MitreCve
from providers.nvd import Nvd
from providers.osv import Osv
from providers.urlscan import UrlScan

ALL_PROVIDERS = [IpApi(), UrlScan(), Nvd(), MitreCve(), Osv()]


class FakeResponse:
    def __init__(self, status_code: int, payload: dict | None = None):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}
        self._httpx_response = httpx.Response(
            status_code, request=httpx.Request("GET", "https://example.invalid/")
        )

    def json(self) -> dict:
        return self._payload

    def raise_for_status(self) -> None:
        self._httpx_response.raise_for_status()


class FakeClient:
    def __init__(self, response: FakeResponse):
        self.response = response
        self.calls: list[tuple[str, dict]] = []

    async def get(self, url: str, **kwargs) -> FakeResponse:
        self.calls.append((url, kwargs))
        return self.response


def _patch_client(monkeypatch, provider, response: FakeResponse) -> FakeClient:
    client = FakeClient(response)
    monkeypatch.setattr(f"{type(provider).__module__}.get_client", lambda: client)
    return client


IPAPI_CANONICAL_RAW = {
    "status": "success",
    "country": "United States",
    "regionName": "California",
    "city": "Mountain View",
    "isp": "Google LLC",
    "org": "Google Public DNS",
    "as": "AS15169 Google LLC",
    "query": "8.8.8.8",
}

URLSCAN_CANONICAL_RAW = {
    "total": 1,
    "results": [
        {
            "score": 0,
            "task": {"time": "2024-01-01T00:00:00.000Z"},
            "page": {"domain": "example.com"},
            "verdicts": {"overall": {"malicious": False}},
        }
    ],
}

NVD_CANONICAL_RAW = {
    "totalResults": 1,
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2024-1234",
                "published": "2024-03-01T00:00:00.000",
                "descriptions": [
                    {"lang": "es", "value": "no ingles"},
                    {"lang": "en", "value": "A remote code execution flaw."},
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 9.8,
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            }
                        }
                    ]
                },
                "references": [
                    {"url": "https://example.com/advisory"},
                    {"url": "https://example.org/patch"},
                ],
                "weaknesses": [
                    {"description": [{"lang": "en", "value": "CWE-79"}]},
                    {"description": [{"lang": "en", "value": "NVD-CWE-Other"}]},
                ],
            }
        }
    ],
}

MITRE_CANONICAL_RAW = {
    "cveMetadata": {
        "cveId": "CVE-2024-1234",
        "datePublished": "2024-02-01T00:00:00.000Z",
    },
    "containers": {
        "cna": {
            "descriptions": [{"lang": "en", "value": "A local privilege escalation issue."}],
            "metrics": [
                {
                    "cvssV3_1": {
                        "baseScore": 5.0,
                        "vectorString": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
                    }
                }
            ],
        }
    },
}

OSV_CANONICAL_RAW = {
    "id": "GHSA-xxxx-yyyy-zzzz",
    "summary": "Package mishandles untrusted input",
    "aliases": ["CVE-2024-1234"],
    "published": "2024-01-01T00:00:00Z",
    "modified": "2024-02-01T00:00:00Z",
    "database_specific": {"severity": "HIGH"},
}


def test_from_cvss_boundaries():
    assert from_cvss(None) == ("unknown", "unknown")
    assert from_cvss(9.8) == ("malicious", "critical")
    assert from_cvss(9.0) == ("malicious", "critical")
    assert from_cvss(7.0) == ("malicious", "high")
    assert from_cvss(4.0) == ("suspicious", "medium")
    assert from_cvss(0.1) == ("suspicious", "low")
    assert from_cvss(0) == ("benign", "none")


def test_from_qualitative_labels():
    assert from_qualitative("CRITICAL") == ("malicious", "critical")
    assert from_qualitative("high") == ("malicious", "high")
    assert from_qualitative("MODERATE") == ("suspicious", "medium")
    assert from_qualitative("medium") == ("suspicious", "medium")
    assert from_qualitative("LOW") == ("benign", "low")
    assert from_qualitative("bogus") == ("unknown", "unknown")
    assert from_qualitative(None) == ("unknown", "unknown")


def test_not_found_result_shape():
    result = not_found_result("nvd")

    assert result.source == "nvd"
    assert result.ok is False
    assert result.verdict == "unknown"
    assert result.severity == "unknown"
    assert result.summary == "nvd: not found"
    assert result.data == {}
    assert result.error == "not_found"
    assert result.retrieved_at.endswith("Z")


@pytest.mark.parametrize("provider", ALL_PROVIDERS, ids=lambda p: p.name)
def test_available_is_true_without_keys(provider, monkeypatch):
    monkeypatch.delenv("URLSCAN_API_KEY", raising=False)
    monkeypatch.delenv("NVD_API_KEY", raising=False)

    assert provider.env_key is None
    assert provider.available() is True


@pytest.mark.parametrize("provider", ALL_PROVIDERS, ids=lambda p: p.name)
def test_mock_raw_is_non_empty_dict(provider):
    raw = provider.mock_raw("probe-value")

    assert isinstance(raw, dict)
    assert raw


@pytest.mark.parametrize("provider", ALL_PROVIDERS, ids=lambda p: p.name)
def test_normalize_not_found_payload(provider):
    result = provider.normalize("probe-value", {"not_found": True})

    assert result.ok is False
    assert result.error == "not_found"
    assert result.verdict == "unknown"
    assert result.severity == "unknown"


@pytest.mark.parametrize("provider", ALL_PROVIDERS, ids=lambda p: p.name)
async def test_fetch_returns_not_found_on_404(provider, monkeypatch):
    client = _patch_client(monkeypatch, provider, FakeResponse(404))

    result = await provider.fetch("probe-value")

    assert result == {"not_found": True}
    assert len(client.calls) == 1


@pytest.mark.parametrize("provider", ALL_PROVIDERS, ids=lambda p: p.name)
async def test_fetch_raises_rate_limited_on_429(provider, monkeypatch):
    _patch_client(monkeypatch, provider, FakeResponse(429))

    with pytest.raises(RateLimited):
        await provider.fetch("probe-value")


@pytest.mark.parametrize("provider", ALL_PROVIDERS, ids=lambda p: p.name)
async def test_fetch_raises_on_non_404_http_error(provider, monkeypatch):
    _patch_client(monkeypatch, provider, FakeResponse(500))

    with pytest.raises(httpx.HTTPStatusError):
        await provider.fetch("probe-value")


def test_ipapi_normalize_canonical():
    result = IpApi().normalize("8.8.8.8", IPAPI_CANONICAL_RAW)

    assert result.ok is True
    assert result.source == "ipapi"
    assert result.verdict == "benign"
    assert result.severity == "none"
    assert result.summary == "Mountain View, United States (Google LLC)"
    assert result.error is None
    assert set(result.data) == {"country", "regionName", "city", "isp", "org", "as"}
    assert result.data == {
        "country": "United States",
        "regionName": "California",
        "city": "Mountain View",
        "isp": "Google LLC",
        "org": "Google Public DNS",
        "as": "AS15169 Google LLC",
    }


def test_ipapi_normalize_failure_status():
    result = IpApi().normalize("1.2.3.4", {"status": "fail", "message": "invalid query"})

    assert result.ok is False
    assert result.verdict == "error"
    assert result.severity == "unknown"
    assert result.summary == "ipapi lookup failed"
    assert result.data == {"message": "invalid query"}
    assert result.error == "invalid query"


def test_urlscan_normalize_canonical():
    result = UrlScan().normalize("https://example.com/", URLSCAN_CANONICAL_RAW)

    assert result.ok is True
    assert result.source == "urlscan"
    assert (result.verdict, result.severity) == ("unknown", "none")
    assert result.summary == "1 urlscan result(s)"
    assert result.error is None
    assert set(result.data) == {"total", "last_task_time", "top_score", "domains"}
    assert result.data["total"] == 1
    assert result.data["last_task_time"] == "2024-01-01T00:00:00.000Z"
    assert result.data["top_score"] == 0
    assert result.data["domains"] == ["example.com"]


def test_urlscan_normalize_malicious_hit():
    raw = {
        "total": 2,
        "results": [
            {
                "score": 10,
                "task": {"time": "2024-05-01T00:00:00.000Z"},
                "page": {"domain": "bad.example"},
                "verdicts": {"overall": {"malicious": True}},
            },
            {
                "score": 1,
                "task": {"time": "2024-04-01T00:00:00.000Z"},
                "page": {"domain": "other.example"},
                "verdicts": {"overall": {"malicious": False}},
            },
        ],
    }

    result = UrlScan().normalize("https://bad.example/", raw)

    assert result.ok is True
    assert (result.verdict, result.severity) == ("malicious", "high")
    assert result.summary == "2 urlscan result(s)"
    assert set(result.data) == {"total", "last_task_time", "top_score", "domains"}
    assert result.data["total"] == 2
    assert result.data["top_score"] == 10
    assert result.data["domains"] == ["bad.example", "other.example"]


def test_urlscan_normalize_empty_results():
    result = UrlScan().normalize("https://example.com/", {"total": 0, "results": []})

    assert result.ok is True
    assert (result.verdict, result.severity) == ("benign", "none")
    assert result.summary == "No urlscan results"
    assert result.data == {
        "total": 0,
        "last_task_time": None,
        "top_score": None,
        "domains": [],
    }


def test_nvd_normalize_canonical():
    result = Nvd().normalize("CVE-2024-1234", NVD_CANONICAL_RAW)

    assert result.ok is True
    assert result.source == "nvd"
    assert (result.verdict, result.severity) == ("malicious", "critical")
    assert result.summary == "CVSS 9.8"
    assert result.error is None
    assert set(result.data) == {"cvss", "vector", "published", "description", "references", "cwe"}
    assert result.data["cvss"] == 9.8
    assert result.data["vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert result.data["published"] == "2024-03-01T00:00:00.000"
    assert result.data["description"] == "A remote code execution flaw."
    assert result.data["references"] == [
        "https://example.com/advisory",
        "https://example.org/patch",
    ]
    assert result.data["cwe"] == ["CWE-79"]


def test_nvd_normalize_zero_results_is_not_found():
    result = Nvd().normalize("CVE-2024-0000", {"totalResults": 0})

    assert result.ok is False
    assert result.source == "nvd"
    assert result.error == "not_found"
    assert result.verdict == "unknown"
    assert result.severity == "unknown"


def test_mitre_cve_normalize_canonical():
    result = MitreCve().normalize("CVE-2024-1234", MITRE_CANONICAL_RAW)

    assert result.ok is True
    assert result.source == "mitre_cve"
    assert (result.verdict, result.severity) == ("suspicious", "medium")
    assert result.summary == "CVSS 5.0"
    assert result.error is None
    assert set(result.data) == {"cvss", "vector", "description", "datePublished"}
    assert result.data["cvss"] == 5.0
    assert result.data["vector"] == "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N"
    assert result.data["description"] == "A local privilege escalation issue."
    assert result.data["datePublished"] == "2024-02-01T00:00:00.000Z"


def test_osv_normalize_canonical():
    result = Osv().normalize("GHSA-xxxx-yyyy-zzzz", OSV_CANONICAL_RAW)

    assert result.ok is True
    assert result.source == "osv"
    assert (result.verdict, result.severity) == ("malicious", "high")
    assert result.summary == "OSV severity: HIGH"
    assert result.error is None
    assert set(result.data) == {"summary", "aliases", "published", "modified"}
    assert result.data == {
        "summary": "Package mishandles untrusted input",
        "aliases": ["CVE-2024-1234"],
        "published": "2024-01-01T00:00:00Z",
        "modified": "2024-02-01T00:00:00Z",
    }


def test_osv_normalize_unknown_severity():
    raw = {**OSV_CANONICAL_RAW, "database_specific": {}}

    result = Osv().normalize("GHSA-xxxx-yyyy-zzzz", raw)

    assert (result.verdict, result.severity) == ("unknown", "unknown")
    assert result.summary == "OSV severity: unknown"


def test_keyless_providers_are_registered():
    by_name = {p.name: p for p in PROVIDERS}

    assert {"ipapi", "urlscan", "nvd", "mitre_cve", "osv"} <= set(by_name)
    assert by_name["ipapi"].tool == "ip"
    assert by_name["urlscan"].tool == "url"
    assert by_name["nvd"].tool == "cve"
    assert by_name["mitre_cve"].tool == "cve"
    assert by_name["osv"].tool == "cve"
    assert all(p.env_key is None for p in (by_name["ipapi"], by_name["urlscan"], by_name["nvd"], by_name["mitre_cve"], by_name["osv"]))
