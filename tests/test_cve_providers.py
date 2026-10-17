import httpx
import pytest

from core.feed import FeedCache
from providers import PROVIDERS
from providers.base import RateLimited
from providers.circl import Circl
from providers.cisa_kev import CisaKev
from providers.epss import Epss

ALL_PROVIDERS = [Epss(), CisaKev(), Circl()]
HTTP_PROVIDERS = [Epss(), Circl()]
MODULES = {
    "epss": "providers.epss",
    "cisa_kev": "providers.cisa_kev",
    "circl": "providers.circl",
}

CVE = "CVE-2021-44228"


class FakeResponse:
    def __init__(self, status_code: int, payload: object | None = None):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}
        self._httpx_response = httpx.Response(
            status_code, request=httpx.Request("GET", "https://example.invalid/")
        )

    def json(self) -> object:
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
    monkeypatch.setattr(f"{MODULES[provider.name]}.get_client", lambda: client)
    return client


def _patch_kev(monkeypatch, response: FakeResponse) -> FakeClient:
    client = FakeClient(response)
    monkeypatch.setattr("providers.cisa_kev.get_client", lambda: client)
    monkeypatch.setattr("providers.cisa_kev._KEV_FEED", FeedCache(ttl=21600))
    return client


EPSS_CANONICAL_RAW = {
    "data": [
        {
            "cve": CVE,
            "epss": "0.97",
            "percentile": "0.99",
            "date": "2026-01-01",
        }
    ]
}

KEV_ENTRY = {
    "cveID": CVE,
    "dateAdded": "2021-12-10",
    "dueDate": "2021-12-24",
    "knownRansomwareCampaignUse": "Known",
    "requiredAction": "Apply updates",
    "vendorProject": "Apache",
    "product": "Log4j2",
}

KEV_FEED_PAYLOAD = {"vulnerabilities": [KEV_ENTRY]}

CIRCL_CANONICAL_RAW = {
    "cvss": 9.8,
    "cvss-vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "summary": "Critical remote code execution.",
    "references": ["https://example.com/advisory"],
    "Published": "2021-12-10T00:00:00",
}


@pytest.mark.parametrize("provider", ALL_PROVIDERS, ids=lambda p: p.name)
def test_env_key_none_and_available(provider):
    assert provider.env_key is None
    assert provider.available() is True
    assert provider.tool == "cve"


@pytest.mark.parametrize("provider", ALL_PROVIDERS, ids=lambda p: p.name)
def test_mock_raw_is_non_empty_dict(provider):
    raw = provider.mock_raw(CVE)

    assert isinstance(raw, dict)
    assert raw


@pytest.mark.parametrize("provider", HTTP_PROVIDERS, ids=lambda p: p.name)
def test_normalize_not_found_payload(provider):
    result = provider.normalize(CVE, {"not_found": True})

    assert result.ok is False
    assert result.error == "not_found"
    assert result.verdict == "unknown"
    assert result.severity == "unknown"


@pytest.mark.parametrize("provider", HTTP_PROVIDERS, ids=lambda p: p.name)
async def test_fetch_returns_not_found_on_404(provider, monkeypatch):
    client = _patch_client(monkeypatch, provider, FakeResponse(404))

    result = await provider.fetch(CVE)

    assert result == {"not_found": True}
    assert len(client.calls) == 1


@pytest.mark.parametrize("provider", HTTP_PROVIDERS, ids=lambda p: p.name)
async def test_fetch_raises_rate_limited_on_429(provider, monkeypatch):
    _patch_client(monkeypatch, provider, FakeResponse(429))

    with pytest.raises(RateLimited):
        await provider.fetch(CVE)


@pytest.mark.parametrize("provider", HTTP_PROVIDERS, ids=lambda p: p.name)
async def test_fetch_raises_on_non_404_http_error(provider, monkeypatch):
    _patch_client(monkeypatch, provider, FakeResponse(500))

    with pytest.raises(httpx.HTTPStatusError):
        await provider.fetch(CVE)


async def test_epss_fetch_sends_cve_param(monkeypatch):
    client = _patch_client(monkeypatch, Epss(), FakeResponse(200, EPSS_CANONICAL_RAW))

    result = await Epss().fetch(CVE)

    assert result == EPSS_CANONICAL_RAW
    url, kwargs = client.calls[0]
    assert url == "https://api.first.org/data/v1/epss"
    assert kwargs.get("params") == {"cve": CVE}


def test_epss_normalize_canonical():
    result = Epss().normalize(CVE, EPSS_CANONICAL_RAW)

    assert result.ok is True
    assert result.source == "epss"
    assert result.verdict == "unknown"
    assert result.severity == "medium"
    assert result.error is None
    assert result.summary == "EPSS 0.970"
    assert set(result.data) == {"epss", "percentile", "date"}
    assert result.data["epss"] == 0.97
    assert result.data["percentile"] == "0.99"
    assert result.data["date"] == "2026-01-01"


def test_epss_normalize_empty_data_is_not_found():
    result = Epss().normalize(CVE, {"data": []})

    assert result.ok is False
    assert result.error == "not_found"


def test_epss_normalize_severity_thresholds():
    low = Epss().normalize(CVE, {"data": [{"cve": CVE, "epss": "0.2"}]})
    none = Epss().normalize(CVE, {"data": [{"cve": CVE, "epss": "0.01"}]})

    assert low.severity == "low"
    assert low.verdict == "unknown"
    assert none.severity == "none"
    assert none.verdict == "unknown"


def test_epss_normalize_date_falls_back_to_top_level():
    raw = {"data": [{"cve": CVE, "epss": "0.5"}], "date": "2026-02-02"}

    result = Epss().normalize(CVE, raw)

    assert result.data["date"] == "2026-02-02"


def test_epss_mock_raw_normalizes():
    provider = Epss()

    result = provider.normalize(CVE, provider.mock_raw(CVE))

    assert result.ok is True
    assert result.severity == "medium"


async def test_cisa_kev_fetch_returns_entry_for_listed_cve(monkeypatch):
    _patch_kev(monkeypatch, FakeResponse(200, KEV_FEED_PAYLOAD))

    result = await CisaKev().fetch(CVE)

    assert result == {"entry": KEV_ENTRY}


async def test_cisa_kev_fetch_returns_none_entry_for_absent_cve(monkeypatch):
    _patch_kev(monkeypatch, FakeResponse(200, KEV_FEED_PAYLOAD))

    result = await CisaKev().fetch("CVE-1999-0001")

    assert result == {"entry": None}


async def test_cisa_kev_feed_fetched_once_across_lookups(monkeypatch):
    client = _patch_kev(monkeypatch, FakeResponse(200, KEV_FEED_PAYLOAD))
    provider = CisaKev()

    present = await provider.fetch(CVE)
    absent = await provider.fetch("CVE-1999-0001")

    assert present == {"entry": KEV_ENTRY}
    assert absent == {"entry": None}
    assert len(client.calls) == 1


async def test_cisa_kev_fetch_raises_rate_limited_on_feed_429(monkeypatch):
    _patch_kev(monkeypatch, FakeResponse(429))

    with pytest.raises(RateLimited):
        await CisaKev().fetch(CVE)


async def test_cisa_kev_fetch_raises_on_feed_500(monkeypatch):
    _patch_kev(monkeypatch, FakeResponse(500))

    with pytest.raises(httpx.HTTPStatusError):
        await CisaKev().fetch(CVE)


def test_cisa_kev_normalize_listed():
    result = CisaKev().normalize(CVE, {"entry": KEV_ENTRY})

    assert result.ok is True
    assert result.source == "cisa_kev"
    assert (result.verdict, result.severity) == ("malicious", "high")
    assert result.error is None
    assert result.summary == "KEV: Apache Log4j2"
    assert set(result.data) == {
        "listed",
        "dateAdded",
        "dueDate",
        "knownRansomwareCampaignUse",
        "requiredAction",
        "vendorProject",
        "product",
    }
    assert result.data == {
        "listed": True,
        "dateAdded": "2021-12-10",
        "dueDate": "2021-12-24",
        "knownRansomwareCampaignUse": "Known",
        "requiredAction": "Apply updates",
        "vendorProject": "Apache",
        "product": "Log4j2",
    }


def test_cisa_kev_normalize_absent():
    result = CisaKev().normalize(CVE, {"entry": None})

    assert result.ok is True
    assert (result.verdict, result.severity) == ("benign", "none")
    assert result.summary == "Not in CISA KEV catalog"
    assert set(result.data) == {
        "listed",
        "dateAdded",
        "dueDate",
        "knownRansomwareCampaignUse",
        "requiredAction",
        "vendorProject",
        "product",
    }
    assert result.data == {
        "listed": False,
        "dateAdded": None,
        "dueDate": None,
        "knownRansomwareCampaignUse": None,
        "requiredAction": None,
        "vendorProject": None,
        "product": None,
    }


def test_cisa_kev_mock_raw_normalizes():
    provider = CisaKev()

    result = provider.normalize(CVE, provider.mock_raw(CVE))

    assert result.ok is True
    assert (result.verdict, result.severity) == ("malicious", "high")
    assert result.data["listed"] is True


async def test_circl_fetch_returns_not_found_on_empty_json(monkeypatch):
    _patch_client(monkeypatch, Circl(), FakeResponse(200, {}))

    result = await Circl().fetch(CVE)

    assert result == {"not_found": True}


async def test_circl_fetch_returns_payload(monkeypatch):
    _patch_client(monkeypatch, Circl(), FakeResponse(200, CIRCL_CANONICAL_RAW))

    result = await Circl().fetch(CVE)

    assert result == CIRCL_CANONICAL_RAW


def test_circl_normalize_canonical():
    result = Circl().normalize(CVE, CIRCL_CANONICAL_RAW)

    assert result.ok is True
    assert result.source == "circl"
    assert (result.verdict, result.severity) == ("malicious", "critical")
    assert result.error is None
    assert result.summary == "CVSS 9.8"
    assert set(result.data) == {"cvss", "vector", "summary", "references", "published"}
    assert result.data == {
        "cvss": 9.8,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "summary": "Critical remote code execution.",
        "references": ["https://example.com/advisory"],
        "published": "2021-12-10T00:00:00",
    }


def test_circl_normalize_caps_summary_and_references():
    raw = {
        "cvss": 5.0,
        "summary": "x" * 600,
        "references": [f"https://example.com/{i}" for i in range(10)],
    }

    result = Circl().normalize(CVE, raw)

    assert len(result.data["summary"]) == 500
    assert len(result.data["references"]) == 5


def test_circl_normalize_missing_score():
    result = Circl().normalize(CVE, {"summary": "no score"})

    assert result.summary == "No CVSS score"
    assert result.data["cvss"] is None
    assert result.data["published"] is None


def test_circl_normalize_empty_payload_is_not_found():
    for raw in ({}, None):
        result = Circl().normalize(CVE, raw)

        assert result.ok is False
        assert result.error == "not_found"


def test_circl_mock_raw_normalizes():
    provider = Circl()

    result = provider.normalize(CVE, provider.mock_raw(CVE))

    assert result.ok is True
    assert (result.verdict, result.severity) == ("malicious", "critical")


def test_cve_providers_are_registered():
    by_name = {p.name: p for p in PROVIDERS}

    assert {"epss", "cisa_kev", "circl"} <= set(by_name)
    for name in ("epss", "cisa_kev", "circl"):
        assert by_name[name].tool == "cve"
        assert by_name[name].env_key is None
