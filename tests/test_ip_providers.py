import ipaddress

import httpx
import pytest

from providers import PROVIDERS
from providers.base import RateLimited
from providers.internetdb import InternetDb
from providers.ipinfo import IpInfo
from providers.otx_ip import OtxIp
from providers.reverse_dns import ReverseDns

ALL_PROVIDERS = [IpInfo(), InternetDb(), ReverseDns(), OtxIp()]
MODULES = {
    "ipinfo": "providers.ipinfo",
    "internetdb": "providers.internetdb",
    "reverse_dns": "providers.reverse_dns",
    "otx_ip": "providers._otx",
}


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


IPINFO_CANONICAL_RAW = {
    "city": "Mountain View",
    "region": "California",
    "country": "US",
    "org": "AS15169 Google LLC",
    "loc": "37.4,-122.1",
    "timezone": "America/Los_Angeles",
}

INTERNETDB_CANONICAL_RAW = {
    "ip": "8.8.8.8",
    "ports": [443, 80],
    "tags": ["cdn"],
    "hostnames": ["dns.google"],
    "cpes": ["cpe:/a:igor_sysoev:nginx"],
    "vulns": ["CVE-2019-1234"],
}

OTX_IP_CANONICAL_RAW = {
    "general": {
        "pulse_info": {"count": 3},
        "validation": [{"source": "alienvault", "name": "malware"}],
    },
    "passive_dns": {
        "passive_dns": [
            {"hostname": "dns.google"},
            {"hostname": "dns.google"},
            {"hostname": "mail.example"},
        ]
    },
}


@pytest.mark.parametrize("provider", ALL_PROVIDERS, ids=lambda p: p.name)
def test_env_key_none_and_available(provider):
    assert provider.env_key is None
    assert provider.available() is True


@pytest.mark.parametrize("provider", ALL_PROVIDERS, ids=lambda p: p.name)
def test_mock_raw_is_non_empty_dict(provider):
    raw = provider.mock_raw("8.8.8.8")

    assert isinstance(raw, dict)
    assert raw


@pytest.mark.parametrize("provider", ALL_PROVIDERS, ids=lambda p: p.name)
def test_normalize_not_found_payload(provider):
    result = provider.normalize("8.8.8.8", {"not_found": True})

    assert result.ok is False
    assert result.error == "not_found"
    assert result.verdict == "unknown"
    assert result.severity == "unknown"


@pytest.mark.parametrize("provider", ALL_PROVIDERS, ids=lambda p: p.name)
async def test_fetch_returns_not_found_on_404(provider, monkeypatch):
    client = _patch_client(monkeypatch, provider, FakeResponse(404))

    result = await provider.fetch("8.8.8.8")

    assert result == {"not_found": True}
    assert len(client.calls) >= 1


@pytest.mark.parametrize("provider", ALL_PROVIDERS, ids=lambda p: p.name)
async def test_fetch_raises_rate_limited_on_429(provider, monkeypatch):
    _patch_client(monkeypatch, provider, FakeResponse(429))

    with pytest.raises(RateLimited):
        await provider.fetch("8.8.8.8")


@pytest.mark.parametrize("provider", ALL_PROVIDERS, ids=lambda p: p.name)
async def test_fetch_raises_on_non_404_http_error(provider, monkeypatch):
    _patch_client(monkeypatch, provider, FakeResponse(500))

    with pytest.raises(httpx.HTTPStatusError):
        await provider.fetch("8.8.8.8")


def test_ipinfo_normalize_canonical():
    result = IpInfo().normalize("8.8.8.8", IPINFO_CANONICAL_RAW)

    assert result.ok is True
    assert result.source == "ipinfo"
    assert (result.verdict, result.severity) == ("benign", "none")
    assert result.error is None
    assert result.summary == "Mountain View, California, US (AS15169 Google LLC)"
    assert set(result.data) == {"city", "region", "country", "org", "loc", "timezone"}
    assert result.data == {
        "city": "Mountain View",
        "region": "California",
        "country": "US",
        "org": "AS15169 Google LLC",
        "loc": "37.4,-122.1",
        "timezone": "America/Los_Angeles",
    }


def test_ipinfo_normalize_error_payload_is_not_found():
    result = IpInfo().normalize("8.8.8.8", {"error": {"title": "RateLimited"}})

    assert result.ok is False
    assert result.error == "not_found"
    assert result.verdict == "unknown"
    assert result.severity == "unknown"


async def test_ipinfo_fetch_includes_token_when_set(monkeypatch):
    monkeypatch.setenv("IPINFO_TOKEN", "secret-token")
    client = _patch_client(monkeypatch, IpInfo(), FakeResponse(200, IPINFO_CANONICAL_RAW))

    await IpInfo().fetch("8.8.8.8")

    url, kwargs = client.calls[0]
    assert url == "https://ipinfo.io/8.8.8.8/json"
    assert kwargs.get("params") == {"token": "secret-token"}


async def test_ipinfo_fetch_omits_token_when_unset(monkeypatch):
    monkeypatch.delenv("IPINFO_TOKEN", raising=False)
    client = _patch_client(monkeypatch, IpInfo(), FakeResponse(200, IPINFO_CANONICAL_RAW))

    await IpInfo().fetch("8.8.8.8")

    url, kwargs = client.calls[0]
    assert url == "https://ipinfo.io/8.8.8.8/json"
    assert "token" not in (kwargs.get("params") or {})


def test_internetdb_normalize_with_vulns():
    result = InternetDb().normalize("8.8.8.8", INTERNETDB_CANONICAL_RAW)

    assert result.ok is True
    assert result.source == "internetdb"
    assert (result.verdict, result.severity) == ("unknown", "medium")
    assert result.error is None
    assert result.summary == "2 open port(s), 1 known vuln(s)"
    assert set(result.data) == {
        "ports",
        "tags",
        "hostnames",
        "cpes",
        "vulns_count",
        "vulns",
    }
    assert result.data["ports"] == [443, 80]
    assert result.data["tags"] == ["cdn"]
    assert result.data["hostnames"] == ["dns.google"]
    assert result.data["cpes"] == ["cpe:/a:igor_sysoev:nginx"]
    assert result.data["vulns_count"] == 1
    assert result.data["vulns"] == ["CVE-2019-1234"]


def test_internetdb_normalize_without_vulns():
    raw = {
        "ip": "8.8.8.8",
        "ports": [443],
        "tags": [],
        "hostnames": [],
        "cpes": [],
        "vulns": [],
    }

    result = InternetDb().normalize("8.8.8.8", raw)

    assert (result.verdict, result.severity) == ("unknown", "none")
    assert result.summary == "1 open port(s), 0 known vuln(s)"
    assert result.data["vulns_count"] == 0


def test_internetdb_normalize_caps_cpes_and_vulns():
    raw = {
        "ip": "8.8.8.8",
        "ports": [80],
        "tags": [],
        "hostnames": [],
        "cpes": [f"cpe:/a:vendor:{i}" for i in range(15)],
        "vulns": [f"CVE-2024-{i:04d}" for i in range(15)],
    }

    result = InternetDb().normalize("8.8.8.8", raw)

    assert len(result.data["cpes"]) == 10
    assert len(result.data["vulns"]) == 10
    assert result.data["vulns_count"] == 15


def test_internetdb_normalize_empty_payload():
    result = InternetDb().normalize("8.8.8.8", {})

    assert (result.verdict, result.severity) == ("unknown", "none")
    assert result.summary == "0 open port(s), 0 known vuln(s)"
    assert result.data["ports"] == []
    assert result.data["vulns_count"] == 0


async def test_reverse_dns_fetch_uses_reverse_pointer(monkeypatch):
    payload = {"Answer": [{"data": "dns.google"}]}
    client = _patch_client(monkeypatch, ReverseDns(), FakeResponse(200, payload))

    result = await ReverseDns().fetch("8.8.8.8")

    expected_name = ipaddress.ip_address("8.8.8.8").reverse_pointer
    assert result == {"ptr": ["dns.google"]}
    url, kwargs = client.calls[0]
    assert url == "https://dns.google/resolve"
    assert kwargs.get("params") == {"name": expected_name, "type": "PTR"}
    assert expected_name == "8.8.8.8.in-addr.arpa"


def test_reverse_dns_normalize_canonical():
    result = ReverseDns().normalize("8.8.8.8", {"ptr": ["dns.google"]})

    assert result.ok is True
    assert result.source == "reverse_dns"
    assert (result.verdict, result.severity) == ("benign", "none")
    assert result.error is None
    assert result.summary == "PTR: dns.google"
    assert set(result.data) == {"ptr"}
    assert result.data["ptr"] == ["dns.google"]


def test_reverse_dns_normalize_empty_ptr():
    result = ReverseDns().normalize("8.8.8.8", {"ptr": []})

    assert result.ok is True
    assert (result.verdict, result.severity) == ("benign", "none")
    assert result.summary == "No PTR record"
    assert result.data["ptr"] == []


def test_otx_ip_normalize_with_pulses():
    result = OtxIp().normalize("8.8.8.8", OTX_IP_CANONICAL_RAW)

    assert result.ok is True
    assert result.source == "otx_ip"
    assert (result.verdict, result.severity) == ("suspicious", "medium")
    assert result.error is None
    assert result.summary == "OTX: 3 pulse(s)"
    assert set(result.data) == {"pulse_count", "validation", "passive_dns_hostnames"}
    assert result.data["pulse_count"] == 3
    assert result.data["passive_dns_hostnames"] == ["dns.google", "mail.example"]


def test_otx_ip_normalize_without_pulses():
    raw = {
        "general": {"pulse_info": {"count": 0}, "validation": []},
        "passive_dns": {"passive_dns": []},
    }

    result = OtxIp().normalize("8.8.8.8", raw)

    assert (result.verdict, result.severity) == ("benign", "none")
    assert result.summary == "OTX: 0 pulse(s)"
    assert result.data["passive_dns_hostnames"] == []


async def test_otx_ip_fetch_combines_general_and_passive_dns(monkeypatch):
    payload = {
        "pulse_info": {"count": 1},
        "validation": [],
        "passive_dns": [{"hostname": "dns.google"}],
    }
    client = _patch_client(monkeypatch, OtxIp(), FakeResponse(200, payload))

    result = await OtxIp().fetch("8.8.8.8")

    assert result == {"general": payload, "passive_dns": payload}
    assert len(client.calls) == 2
    assert client.calls[0][0].endswith("IPv4/8.8.8.8/general")
    assert client.calls[1][0].endswith("IPv4/8.8.8.8/passive_dns")


def test_ip_providers_are_registered():
    by_name = {p.name: p for p in PROVIDERS}

    assert {"ipinfo", "internetdb", "reverse_dns", "otx_ip"} <= set(by_name)
    for name in ("ipinfo", "internetdb", "reverse_dns", "otx_ip"):
        assert by_name[name].tool == "ip"
        assert by_name[name].env_key is None
