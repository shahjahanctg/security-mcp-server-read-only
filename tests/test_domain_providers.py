from datetime import datetime, timedelta, timezone

import httpx
import pytest

from providers import PROVIDERS
from providers._otx import OTX_BASE, verdict_from_pulses
from providers.base import RateLimited
from providers.crtsh import CrtSh
from providers.dns_records import DnsRecords
from providers.otx_domain import OtxDomain
from providers.rdap import Rdap

ALL_PROVIDERS = [Rdap(), DnsRecords(), CrtSh(), OtxDomain()]
MODULES = {
    "rdap": "providers.rdap",
    "dns": "providers.dns_records",
    "crtsh": "providers.crtsh",
    "otx_domain": "providers._otx",
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


def _recent_iso(days: int) -> str:
    stamp = datetime.now(timezone.utc) - timedelta(days=days)
    return stamp.strftime("%Y-%m-%dT%H:%M:%SZ")


RDAP_CANONICAL_RAW = {
    "ldhName": "example.com",
    "status": ["client transfer prohibited"],
    "secureDNS": {"delegationSigned": False},
    "nameservers": [
        {"ldhName": "A.IANA-SERVERS.NET"},
        {"ldhName": "B.IANA-SERVERS.NET"},
        {"objectClassName": "nameserver"},
    ],
    "entities": [
        {
            "roles": ["technical"],
            "vcardArray": ["vcard", [["fn", {}, "text", "Tech Contact"]]],
        },
        {
            "roles": ["registrar"],
            "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]],
        },
    ],
    "events": [
        {"eventAction": "expiration", "eventDate": "2030-01-01T00:00:00Z"},
        {"eventAction": "last changed", "eventDate": "2024-01-01T00:00:00Z"},
        {"eventAction": "registration", "eventDate": _recent_iso(5)},
    ],
}

DNS_CANONICAL_RAW = {
    "A": ["93.184.216.34", "1.2.3.4"],
    "MX": ["0 ."],
    "NS": ["a.iana-servers.net"],
    "TXT": ["v=spf1 -all"],
}

CRTSH_CANONICAL_RAW = [
    {"name_value": "www.example.com\napi.example.com\nwww.example.com"},
    {"name_value": "example.com"},
    {"name_value": "mail.other.com"},
]

OTX_DOMAIN_CANONICAL_RAW = {
    "general": {
        "pulse_info": {"count": 2},
        "validation": [{"source": "alienvault", "name": "malware"}],
    },
    "passive_dns": {
        "passive_dns": [
            {"address": "93.184.216.34"},
            {"address": "93.184.216.34"},
            {"address": "203.0.113.7"},
        ]
    },
}


def test_verdict_from_pulses():
    assert verdict_from_pulses(0) == ("benign", "none")
    assert verdict_from_pulses(1) == ("suspicious", "medium")
    assert verdict_from_pulses(7) == ("suspicious", "medium")


def test_otx_base_constant():
    assert OTX_BASE == "https://otx.alienvault.com/api/v1/indicators/"


@pytest.mark.parametrize("provider", ALL_PROVIDERS, ids=lambda p: p.name)
def test_env_key_none_and_available(provider):
    assert provider.env_key is None
    assert provider.available() is True


@pytest.mark.parametrize("provider", ALL_PROVIDERS, ids=lambda p: p.name)
def test_mock_raw_is_non_empty(provider):
    raw = provider.mock_raw("example.com")

    assert raw
    assert isinstance(raw, (dict, list))


@pytest.mark.parametrize("provider", ALL_PROVIDERS, ids=lambda p: p.name)
def test_normalize_not_found_payload(provider):
    result = provider.normalize("example.com", {"not_found": True})

    assert result.ok is False
    assert result.error == "not_found"
    assert result.verdict == "unknown"
    assert result.severity == "unknown"


@pytest.mark.parametrize("provider", ALL_PROVIDERS, ids=lambda p: p.name)
async def test_fetch_returns_not_found_on_404(provider, monkeypatch):
    client = _patch_client(monkeypatch, provider, FakeResponse(404))

    result = await provider.fetch("example.com")

    assert result == {"not_found": True}
    assert len(client.calls) == 1


@pytest.mark.parametrize("provider", ALL_PROVIDERS, ids=lambda p: p.name)
async def test_fetch_raises_rate_limited_on_429(provider, monkeypatch):
    _patch_client(monkeypatch, provider, FakeResponse(429))

    with pytest.raises(RateLimited):
        await provider.fetch("example.com")


@pytest.mark.parametrize("provider", ALL_PROVIDERS, ids=lambda p: p.name)
async def test_fetch_raises_on_non_404_http_error(provider, monkeypatch):
    _patch_client(monkeypatch, provider, FakeResponse(500))

    with pytest.raises(httpx.HTTPStatusError):
        await provider.fetch("example.com")


async def test_rdap_fetch_uses_follow_redirects(monkeypatch):
    payload = {"ldhName": "example.com"}
    client = _patch_client(monkeypatch, Rdap(), FakeResponse(200, payload))

    result = await Rdap().fetch("example.com")

    assert result == payload
    url, kwargs = client.calls[0]
    assert url == "https://rdap.org/domain/example.com"
    assert kwargs.get("follow_redirects") is True


def test_rdap_normalize_recent_registration_is_suspicious():
    result = Rdap().normalize("example.com", RDAP_CANONICAL_RAW)

    assert result.ok is True
    assert result.source == "rdap"
    assert (result.verdict, result.severity) == ("suspicious", "medium")
    assert result.error is None
    assert set(result.data) == {
        "registrar",
        "created",
        "expires",
        "updated",
        "statuses",
        "nameservers",
        "dnssec",
        "age_days",
    }
    assert result.data["registrar"] == "Example Registrar"
    assert result.data["expires"] == "2030-01-01T00:00:00Z"
    assert result.data["updated"] == "2024-01-01T00:00:00Z"
    assert result.data["statuses"] == ["client transfer prohibited"]
    assert result.data["nameservers"] == ["A.IANA-SERVERS.NET", "B.IANA-SERVERS.NET"]
    assert result.data["dnssec"] is False
    assert result.data["age_days"] == 5


def test_rdap_normalize_old_registration_is_benign():
    raw = {
        **RDAP_CANONICAL_RAW,
        "events": [
            {"eventAction": "registration", "eventDate": _recent_iso(400)},
        ],
    }

    result = Rdap().normalize("example.com", raw)

    assert (result.verdict, result.severity) == ("benign", "none")
    assert result.data["age_days"] == 400


def test_rdap_normalize_summary_and_missing_data():
    raw = {"events": [], "entities": [], "nameservers": []}

    result = Rdap().normalize("example.com", raw)

    assert (result.verdict, result.severity) == ("benign", "none")
    assert result.data["registrar"] is None
    assert result.data["created"] is None
    assert result.data["age_days"] is None
    assert result.summary == "unknown registrar — registered unknown"


def test_dns_normalize_canonical():
    result = DnsRecords().normalize("example.com", DNS_CANONICAL_RAW)

    assert result.ok is True
    assert result.source == "dns"
    assert (result.verdict, result.severity) == ("benign", "none")
    assert result.summary == "A:2 MX:1 NS:1 TXT:1"
    assert set(result.data) == {"a", "mx", "ns", "txt"}
    assert result.data["a"] == ["93.184.216.34", "1.2.3.4"]
    assert result.data["mx"] == ["0 ."]
    assert result.data["ns"] == ["a.iana-servers.net"]
    assert result.data["txt"] == ["v=spf1 -all"]


def test_crtsh_normalize_dedupes_filters_sorts():
    result = CrtSh().normalize("example.com", CRTSH_CANONICAL_RAW)

    assert result.ok is True
    assert result.source == "crtsh"
    assert (result.verdict, result.severity) == ("benign", "none")
    assert result.summary == "3 subdomain(s) in CT logs"
    assert set(result.data) == {"subdomain_count", "subdomains"}
    assert result.data["subdomain_count"] == 3
    assert result.data["subdomains"] == [
        "api.example.com",
        "example.com",
        "www.example.com",
    ]


def test_crtsh_normalize_caps_at_fifty():
    entries = [{"name_value": f"h{i}.example.com"} for i in range(60)]

    result = CrtSh().normalize("example.com", entries)

    assert result.data["subdomain_count"] == 60
    assert len(result.data["subdomains"]) == 50


def test_otx_domain_normalize_with_pulses():
    result = OtxDomain().normalize("example.com", OTX_DOMAIN_CANONICAL_RAW)

    assert result.ok is True
    assert result.source == "otx_domain"
    assert (result.verdict, result.severity) == ("suspicious", "medium")
    assert result.summary == "OTX: 2 pulse(s)"
    assert set(result.data) == {"pulse_count", "validation", "passive_dns_ips"}
    assert result.data["pulse_count"] == 2
    assert result.data["passive_dns_ips"] == ["93.184.216.34", "203.0.113.7"]


def test_otx_domain_normalize_without_pulses():
    raw = {
        "general": {"pulse_info": {"count": 0}, "validation": []},
        "passive_dns": {"passive_dns": []},
    }

    result = OtxDomain().normalize("example.com", raw)

    assert (result.verdict, result.severity) == ("benign", "none")
    assert result.summary == "OTX: 0 pulse(s)"
    assert result.data["passive_dns_ips"] == []


def test_domain_providers_are_registered():
    by_name = {p.name: p for p in PROVIDERS}

    assert {"rdap", "dns", "crtsh", "otx_domain"} <= set(by_name)
    for name in ("rdap", "dns", "crtsh", "otx_domain"):
        assert by_name[name].tool == "domain"
        assert by_name[name].env_key is None
