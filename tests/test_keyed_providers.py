import httpx
import pytest

from providers import PROVIDERS, for_tool
from providers.abuseipdb import AbuseIPDB
from providers.base import RateLimited, not_found_result
from providers.greynoise import GreyNoise
from providers.shodan import Shodan
from providers.virustotal import (
    VirusTotalIP,
    VirusTotalURL,
    url_id,
)


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


ABUSEIPDB_CANONICAL_RAW = {
    "data": {
        "abuseConfidenceScore": 0,
        "countryCode": "US",
        "isp": "Google LLC",
        "usageType": "Data Center/Web Hosting/Transit",
        "totalReports": 0,
    }
}

VIRUSTOTAL_IP_CANONICAL_RAW = {
    "data": {
        "attributes": {
            "reputation": 0,
            "last_analysis_stats": {"malicious": 0, "suspicious": 0},
            "country": "US",
            "as_owner": "Google LLC",
        }
    }
}

VIRUSTOTAL_URL_CANONICAL_RAW = {
    "data": {
        "attributes": {
            "last_final_url": "https://example.com/",
            "times_submitted": 1,
            "last_analysis_stats": {"malicious": 0, "suspicious": 0},
        }
    }
}

GREYNOISE_CANONICAL_RAW = {
    "ip": "8.8.8.8",
    "noise": False,
    "riot": True,
    "classification": "benign",
    "name": "Google",
    "link": "https://viz.greynoise.io/ip/8.8.8.8",
    "malicious": False,
}

SHODAN_CANONICAL_RAW = {
    "org": "Google LLC",
    "ports": [443],
    "hostnames": ["dns.google"],
    "vulns": {},
}


def test_url_id_basic():
    assert url_id("https://example.com/") == "aHR0cHM6Ly9leGFtcGxlLmNvbS8"
    assert url_id("https://example.com/a b") == "aHR0cHM6Ly9leGFtcGxlLmNvbS9hIGI"
    res = url_id("https://example.com/a b")
    assert "=" not in res
    assert "+" not in res
    assert "/" not in res


def test_url_id_no_padding_and_no_unsafe_chars():
    res = url_id("https://example.com/a b")
    assert "=" not in res
    assert "+" not in res
    assert "/" not in res


def test_abuseipdb_normalize_canonical():
    result = AbuseIPDB().normalize("8.8.8.8", ABUSEIPDB_CANONICAL_RAW)
    assert result.ok is True
    assert result.source == "abuseipdb"
    assert (result.verdict, result.severity) == ("benign", "low")
    assert result.summary == "Abuse confidence 0%, 0 reports/90d"
    assert result.error is None
    assert set(result.data) == {
        "abuseConfidenceScore",
        "countryCode",
        "isp",
        "usageType",
        "totalReports",
    }


def test_abuseipdb_confidence_cases():
    provider = AbuseIPDB()
    assert provider.normalize("1.1.1.1", {"data": {"abuseConfidenceScore": 0}}).verdict == "benign"
    assert provider.normalize("1.1.1.1", {"data": {"abuseConfidenceScore": 0}}).severity == "low"
    assert provider.normalize("1.1.1.1", {"data": {"abuseConfidenceScore": 50}}).verdict == "suspicious"
    assert provider.normalize("1.1.1.1", {"data": {"abuseConfidenceScore": 50}}).severity == "medium"
    assert provider.normalize("1.1.1.1", {"data": {"abuseConfidenceScore": 90}}).verdict == "malicious"
    assert provider.normalize("1.1.1.1", {"data": {"abuseConfidenceScore": 90}}).severity == "high"


def test_abuseipdb_none_score_is_benign():
    result = AbuseIPDB().normalize("1.1.1.1", {"data": {"abuseConfidenceScore": None}})
    assert result.ok is True
    assert (result.verdict, result.severity) == ("benign", "low")
    assert result.summary == "Abuse confidence 0%, 0 reports/90d"


def test_virustotal_ip_normalize_cases():
    provider = VirusTotalIP()
    res = provider.normalize("8.8.8.8", VIRUSTOTAL_IP_CANONICAL_RAW)
    assert (res.verdict, res.severity) == ("benign", "none")
    assert set(res.data) == {"reputation", "mal", "sus", "country", "as_owner"}

    raw = VIRUSTOTAL_IP_CANONICAL_RAW.copy()
    raw["data"] = {"attributes": {**raw["data"]["attributes"], "last_analysis_stats": {"malicious": 3, "suspicious": 0}}}
    res = provider.normalize("8.8.8.8", raw)
    assert (res.verdict, res.severity) == ("malicious", "high")

    raw = VIRUSTOTAL_IP_CANONICAL_RAW.copy()
    raw["data"] = {"attributes": {**raw["data"]["attributes"], "last_analysis_stats": {"malicious": 0, "suspicious": 2}}}
    res = provider.normalize("8.8.8.8", raw)
    assert (res.verdict, res.severity) == ("suspicious", "medium")


def test_virustotal_url_normalize_cases():
    provider = VirusTotalURL()
    res = provider.normalize("https://example.com/", VIRUSTOTAL_URL_CANONICAL_RAW)
    assert (res.verdict, res.severity) == ("benign", "none")
    assert set(res.data) == {"last_final_url", "times_submitted", "mal", "sus"}

    raw = VIRUSTOTAL_URL_CANONICAL_RAW.copy()
    raw["data"] = {"attributes": {**raw["data"]["attributes"], "last_analysis_stats": {"malicious": 3, "suspicious": 0}}}
    res = provider.normalize("https://example.com/", raw)
    assert (res.verdict, res.severity) == ("malicious", "high")

    raw = VIRUSTOTAL_URL_CANONICAL_RAW.copy()
    raw["data"] = {"attributes": {**raw["data"]["attributes"], "last_analysis_stats": {"malicious": 0, "suspicious": 2}}}
    res = provider.normalize("https://example.com/", raw)
    assert (res.verdict, res.severity) == ("suspicious", "medium")


def test_greynoise_normalize_cases():
    provider = GreyNoise()
    assert (provider.normalize("1.1.1.1", {"malicious": True}).verdict, provider.normalize("1.1.1.1", {"malicious": True}).severity) == ("malicious", "high")
    assert (provider.normalize("1.1.1.1", {"noise": True}).verdict, provider.normalize("1.1.1.1", {"noise": True}).severity) == ("suspicious", "medium")
    assert (provider.normalize("1.1.1.1", {"riot": True}).verdict, provider.normalize("1.1.1.1", {"riot": True}).severity) == ("benign", "low")
    assert (provider.normalize("1.1.1.1", {"noise": False, "riot": False, "malicious": False}).verdict, provider.normalize("1.1.1.1", {"noise": False, "riot": False, "malicious": False}).severity) == ("unknown", "unknown")
    assert set(provider.normalize("1.1.1.1", GREYNOISE_CANONICAL_RAW).data) == {"noise", "riot", "classification", "name", "link"}


def test_shodan_normalize_cases():
    provider = Shodan()
    res = provider.normalize("1.1.1.1", SHODAN_CANONICAL_RAW)
    assert res.verdict == "unknown"
    assert res.severity == "none"
    assert set(res.data) == {"org", "port", "hostnames", "vulns_count"}

    res = provider.normalize("1.1.1.1", {"vulns": {"CVE-1": {}}})
    assert res.severity == "medium"
    assert res.verdict == "unknown"


def test_shodan_port_fallbacks():
    provider = Shodan()
    assert provider.normalize("1.1.1.1", {"ports": [22, 80]}).data["port"] == 22
    assert provider.normalize("1.1.1.1", {"ports": [], "port": 8080}).data["port"] == 8080
    assert provider.normalize("1.1.1.1", {"port": 8080}).data["port"] == 8080
    assert provider.normalize("1.1.1.1", {}).data["port"] is None


def test_available_for_keyed(monkeypatch):
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    monkeypatch.delenv("VT_API_KEY", raising=False)
    assert AbuseIPDB().available() is False
    assert VirusTotalIP().available() is False
    assert VirusTotalURL().available() is False

    monkeypatch.setenv("ABUSEIPDB_API_KEY", "key")
    monkeypatch.setenv("VT_API_KEY", "key")
    assert AbuseIPDB().available() is True
    assert VirusTotalIP().available() is True
    assert VirusTotalURL().available() is True


@pytest.mark.parametrize("provider", [AbuseIPDB(), VirusTotalIP(), VirusTotalURL(), GreyNoise(), Shodan()], ids=lambda p: p.name)
def test_mock_raw_non_empty(provider):
    raw = provider.mock_raw("8.8.8.8")
    assert isinstance(raw, dict)
    assert raw


def test_for_tool_includes_keyed(monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "k")
    monkeypatch.setenv("VT_API_KEY", "k")
    monkeypatch.setenv("GREYNOISE_API_KEY", "k")
    monkeypatch.setenv("SHODAN_API_KEY", "k")

    selected, skipped = for_tool("url", None)
    names = {p.name for p in selected}
    assert "virustotal_url" in names

    selected, skipped = for_tool("ip", None)
    names = {p.name for p in selected}
    assert "virustotal_ip" in names
    assert "abuseipdb" in names
    assert "greynoise" in names
    assert "shodan" in names


def test_providers_list_contains_keyed():
    by_name = {p.name: p for p in PROVIDERS}
    assert "abuseipdb" in by_name
    assert "virustotal_ip" in by_name
    assert "virustotal_url" in by_name
    assert "greynoise" in by_name
    assert "shodan" in by_name
    assert by_name["virustotal_ip"].tool == "ip"
    assert by_name["virustotal_url"].tool == "url"
    assert by_name["abuseipdb"].env_key == "ABUSEIPDB_API_KEY"
    assert by_name["virustotal_ip"].env_key == "VT_API_KEY"
    assert by_name["virustotal_url"].env_key == "VT_API_KEY"
    assert by_name["greynoise"].env_key == "GREYNOISE_API_KEY"
    assert by_name["shodan"].env_key == "SHODAN_API_KEY"
