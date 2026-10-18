import httpx
import pytest

from providers import PROVIDERS
from providers.base import RateLimited
from providers.otx_file import OtxFile
from providers.virustotal_file import VirusTotalFile


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


HASH = "eicar.com"


def _patch_vt_client(monkeypatch, response: FakeResponse) -> FakeClient:
    client = FakeClient(response)
    monkeypatch.setattr("providers.virustotal_file.get_client", lambda: client)
    return client


def _patch_otx_client(monkeypatch, response: FakeResponse) -> FakeClient:
    client = FakeClient(response)
    monkeypatch.setattr("providers._otx.get_client", lambda: client)
    return client


VIRUSTOTAL_FILE_CANONICAL_RAW = {
    "data": {
        "attributes": {
            "last_analysis_stats": {"malicious": 0, "suspicious": 0},
            "reputation": 0,
            "meaningful_name": "eicar.com",
            "type_description": "Text",
        }
    }
}

OTX_FILE_CANONICAL_RAW = {
    "general": {
        "pulse_info": {"count": 3},
        "validation": [],
        "detection_count": 5,
    }
}


def test_virustotal_file_env_key_and_available(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "key")
    provider = VirusTotalFile()
    assert provider.env_key == "VT_API_KEY"
    assert provider.available() is True

    monkeypatch.delenv("VT_API_KEY", raising=False)
    assert VirusTotalFile().available() is False


def test_virustotal_file_mock_raw_non_empty():
    raw = VirusTotalFile().mock_raw(HASH)
    assert isinstance(raw, dict)
    assert raw


def test_virustotal_file_normalize_canonical():
    result = VirusTotalFile().normalize(HASH, VIRUSTOTAL_FILE_CANONICAL_RAW)

    assert result.ok is True
    assert result.source == "virustotal_file"
    assert (result.verdict, result.severity) == ("benign", "none")
    assert result.error is None
    assert result.summary == "0 malicious / 0 suspicious engine detections"
    assert set(result.data) == {
        "mal",
        "sus",
        "reputation",
        "meaningful_name",
        "type_description",
    }
    assert result.data == {
        "mal": 0,
        "sus": 0,
        "reputation": 0,
        "meaningful_name": "eicar.com",
        "type_description": "Text",
    }


def test_virustotal_file_normalize_malicious():
    raw = {
        "data": {
            "attributes": {
                **VIRUSTOTAL_FILE_CANONICAL_RAW["data"]["attributes"],
                "last_analysis_stats": {"malicious": 3, "suspicious": 0},
            }
        }
    }

    result = VirusTotalFile().normalize(HASH, raw)

    assert (result.verdict, result.severity) == ("malicious", "high")
    assert result.summary == "3 malicious / 0 suspicious engine detections"


def test_virustotal_file_normalize_suspicious():
    raw = {
        "data": {
            "attributes": {
                **VIRUSTOTAL_FILE_CANONICAL_RAW["data"]["attributes"],
                "last_analysis_stats": {"malicious": 0, "suspicious": 2},
            }
        }
    }

    result = VirusTotalFile().normalize(HASH, raw)

    assert (result.verdict, result.severity) == ("suspicious", "medium")


def test_virustotal_file_normalize_not_found():
    result = VirusTotalFile().normalize(HASH, {"not_found": True})

    assert result.ok is False
    assert result.error == "not_found"
    assert result.verdict == "unknown"
    assert result.severity == "unknown"


async def test_virustotal_file_fetch_sends_api_key_header(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "secret-key")
    client = _patch_vt_client(
        monkeypatch, FakeResponse(200, VIRUSTOTAL_FILE_CANONICAL_RAW)
    )

    result = await VirusTotalFile().fetch(HASH)

    assert result == VIRUSTOTAL_FILE_CANONICAL_RAW
    url, kwargs = client.calls[0]
    assert url == f"https://www.virustotal.com/api/v3/files/{HASH}"
    assert kwargs.get("headers") == {"x-apikey": "secret-key"}


async def test_virustotal_file_fetch_404_returns_not_found(monkeypatch):
    _patch_vt_client(monkeypatch, FakeResponse(404))

    result = await VirusTotalFile().fetch(HASH)

    assert result == {"not_found": True}


async def test_virustotal_file_fetch_429_raises_rate_limited(monkeypatch):
    _patch_vt_client(monkeypatch, FakeResponse(429))

    with pytest.raises(RateLimited):
        await VirusTotalFile().fetch(HASH)


async def test_virustotal_file_fetch_500_raises(monkeypatch):
    _patch_vt_client(monkeypatch, FakeResponse(500))

    with pytest.raises(httpx.HTTPStatusError):
        await VirusTotalFile().fetch(HASH)


def test_otx_file_env_key_none_and_available():
    provider = OtxFile()
    assert provider.env_key is None
    assert provider.available() is True


def test_otx_file_mock_raw_non_empty():
    raw = OtxFile().mock_raw(HASH)
    assert isinstance(raw, dict)
    assert raw


def test_otx_file_normalize_with_pulses():
    result = OtxFile().normalize(HASH, OTX_FILE_CANONICAL_RAW)

    assert result.ok is True
    assert result.source == "otx_file"
    assert (result.verdict, result.severity) == ("suspicious", "medium")
    assert result.error is None
    assert result.summary == "OTX: 3 pulse(s)"
    assert set(result.data) == {"pulse_count", "validation", "detection_count"}
    assert result.data == {
        "pulse_count": 3,
        "validation": [],
        "detection_count": 5,
    }


def test_otx_file_normalize_without_pulses():
    raw = {
        "general": {"pulse_info": {"count": 0}, "validation": [], "detection_count": 0}
    }

    result = OtxFile().normalize(HASH, raw)

    assert (result.verdict, result.severity) == ("benign", "none")
    assert result.summary == "OTX: 0 pulse(s)"
    assert result.data["pulse_count"] == 0
    assert result.data["detection_count"] == 0


def test_otx_file_normalize_not_found():
    result = OtxFile().normalize(HASH, {"not_found": True})

    assert result.ok is False
    assert result.error == "not_found"
    assert result.verdict == "unknown"
    assert result.severity == "unknown"


async def test_otx_file_fetch_wraps_general(monkeypatch):
    payload = {"pulse_info": {"count": 1}, "validation": [], "detection_count": 2}
    client = _patch_otx_client(monkeypatch, FakeResponse(200, payload))

    result = await OtxFile().fetch(HASH)

    assert result == {"general": payload}
    assert len(client.calls) == 1
    assert client.calls[0][0].endswith(f"file/{HASH}/general")


async def test_otx_file_fetch_404_returns_not_found(monkeypatch):
    _patch_otx_client(monkeypatch, FakeResponse(404))

    result = await OtxFile().fetch(HASH)

    assert result == {"not_found": True}


async def test_otx_file_fetch_429_raises_rate_limited(monkeypatch):
    _patch_otx_client(monkeypatch, FakeResponse(429))

    with pytest.raises(RateLimited):
        await OtxFile().fetch(HASH)


async def test_otx_file_fetch_500_raises(monkeypatch):
    _patch_otx_client(monkeypatch, FakeResponse(500))

    with pytest.raises(httpx.HTTPStatusError):
        await OtxFile().fetch(HASH)


def test_hash_providers_are_registered():
    by_name = {p.name: p for p in PROVIDERS}

    assert {"virustotal_file", "otx_file"} <= set(by_name)
    assert by_name["virustotal_file"].tool == "hash"
    assert by_name["otx_file"].tool == "hash"
