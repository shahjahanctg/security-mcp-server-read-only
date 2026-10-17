import pytest

import providers as providers_pkg
from core.schemas import ProviderResult, now_iso
from providers.base import Provider, RateLimited


class FakeProvider(Provider):
    name = "fake"
    tool = "ip"
    env_key = None

    def __init__(
        self,
        *,
        name: str | None = None,
        tool: str | None = None,
        env_key: str | None = None,
        mock_payload: dict | None = None,
        fetch_error: Exception | None = None,
    ):
        if name is not None:
            self.name = name
        if tool is not None:
            self.tool = tool
        if env_key is not None:
            self.env_key = env_key
        self.mock_payload = mock_payload if mock_payload is not None else {"kind": "mock"}
        self.fetch_error = fetch_error
        self.fetch_calls: list[str] = []
        self.normalize_calls: list[tuple[str, dict]] = []

    def mock_raw(self, value: str) -> dict:
        return {**self.mock_payload, "value": value}

    async def fetch(self, value: str) -> dict:
        self.fetch_calls.append(value)
        if self.fetch_error is not None:
            raise self.fetch_error
        return {"kind": "live", "value": value}

    def normalize(self, value: str, raw: dict) -> ProviderResult:
        self.normalize_calls.append((value, raw))
        return ProviderResult(
            source=self.name,
            ok=True,
            verdict="benign",
            severity="none",
            summary=str(raw.get("kind", "")),
            data=dict(raw),
            error=None,
            retrieved_at=now_iso(),
        )


def test_for_tool_none_selects_only_matching_tool(monkeypatch):
    ip_a = FakeProvider(name="ip-a", tool="ip")
    url_b = FakeProvider(name="url-b", tool="url")
    ip_c = FakeProvider(name="ip-c", tool="ip")
    monkeypatch.setattr(providers_pkg, "PROVIDERS", [ip_a, url_b, ip_c])

    selected, skipped = providers_pkg.for_tool("ip", None)

    assert selected == [ip_a, ip_c]
    assert skipped == []


def test_for_tool_skips_keyed_provider_when_env_unset(monkeypatch):
    keyed = FakeProvider(name="keyed", tool="ip", env_key="FAKE_API_KEY")
    monkeypatch.setattr(providers_pkg, "PROVIDERS", [keyed])
    monkeypatch.delenv("FAKE_API_KEY", raising=False)

    selected, skipped = providers_pkg.for_tool("ip", None)

    assert selected == []
    assert skipped == [{"provider": "keyed", "reason": "FAKE_API_KEY not set"}]

    monkeypatch.setenv("FAKE_API_KEY", "secret")
    selected, skipped = providers_pkg.for_tool("ip", None)

    assert selected == [keyed]
    assert skipped == []


def test_for_tool_keyless_provider_is_always_available(monkeypatch):
    keyless = FakeProvider(name="keyless", tool="ip", env_key=None)
    monkeypatch.setattr(providers_pkg, "PROVIDERS", [keyless])

    assert keyless.available() is True

    selected, skipped = providers_pkg.for_tool("ip", None)

    assert selected == [keyless]
    assert skipped == []


def test_for_tool_unknown_name_and_wrong_tool_are_skipped(monkeypatch):
    ip_a = FakeProvider(name="ip-a", tool="ip")
    url_b = FakeProvider(name="url-b", tool="url")
    monkeypatch.setattr(providers_pkg, "PROVIDERS", [ip_a, url_b])

    selected, skipped = providers_pkg.for_tool("ip", ["nope"])

    assert selected == []
    assert skipped == [{"provider": "nope", "reason": "unknown provider"}]

    selected, skipped = providers_pkg.for_tool("ip", ["url-b"])

    assert selected == []
    assert skipped == [{"provider": "url-b", "reason": "unknown provider"}]


def test_for_tool_only_preserves_caller_order_and_reports_missing_key(monkeypatch):
    ip_a = FakeProvider(name="ip-a", tool="ip")
    keyed = FakeProvider(name="keyed", tool="ip", env_key="FAKE_API_KEY")
    monkeypatch.setattr(providers_pkg, "PROVIDERS", [keyed, ip_a])
    monkeypatch.delenv("FAKE_API_KEY", raising=False)

    selected, skipped = providers_pkg.for_tool("ip", ["ip-a", "keyed", "ghost"])

    assert selected == [ip_a]
    assert skipped == [
        {"provider": "ghost", "reason": "unknown provider"},
        {"provider": "keyed", "reason": "FAKE_API_KEY not set"},
    ]


async def test_run_uses_mock_raw_when_mock_env_set(monkeypatch):
    provider = FakeProvider(mock_payload={"kind": "mock", "score": 42})
    monkeypatch.setenv("MOCK", "1")

    result = await provider.run("1.2.3.4")

    assert provider.fetch_calls == []
    assert provider.normalize_calls == [("1.2.3.4", {"kind": "mock", "score": 42, "value": "1.2.3.4"})]
    assert result.ok is True
    assert result.source == "fake"
    assert result.summary == "mock"
    assert result.data["kind"] == "mock"
    assert result.data["score"] == 42


async def test_run_calls_fetch_when_mock_env_unset(monkeypatch):
    provider = FakeProvider()
    monkeypatch.delenv("MOCK", raising=False)

    result = await provider.run("1.2.3.4")

    assert provider.fetch_calls == ["1.2.3.4"]
    assert provider.normalize_calls == [("1.2.3.4", {"kind": "live", "value": "1.2.3.4"})]
    assert result.summary == "live"


async def test_run_returns_error_result_on_fetch_failure(monkeypatch):
    provider = FakeProvider(fetch_error=RuntimeError("boom"))
    monkeypatch.delenv("MOCK", raising=False)

    result = await provider.run("1.2.3.4")

    assert isinstance(result, ProviderResult)
    assert result.ok is False
    assert result.verdict == "error"
    assert result.severity == "unknown"
    assert result.source == "fake"
    assert result.summary == "fake lookup failed"
    assert result.data == {}
    assert result.error == "boom"
    assert result.retrieved_at.endswith("Z")


async def test_run_propagates_rate_limited(monkeypatch):
    provider = FakeProvider(fetch_error=RateLimited("slow down"))
    monkeypatch.delenv("MOCK", raising=False)

    with pytest.raises(RateLimited):
        await provider.run("1.2.3.4")


def test_now_iso_is_utc_with_z_suffix():
    stamp = now_iso()

    assert stamp.endswith("Z")
    assert "+" not in stamp
