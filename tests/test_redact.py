import server
from core.ratelimit import RateLimiter
from core.redact import redact
from providers.base import Provider


def test_redact_replaces_secret_value(monkeypatch):
    monkeypatch.setenv("SHODAN_API_KEY", "s3cr3t-value-123")

    text = "403 for url https://api.shodan.io/shodan/host/1.2.3.4?key=s3cr3t-value-123"
    out = redact(text)

    assert "s3cr3t-value-123" not in out
    assert "***" in out


def test_redact_leaves_clean_text_unchanged():
    assert redact("500 Internal Server Error") == "500 Internal Server Error"
    assert redact("") == ""


def test_redact_ignores_empty_and_short_secrets(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "")
    monkeypatch.setenv("NVD_API_KEY", "abc")

    assert redact("value abc here") == "value abc here"


def test_redact_ignores_non_secret_env_names(monkeypatch):
    monkeypatch.setenv("MONKEY", "banana-secret")

    assert redact("a banana-secret monkey") == "a banana-secret monkey"


class _Boom(Provider):
    name = "boom"
    tool = "ip"

    def mock_raw(self, value):
        return {}

    async def fetch(self, value):
        raise RuntimeError("failed https://api.shodan.io/x?key=s3cr3t-value-123")

    def normalize(self, value, raw):
        raise AssertionError("normalize should not be reached")


async def test_provider_run_redacts_secret_in_error(monkeypatch):
    monkeypatch.setenv("SHODAN_API_KEY", "s3cr3t-value-123")

    result = await _Boom().run("1.2.3.4")

    assert result.ok is False
    assert "s3cr3t-value-123" not in (result.error or "")
    assert "***" in (result.error or "")


class _BoomStub:
    name = "boom"
    tool = "ip"

    def __init__(self):
        self._run = None

    def available(self):
        return True

    async def run(self, value):
        raise RuntimeError("failed https://api.shodan.io/x?key=s3cr3t-value-123")


async def test_server_redacts_secret_in_error(monkeypatch):
    monkeypatch.setenv("SHODAN_API_KEY", "s3cr3t-value-123")
    server._LIMITERS["boom"] = RateLimiter(1000.0)

    result = await server._run_with_limit(_BoomStub(), "1.2.3.4")

    assert result.ok is False
    assert "s3cr3t-value-123" not in (result.error or "")
    assert "***" in (result.error or "")
