import pytest

from core.schemas import SEVERITIES, VERDICTS, ProviderResult, validate_cve, validate_ip, validate_url


def test_verdicts_vocabulary():
    assert VERDICTS == ("benign", "suspicious", "malicious", "unknown", "error")


def test_severities_vocabulary():
    assert SEVERITIES == ("none", "low", "medium", "high", "critical", "unknown")


def test_provider_result_fields():
    result = ProviderResult(
        source="test",
        ok=True,
        verdict="benign",
        severity="none",
        summary="looks fine",
        data={"a": 1},
        error=None,
        retrieved_at="2026-10-17T00:00:00Z",
    )
    assert result.source == "test"
    assert result.ok is True
    assert result.verdict == "benign"
    assert result.severity == "none"
    assert result.summary == "looks fine"
    assert result.data == {"a": 1}
    assert result.error is None
    assert result.retrieved_at == "2026-10-17T00:00:00Z"


def test_validate_ip_valid_ipv4():
    assert validate_ip("8.8.8.8") == "8.8.8.8"


def test_validate_ip_valid_ipv6():
    assert validate_ip("2001:4860:4860::8888") == "2001:4860:4860::8888"


def test_validate_ip_rejects_non_ip():
    with pytest.raises(ValueError):
        validate_ip("not-an-ip")


def test_validate_ip_rejects_empty():
    with pytest.raises(ValueError):
        validate_ip("")


def test_validate_url_valid_https():
    assert validate_url("https://example.com/a") == "https://example.com/a"


def test_validate_url_valid_http():
    assert validate_url("http://example.org/path?q=1") == "http://example.org/path?q=1"


def test_validate_url_rejects_ftp():
    with pytest.raises(ValueError):
        validate_url("ftp://x")


def test_validate_url_rejects_file_scheme():
    with pytest.raises(ValueError):
        validate_url("file:///etc/passwd")


def test_validate_url_rejects_localhost():
    with pytest.raises(ValueError):
        validate_url("http://localhost/")


def test_validate_url_rejects_private_ipv4_literal():
    with pytest.raises(ValueError):
        validate_url("http://10.0.0.1/")


def test_validate_url_rejects_link_local_ipv4_literal():
    with pytest.raises(ValueError):
        validate_url("http://169.254.169.254/")


def test_validate_url_rejects_loopback_ipv4_literal():
    with pytest.raises(ValueError):
        validate_url("http://127.0.0.1/")


def test_validate_url_rejects_private_ipv6_literal():
    with pytest.raises(ValueError):
        validate_url("http://[::1]/")


def test_validate_url_rejects_dot_local_hostname():
    with pytest.raises(ValueError):
        validate_url("http://printer.local/")


def test_validate_url_rejects_dot_internal_hostname():
    with pytest.raises(ValueError):
        validate_url("http://db.internal/")


def test_validate_url_rejects_missing_netloc():
    with pytest.raises(ValueError):
        validate_url("https:")


def test_validate_url_rejects_backslash_authority_bypass():
    with pytest.raises(ValueError):
        validate_url("http://127.0.0.1\\@example.com/")


def test_validate_url_rejects_backslash_in_host():
    with pytest.raises(ValueError):
        validate_url("http://exam\\ple.com/")


def test_validate_cve_normalizes_lowercase():
    assert validate_cve("cve-2021-44228") == "CVE-2021-44228"


def test_validate_cve_passes_through_uppercase():
    assert validate_cve("CVE-2021-44228") == "CVE-2021-44228"


def test_validate_cve_rejects_short_year():
    with pytest.raises(ValueError):
        validate_cve("CVE-21-1")


def test_validate_cve_rejects_non_cve():
    with pytest.raises(ValueError):
        validate_cve("not-a-cve")
