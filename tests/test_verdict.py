import httpx

from core.http import get_client
from core.schemas import ProviderResult
from core.verdict import roll_up


def make_result(
    source="provider",
    ok=True,
    verdict="unknown",
    severity="unknown",
    summary="summary",
):
    return ProviderResult(
        source=source,
        ok=ok,
        verdict=verdict,
        severity=severity,
        summary=summary,
        data={},
        error=None if ok else "request failed",
        retrieved_at="2026-10-17T00:00:00+00:00",
    )


def test_empty_list_returns_unknown_no_providers():
    assert roll_up([]) == ("unknown", "unknown", "No providers responded.")


def test_all_results_not_ok_returns_no_providers():
    results = [
        make_result(source="a", ok=False, verdict="malicious", severity="critical"),
        make_result(source="b", ok=False, verdict="benign", severity="none"),
    ]
    assert roll_up(results) == ("unknown", "unknown", "No providers responded.")


def test_malicious_beats_benign():
    results = [
        make_result(source="a", verdict="benign", severity="low"),
        make_result(source="b", verdict="malicious", severity="high"),
    ]
    verdict, severity, summary = roll_up(results)
    assert verdict == "malicious"
    assert severity == "high"
    assert summary == "Consensus: malicious across 2/2 responding providers."


def test_suspicious_beats_benign_and_unknown():
    results = [
        make_result(source="a", verdict="unknown", severity="unknown"),
        make_result(source="b", verdict="benign", severity="none"),
        make_result(source="c", verdict="suspicious", severity="medium"),
    ]
    verdict, severity, _ = roll_up(results)
    assert verdict == "suspicious"
    assert severity == "medium"


def test_all_unknown_verdicts_roll_up_to_unknown():
    results = [
        make_result(source="a", verdict="unknown", severity="unknown"),
        make_result(source="b", verdict="unknown", severity="unknown"),
    ]
    verdict, severity, summary = roll_up(results)
    assert verdict == "unknown"
    assert severity == "unknown"
    assert summary == "Consensus: unknown across 2/2 responding providers."


def test_summary_format_for_mixed_case():
    results = [
        make_result(source="a", verdict="benign", severity="none"),
        make_result(source="b", verdict="benign", severity="low"),
        make_result(source="c", ok=False, verdict="malicious", severity="critical"),
    ]
    verdict, severity, summary = roll_up(results)
    assert verdict == "benign"
    assert summary == "Consensus: benign across 2/3 responding providers."


def test_non_ok_excluded_from_verdict_and_count_but_in_denominator():
    results = [
        make_result(source="ok-provider", verdict="benign", severity="none"),
        make_result(source="failed", ok=False, verdict="malicious", severity="critical"),
        make_result(source="failed-too", ok=False, verdict="suspicious", severity="high"),
    ]
    verdict, severity, summary = roll_up(results)
    assert verdict == "benign"
    assert severity == "none"
    assert summary == "Consensus: benign across 1/3 responding providers."


def test_severity_worst_case_full_ordering():
    results = [
        make_result(source="a", severity="low"),
        make_result(source="b", severity="medium"),
        make_result(source="c", severity="critical"),
        make_result(source="d", severity="high"),
        make_result(source="e", severity="none"),
    ]
    _, severity, _ = roll_up(results)
    assert severity == "critical"


def test_severity_low_beats_unknown():
    results = [
        make_result(source="a", severity="unknown"),
        make_result(source="b", severity="low"),
    ]
    _, severity, _ = roll_up(results)
    assert severity == "low"


def test_severity_none_beats_unknown():
    results = [
        make_result(source="a", severity="unknown"),
        make_result(source="b", severity="none"),
    ]
    _, severity, _ = roll_up(results)
    assert severity == "none"


def test_get_client_returns_configured_async_client():
    client = get_client()
    assert isinstance(client, httpx.AsyncClient)
    assert client.timeout == httpx.Timeout(10.0)
    assert client.follow_redirects is False
