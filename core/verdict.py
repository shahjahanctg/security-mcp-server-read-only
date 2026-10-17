from core.schemas import ProviderResult

_VERDICT_RANK = {
    "unknown": 0,
    "benign": 1,
    "suspicious": 2,
    "malicious": 3,
}

_SEVERITY_RANK = {
    "unknown": 0,
    "none": 1,
    "low": 2,
    "medium": 3,
    "high": 4,
    "critical": 5,
}


def roll_up(results: list[ProviderResult]) -> tuple[str, str, str]:
    ok_results = [r for r in results if r.ok]
    if not ok_results:
        return ("unknown", "unknown", "No providers responded.")
    verdict = max((r.verdict for r in ok_results), key=lambda v: _VERDICT_RANK.get(v, 0))
    severity = max((r.severity for r in ok_results), key=lambda s: _SEVERITY_RANK.get(s, 0))
    summary = (
        f"Consensus: {verdict} across {len(ok_results)}/{len(results)} "
        "responding providers."
    )
    return (verdict, severity, summary)
