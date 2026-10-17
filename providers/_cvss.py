def from_cvss(score: float | None) -> tuple[str, str]:
    if score is None:
        return ("unknown", "unknown")
    if score >= 9:
        return ("malicious", "critical")
    if score >= 7:
        return ("malicious", "high")
    if score >= 4:
        return ("suspicious", "medium")
    if score > 0:
        return ("suspicious", "low")
    return ("benign", "none")


_QUALITATIVE: dict[str, tuple[str, str]] = {
    "CRITICAL": ("malicious", "critical"),
    "HIGH": ("malicious", "high"),
    "MODERATE": ("suspicious", "medium"),
    "MEDIUM": ("suspicious", "medium"),
    "LOW": ("benign", "low"),
}


def from_qualitative(label: str | None) -> tuple[str, str]:
    if label is None:
        return ("unknown", "unknown")
    return _QUALITATIVE.get(str(label).strip().upper(), ("unknown", "unknown"))
