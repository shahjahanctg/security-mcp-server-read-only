import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlparse

VERDICTS = ("benign", "suspicious", "malicious", "unknown", "error")
SEVERITIES = ("none", "low", "medium", "high", "critical", "unknown")

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


@dataclass
class ProviderResult:
    source: str
    ok: bool
    verdict: str
    severity: str
    summary: str
    data: dict
    error: str | None
    retrieved_at: str


def validate_ip(value: str) -> str:
    candidate = value.strip()
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError as exc:
        raise ValueError(f"invalid IP address: {value!r}") from exc


def validate_url(value: str) -> str:
    if "\\" in value:
        raise ValueError(f"URL must not contain backslashes, got {value!r}")
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"URL scheme must be http or https, got {parsed.scheme!r}")
    if not parsed.netloc:
        raise ValueError(f"URL must include a host, got {value!r}")
    host = parsed.hostname
    if host is None:
        raise ValueError(f"URL must include a host, got {value!r}")
    normalized_host = host.rstrip(".").lower()
    if normalized_host == "localhost":
        raise ValueError(f"URL host must not be localhost, got {value!r}")
    if normalized_host.endswith(".local") or normalized_host.endswith(".internal"):
        raise ValueError(f"URL host must not end in .local or .internal, got {value!r}")
    try:
        address = ipaddress.ip_address(normalized_host)
    except ValueError:
        address = None
    if address is not None and (
        address.is_private or address.is_loopback or address.is_link_local
    ):
        raise ValueError(f"URL host must be a public IP address, got {value!r}")
    return value


def validate_cve(value: str) -> str:
    candidate = value.strip().upper()
    if not CVE_PATTERN.match(candidate):
        raise ValueError(f"invalid CVE ID: {value!r}")
    return candidate
