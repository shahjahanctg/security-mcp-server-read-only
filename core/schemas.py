import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlparse

VERDICTS = ("benign", "suspicious", "malicious", "unknown", "error")
SEVERITIES = ("none", "low", "medium", "high", "critical", "unknown")

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
DOMAIN_LABEL_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$")
HASH_PATTERN = re.compile(r"^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$")


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


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


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


def validate_domain(value: str) -> str:
    candidate = value.strip().lower().rstrip(".")
    if not candidate:
        raise ValueError(f"invalid domain: {value!r}")
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        pass
    else:
        raise ValueError(f"domain must not be an IP literal, got {value!r}")
    for char in ("://", "/", ":", "\\"):
        if char in candidate:
            raise ValueError(f"domain must not contain {char!r}, got {value!r}")
    if any(ch.isspace() for ch in candidate):
        raise ValueError(f"domain must not contain whitespace, got {value!r}")
    if candidate == "localhost":
        raise ValueError(f"domain must not be localhost, got {value!r}")
    if candidate.endswith(".local") or candidate.endswith(".internal"):
        raise ValueError(f"domain must not end in .local or .internal, got {value!r}")
    if "." not in candidate:
        raise ValueError(f"domain must contain a dot, got {value!r}")
    if len(candidate) > 253:
        raise ValueError(f"domain too long, got {value!r}")
    for label in candidate.split("."):
        if not label or len(label) > 63:
            raise ValueError(f"domain label must be 1-63 chars, got {value!r}")
        if not DOMAIN_LABEL_PATTERN.match(label):
            raise ValueError(f"invalid domain label: {label!r}")
    return candidate


def validate_hash(value: str) -> str:
    candidate = value.strip().lower()
    if not HASH_PATTERN.match(candidate):
        raise ValueError(f"invalid file hash: {value!r}")
    return candidate
