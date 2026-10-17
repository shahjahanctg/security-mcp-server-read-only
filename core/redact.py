import os

_SECRET_TOKENS = ("KEY", "TOKEN", "SECRET", "PASSWORD", "APIKEY")
_MIN_LEN = 6


def _is_secret_name(name: str) -> bool:
    return any(token in _SECRET_TOKENS for token in name.upper().split("_"))


def _secret_values() -> list[str]:
    values = []
    for name, value in os.environ.items():
        if not value or len(value) < _MIN_LEN or not _is_secret_name(name):
            continue
        values.append(value)
    return values


def redact(text: str, secrets: list[str] | None = None) -> str:
    if not text:
        return text
    values = _secret_values() if secrets is None else secrets
    for value in values:
        if value and len(value) >= _MIN_LEN:
            text = text.replace(value, "***")
    return text
