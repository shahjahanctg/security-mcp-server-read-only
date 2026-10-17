import time


class TTLCache:
    def __init__(self, ttl: float = 900.0, maxsize: int = 1000):
        self.ttl = ttl
        self.maxsize = maxsize
        self._entries: dict[tuple, tuple[dict, float]] = {}

    def get(self, key: tuple) -> dict | None:
        entry = self._entries.get(key)
        if entry is None:
            return None
        value, expires_at = entry
        if time.monotonic() >= expires_at:
            del self._entries[key]
            return None
        return value

    def set(self, key: tuple, value: dict) -> None:
        if key in self._entries:
            del self._entries[key]
        elif len(self._entries) >= self.maxsize and self.maxsize > 0:
            oldest = next(iter(self._entries))
            del self._entries[oldest]
        self._entries[key] = (value, time.monotonic() + self.ttl)
