import asyncio
import time

_MISSING = object()


class FeedCache:
    def __init__(self, ttl: float, clock=time.monotonic):
        self.ttl = ttl
        self._clock = clock
        self._lock = asyncio.Lock()
        self._value = _MISSING
        self._expires_at = 0.0

    async def get(self, fetcher):
        if self._value is not _MISSING and self._clock() < self._expires_at:
            return self._value
        async with self._lock:
            if self._value is not _MISSING and self._clock() < self._expires_at:
                return self._value
            value = await fetcher()
            self._value = value
            self._expires_at = self._clock() + self.ttl
            return value
