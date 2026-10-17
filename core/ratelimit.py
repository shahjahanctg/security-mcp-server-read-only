import asyncio
import time
from collections.abc import Callable


class RateLimiter:
    def __init__(
        self,
        rate: float,
        capacity: float | None = None,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.rate = rate
        self.capacity = max(1.0, rate) if capacity is None else capacity
        self._clock = clock
        self._tokens = self.capacity
        self._last = clock()

    async def acquire(self) -> None:
        while True:
            now = self._clock()
            refill = (now - self._last) * self.rate
            self._tokens = min(self.capacity, self._tokens + refill)
            self._last = now
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return
            await asyncio.sleep((1.0 - self._tokens) / self.rate)
