import asyncio
import time

import pytest

from core.ratelimit import RateLimiter


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def fake_clock(monkeypatch):
    clock = FakeClock()
    real_sleep = asyncio.sleep

    async def fake_sleep(seconds: float) -> None:
        clock.advance(seconds)
        await real_sleep(0)

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)
    return clock


async def test_three_immediate_acquires_return_without_delay(fake_clock):
    limiter = RateLimiter(rate=1000, capacity=3, clock=fake_clock)
    for _ in range(3):
        await limiter.acquire()
    assert fake_clock.now == 0.0


async def test_fourth_acquire_waits_for_token_refill(fake_clock):
    limiter = RateLimiter(rate=10, capacity=1, clock=fake_clock)
    await limiter.acquire()
    for _ in range(2):
        await limiter.acquire()
    before = fake_clock.now
    await limiter.acquire()
    assert fake_clock.now - before >= 0.1


async def test_separate_limiters_are_independent(fake_clock):
    busy = RateLimiter(rate=10, capacity=1, clock=fake_clock)
    other = RateLimiter(rate=10, capacity=1, clock=fake_clock)
    await busy.acquire()
    before = fake_clock.now
    await other.acquire()
    assert fake_clock.now == before
    await busy.acquire()
    assert fake_clock.now - before >= 0.1


def test_capacity_defaults_to_max_of_one_and_rate():
    assert RateLimiter(rate=0.5).capacity == 1.0
    assert RateLimiter(rate=7.5).capacity == 7.5


async def test_acquire_waits_in_real_time_when_bucket_empty():
    limiter = RateLimiter(rate=100, capacity=1)
    await limiter.acquire()
    start = time.monotonic()
    await limiter.acquire()
    assert time.monotonic() - start >= 0.005
