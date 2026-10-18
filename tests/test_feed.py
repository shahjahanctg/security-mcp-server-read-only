import asyncio

from core.feed import FeedCache


async def test_feed_calls_fetcher_once_within_ttl():
    cache = FeedCache(ttl=100)
    calls = []

    async def fetcher():
        calls.append(1)
        return "value"

    first = await cache.get(fetcher)
    second = await cache.get(fetcher)

    assert first == "value"
    assert second == "value"
    assert len(calls) == 1


async def test_feed_refetches_after_ttl_expiry():
    now = [0.0]
    calls = []
    cache = FeedCache(ttl=100, clock=lambda: now[0])

    async def fetcher():
        calls.append(1)
        return len(calls)

    assert await cache.get(fetcher) == 1
    now[0] = 50.0
    assert await cache.get(fetcher) == 1
    now[0] = 100.0
    assert await cache.get(fetcher) == 2
    assert len(calls) == 2


async def test_feed_concurrent_callers_fetch_once():
    cache = FeedCache(ttl=100)
    counter = {"n": 0}

    async def fetcher():
        counter["n"] += 1
        await asyncio.sleep(0)
        return {"v": counter["n"]}

    results = await asyncio.gather(*(cache.get(fetcher) for _ in range(5)))

    assert counter["n"] == 1
    assert all(result == results[0] for result in results)


async def test_feed_caches_falsy_values():
    for falsy in (0, False, {}, [], None):
        cache = FeedCache(ttl=100)
        calls = []

        async def fetcher():
            calls.append(1)
            return falsy

        first = await cache.get(fetcher)
        second = await cache.get(fetcher)

        assert first is falsy
        assert second is falsy
        assert len(calls) == 1
