import time

from core.cache import TTLCache


def test_miss_returns_none():
    cache = TTLCache()
    assert cache.get(("ip", "1.1.1.1", None)) is None


def test_hit_returns_stored_value():
    cache = TTLCache()
    key = ("ip", "1.1.1.1", None)
    value = {"verdict": "benign", "score": 0}
    cache.set(key, value)
    assert cache.get(key) == value


def test_set_overwrites_existing_value():
    cache = TTLCache()
    key = ("ip", "1.1.1.1", None)
    cache.set(key, {"verdict": "benign"})
    cache.set(key, {"verdict": "malicious"})
    assert cache.get(key) == {"verdict": "malicious"}


def test_entry_expires_after_ttl():
    cache = TTLCache(ttl=0.01)
    key = ("ip", "8.8.8.8", None)
    cache.set(key, {"verdict": "benign"})
    time.sleep(0.02)
    assert cache.get(key) is None


def test_entry_survives_before_ttl():
    cache = TTLCache(ttl=10.0)
    key = ("ip", "8.8.8.8", None)
    cache.set(key, {"verdict": "benign"})
    time.sleep(0.02)
    assert cache.get(key) == {"verdict": "benign"}


def test_evicts_oldest_when_over_maxsize():
    cache = TTLCache(ttl=60.0, maxsize=2)
    cache.set(("ip", "1.1.1.1", None), {"n": 1})
    cache.set(("ip", "2.2.2.2", None), {"n": 2})
    cache.set(("ip", "3.3.3.3", None), {"n": 3})
    assert cache.get(("ip", "1.1.1.1", None)) is None
    assert cache.get(("ip", "2.2.2.2", None)) == {"n": 2}
    assert cache.get(("ip", "3.3.3.3", None)) == {"n": 3}


def test_reinserted_key_is_not_oldest():
    cache = TTLCache(ttl=60.0, maxsize=2)
    cache.set(("ip", "1.1.1.1", None), {"n": 1})
    cache.set(("ip", "2.2.2.2", None), {"n": 2})
    cache.set(("ip", "1.1.1.1", None), {"n": 10})
    cache.set(("ip", "3.3.3.3", None), {"n": 3})
    assert cache.get(("ip", "2.2.2.2", None)) is None
    assert cache.get(("ip", "1.1.1.1", None)) == {"n": 10}
    assert cache.get(("ip", "3.3.3.3", None)) == {"n": 3}


def test_provider_filter_makes_keys_distinct():
    cache = TTLCache()
    cache.set(("ip", "1.1.1.1", None), {"verdict": "all-providers"})
    cache.set(("ip", "1.1.1.1", ("ipapi",)), {"verdict": "ipapi-only"})
    assert cache.get(("ip", "1.1.1.1", None)) == {"verdict": "all-providers"}
    assert cache.get(("ip", "1.1.1.1", ("ipapi",))) == {"verdict": "ipapi-only"}


def test_provider_filter_distinct_when_one_side_missing():
    cache = TTLCache()
    cache.set(("ip", "1.1.1.1", ("ipapi",)), {"verdict": "ipapi-only"})
    assert cache.get(("ip", "1.1.1.1", None)) is None


def test_default_ttl_and_maxsize():
    cache = TTLCache()
    assert cache.ttl == 900.0
    assert cache.maxsize == 1000
