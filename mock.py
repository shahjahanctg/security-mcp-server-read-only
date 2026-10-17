import os

from dotenv import load_dotenv

load_dotenv()


def is_mock() -> bool:
    return os.environ.get("MOCK") == "1"


def cache_ttl() -> float:
    return float(os.environ.get("CACHE_TTL", "900"))
