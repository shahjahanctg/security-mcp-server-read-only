import httpx

from core.http import get_client

from .base import RateLimited

OTX_BASE = "https://otx.alienvault.com/api/v1/indicators/"


def verdict_from_pulses(count: int) -> tuple[str, str]:
    if count and count > 0:
        return ("suspicious", "medium")
    return ("benign", "none")


async def fetch_otx(path: str) -> dict:
    r = await get_client().get(OTX_BASE + path)
    if r.status_code == 429:
        raise RateLimited("otx rate limited")
    try:
        r.raise_for_status()
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404:
            return {"not_found": True}
        raise
    return r.json()
