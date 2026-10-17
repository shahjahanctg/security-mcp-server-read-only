import os

import httpx

from core.http import get_client
from core.schemas import ProviderResult, now_iso

from .base import Provider, RateLimited, not_found_result

_DATA_KEYS = ("city", "region", "country", "org", "loc", "timezone")


class IpInfo(Provider):
    name = "ipinfo"
    tool = "ip"
    env_key = None

    def mock_raw(self, value: str) -> dict:
        return {
            "city": "Mountain View",
            "region": "California",
            "country": "US",
            "org": "AS15169 Google LLC",
            "loc": "37.4,-122.1",
            "timezone": "America/Los_Angeles",
        }

    async def fetch(self, value: str) -> dict:
        token = os.environ.get("IPINFO_TOKEN")
        kwargs: dict = {"params": {"token": token}} if token else {}
        r = await get_client().get(f"https://ipinfo.io/{value}/json", **kwargs)
        if r.status_code == 429:
            raise RateLimited("ipinfo rate limited")
        try:
            r.raise_for_status()
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                return {"not_found": True}
            raise
        return r.json()

    def normalize(self, value: str, raw: dict) -> ProviderResult:
        if raw.get("not_found") or raw.get("error"):
            return not_found_result(self.name)
        place = ", ".join(
            str(part)
            for part in (raw.get("city"), raw.get("region"), raw.get("country"))
            if part
        )
        org = raw.get("org")
        summary = f"{place} ({org})" if place and org else place or org or "ipinfo"
        return ProviderResult(
            source=self.name,
            ok=True,
            verdict="benign",
            severity="none",
            summary=summary,
            data={key: raw.get(key) for key in _DATA_KEYS},
            error=None,
            retrieved_at=now_iso(),
        )
