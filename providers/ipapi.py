import httpx

from core.http import get_client
from core.schemas import ProviderResult, now_iso

from .base import Provider, RateLimited, not_found_result

_DATA_KEYS = ("country", "regionName", "city", "isp", "org", "as")


class IpApi(Provider):
    name = "ipapi"
    tool = "ip"
    env_key = None

    def mock_raw(self, value: str) -> dict:
        return {
            "status": "success",
            "country": "United States",
            "regionName": "California",
            "city": "Mountain View",
            "isp": "Google LLC",
            "org": "Google Public DNS",
            "as": "AS15169 Google LLC",
            "query": value,
        }

    async def fetch(self, value: str) -> dict:
        r = await get_client().get(
            f"http://ip-api.com/json/{value}",
            params={
                "fields": "status,message,country,regionName,city,isp,org,as,query"
            },
        )
        if r.status_code == 429:
            raise RateLimited("ipapi rate limited")
        try:
            r.raise_for_status()
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                return {"not_found": True}
            raise
        return r.json()

    def normalize(self, value: str, raw: dict) -> ProviderResult:
        if raw.get("not_found"):
            return not_found_result(self.name)
        if raw.get("status") != "success":
            return ProviderResult(
                source=self.name,
                ok=False,
                verdict="error",
                severity="unknown",
                summary="ipapi lookup failed",
                data={"message": raw.get("message")},
                error=raw.get("message") or "lookup failed",
                retrieved_at=now_iso(),
            )
        place = ", ".join(
            str(part) for part in (raw.get("city"), raw.get("country")) if part
        )
        isp = raw.get("isp")
        summary = f"{place} ({isp})" if place and isp else place or isp or "ipapi"
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
