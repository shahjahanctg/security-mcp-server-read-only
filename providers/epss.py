import httpx

from core.http import get_client
from core.schemas import ProviderResult, now_iso

from .base import Provider, RateLimited, not_found_result


class Epss(Provider):
    name = "epss"
    tool = "cve"
    env_key = None

    def mock_raw(self, value: str) -> dict:
        return {
            "data": [
                {
                    "cve": "CVE-2021-44228",
                    "epss": "0.97",
                    "percentile": "0.99",
                    "date": "2026-01-01",
                }
            ]
        }

    async def fetch(self, value: str) -> dict:
        r = await get_client().get(
            "https://api.first.org/data/v1/epss",
            params={"cve": value},
        )
        if r.status_code == 429:
            raise RateLimited("epss rate limited")
        try:
            r.raise_for_status()
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                return {"not_found": True}
            raise
        return r.json()

    def normalize(self, value: str, raw: dict) -> ProviderResult:
        rows = raw.get("data") or []
        if not rows:
            return not_found_result(self.name)
        row = rows[0]
        score = float(row["epss"])
        percentile = row.get("percentile")
        date = row.get("date") or raw.get("date")
        if score >= 0.5:
            severity = "medium"
        elif score >= 0.1:
            severity = "low"
        else:
            severity = "none"
        return ProviderResult(
            source=self.name,
            ok=True,
            verdict="unknown",
            severity=severity,
            summary=f"EPSS {score:.3f}",
            data={"epss": score, "percentile": percentile, "date": date},
            error=None,
            retrieved_at=now_iso(),
        )
