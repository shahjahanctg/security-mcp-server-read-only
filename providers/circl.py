import httpx

from core.http import get_client
from core.schemas import ProviderResult, now_iso

from ._cvss import from_cvss
from .base import Provider, RateLimited, not_found_result


class Circl(Provider):
    name = "circl"
    tool = "cve"
    env_key = None

    def mock_raw(self, value: str) -> dict:
        return {
            "cvss": 9.8,
            "cvss-vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "summary": "Critical remote code execution.",
            "references": ["https://example.com/advisory"],
            "Published": "2021-12-10T00:00:00",
        }

    async def fetch(self, value: str) -> dict:
        r = await get_client().get(f"https://cve.circl.lu/api/cve/{value}")
        if r.status_code == 429:
            raise RateLimited("circl rate limited")
        try:
            r.raise_for_status()
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                return {"not_found": True}
            raise
        raw = r.json()
        if not raw:
            return {"not_found": True}
        return raw

    def normalize(self, value: str, raw: dict) -> ProviderResult:
        if not raw or raw.get("not_found"):
            return not_found_result(self.name)
        score = raw.get("cvss")
        vector = raw.get("cvss-vector")
        text = str(raw.get("summary") or "")[:500]
        references = (raw.get("references") or [])[:5]
        published = raw.get("Published")
        verdict, severity = from_cvss(score)
        summary = f"CVSS {score}" if score is not None else "No CVSS score"
        return ProviderResult(
            source=self.name,
            ok=True,
            verdict=verdict,
            severity=severity,
            summary=summary,
            data={
                "cvss": score,
                "vector": vector,
                "summary": text,
                "references": references,
                "published": published,
            },
            error=None,
            retrieved_at=now_iso(),
        )
