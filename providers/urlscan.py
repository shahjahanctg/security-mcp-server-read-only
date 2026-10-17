import os

import httpx

from core.http import get_client
from core.schemas import ProviderResult, now_iso

from .base import Provider, RateLimited, not_found_result


class UrlScan(Provider):
    name = "urlscan"
    tool = "url"
    env_key = None

    def mock_raw(self, value: str) -> dict:
        return {
            "total": 1,
            "results": [
                {
                    "score": 0,
                    "task": {"time": "2024-01-01T00:00:00.000Z"},
                    "page": {"domain": "example.com"},
                    "verdicts": {"overall": {"malicious": False}},
                }
            ],
        }

    async def fetch(self, value: str) -> dict:
        headers = {}
        api_key = os.environ.get("URLSCAN_API_KEY")
        if api_key:
            headers["api-key"] = api_key
        r = await get_client().get(
            "https://urlscan.io/api/v1/search/",
            params={"q": f'page.url:"{value}"'},
            headers=headers,
        )
        if r.status_code == 429:
            raise RateLimited("urlscan rate limited")
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
        hits = raw.get("results") or []
        if not hits:
            return ProviderResult(
                source=self.name,
                ok=True,
                verdict="benign",
                severity="none",
                summary="No urlscan results",
                data={
                    "total": raw.get("total", 0),
                    "last_task_time": None,
                    "top_score": None,
                    "domains": [],
                },
                error=None,
                retrieved_at=now_iso(),
            )
        malicious = any(
            ((hit.get("verdicts") or {}).get("overall") or {}).get("malicious")
            for hit in hits
        )
        scores = [hit.get("score") for hit in hits if hit.get("score") is not None]
        domains = [
            (hit.get("page") or {}).get("domain")
            for hit in hits
            if (hit.get("page") or {}).get("domain")
        ][:5]
        data = {
            "total": raw.get("total", len(hits)),
            "last_task_time": (hits[0].get("task") or {}).get("time"),
            "top_score": max(scores) if scores else None,
            "domains": domains,
        }
        verdict, severity = ("malicious", "high") if malicious else ("unknown", "none")
        return ProviderResult(
            source=self.name,
            ok=True,
            verdict=verdict,
            severity=severity,
            summary=f"{len(hits)} urlscan result(s)",
            data=data,
            error=None,
            retrieved_at=now_iso(),
        )
