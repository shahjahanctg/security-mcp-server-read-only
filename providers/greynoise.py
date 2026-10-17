import os

import httpx

from core.http import get_client
from core.schemas import ProviderResult, now_iso

from .base import Provider, RateLimited, not_found_result


class GreyNoise(Provider):
    name = "greynoise"
    tool = "ip"
    env_key = "GREYNOISE_API_KEY"

    def mock_raw(self, value: str) -> dict:
        return {
            "ip": value,
            "noise": False,
            "riot": True,
            "classification": "benign",
            "name": "Google",
            "link": "https://viz.greynoise.io/ip/8.8.8.8",
            "malicious": False,
        }

    async def fetch(self, value: str) -> dict:
        api_key = os.environ.get("GREYNOISE_API_KEY")
        r = await get_client().get(
            f"https://api.greynoise.io/v3/community/{value}",
            headers={"key": api_key or ""},
        )
        if r.status_code == 429:
            raise RateLimited("greynoise rate limited")
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
        if raw.get("malicious"):
            verdict, severity = ("malicious", "high")
        elif raw.get("noise"):
            verdict, severity = ("suspicious", "medium")
        elif raw.get("riot"):
            verdict, severity = ("benign", "low")
        else:
            verdict, severity = ("unknown", "unknown")
        data = {
            "noise": raw.get("noise"),
            "riot": raw.get("riot"),
            "classification": raw.get("classification"),
            "name": raw.get("name"),
            "link": raw.get("link"),
        }
        summary = f"GreyNoise: {raw.get('classification') or 'unknown'}"
        return ProviderResult(
            source=self.name,
            ok=True,
            verdict=verdict,
            severity=severity,
            summary=summary,
            data=data,
            error=None,
            retrieved_at=now_iso(),
        )
