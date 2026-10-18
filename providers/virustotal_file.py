import os

import httpx

from core.http import get_client
from core.schemas import ProviderResult, now_iso

from .base import Provider, RateLimited, not_found_result


class VirusTotalFile(Provider):
    name = "virustotal_file"
    tool = "hash"
    env_key = "VT_API_KEY"

    def mock_raw(self, value: str) -> dict:
        return {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 0, "suspicious": 0},
                    "reputation": 0,
                    "meaningful_name": "eicar.com",
                    "type_description": "Text",
                }
            }
        }

    async def fetch(self, value: str) -> dict:
        api_key = os.environ.get("VT_API_KEY")
        r = await get_client().get(
            f"https://www.virustotal.com/api/v3/files/{value}",
            headers={"x-apikey": api_key or ""},
        )
        if r.status_code == 429:
            raise RateLimited("virustotal_file rate limited")
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
        attrs = (raw.get("data") or {}).get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}
        mal = stats.get("malicious", 0) or 0
        sus = stats.get("suspicious", 0) or 0
        if mal > 0:
            verdict, severity = ("malicious", "high")
        elif sus > 0:
            verdict, severity = ("suspicious", "medium")
        else:
            verdict, severity = ("benign", "none")
        return ProviderResult(
            source=self.name,
            ok=True,
            verdict=verdict,
            severity=severity,
            summary=f"{mal} malicious / {sus} suspicious engine detections",
            data={
                "mal": mal,
                "sus": sus,
                "reputation": attrs.get("reputation"),
                "meaningful_name": attrs.get("meaningful_name"),
                "type_description": attrs.get("type_description"),
            },
            error=None,
            retrieved_at=now_iso(),
        )
