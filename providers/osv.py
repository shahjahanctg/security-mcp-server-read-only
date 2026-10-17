import httpx

from core.http import get_client
from core.schemas import ProviderResult, now_iso

from ._cvss import from_qualitative
from .base import Provider, RateLimited, not_found_result


class Osv(Provider):
    name = "osv"
    tool = "cve"
    env_key = None

    def mock_raw(self, value: str) -> dict:
        return {
            "id": value,
            "summary": "Package mishandles untrusted input",
            "aliases": ["CVE-2024-1234"],
            "published": "2024-01-01T00:00:00Z",
            "modified": "2024-02-01T00:00:00Z",
            "database_specific": {"severity": "HIGH"},
        }

    async def fetch(self, value: str) -> dict:
        r = await get_client().get(f"https://api.osv.dev/v1/vulns/{value}")
        if r.status_code == 429:
            raise RateLimited("osv rate limited")
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
        label = (raw.get("database_specific") or {}).get("severity")
        verdict, severity = from_qualitative(label)
        data = {
            "summary": str(raw.get("summary") or "")[:300],
            "aliases": raw.get("aliases") or [],
            "published": raw.get("published"),
            "modified": raw.get("modified"),
        }
        return ProviderResult(
            source=self.name,
            ok=True,
            verdict=verdict,
            severity=severity,
            summary=f"OSV severity: {label or 'unknown'}",
            data=data,
            error=None,
            retrieved_at=now_iso(),
        )
