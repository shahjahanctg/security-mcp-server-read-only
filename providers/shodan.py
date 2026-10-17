import os

import httpx

from core.http import get_client
from core.schemas import ProviderResult, now_iso

from .base import Provider, RateLimited, not_found_result


class Shodan(Provider):
    name = "shodan"
    tool = "ip"
    env_key = "SHODAN_API_KEY"

    def mock_raw(self, value: str) -> dict:
        return {
            "org": "Google LLC",
            "ports": [443],
            "hostnames": ["dns.google"],
            "vulns": {},
        }

    async def fetch(self, value: str) -> dict:
        api_key = os.environ.get("SHODAN_API_KEY")
        r = await get_client().get(
            f"https://api.shodan.io/shodan/host/{value}",
            params={"key": api_key or ""},
        )
        if r.status_code == 429:
            raise RateLimited("shodan rate limited")
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
        vulns = raw.get("vulns") or {}
        vulns_count = len(vulns)
        if vulns_count > 0:
            severity = "medium"
        else:
            severity = "none"
        verdict = "unknown"
        ports = raw.get("ports")
        if isinstance(ports, list) and ports:
            port = ports[0]
        else:
            port = raw.get("port")
        data = {
            "org": raw.get("org"),
            "port": port,
            "hostnames": raw.get("hostnames", []) or [],
            "vulns_count": vulns_count,
        }
        summary = f"{raw.get('org') or 'unknown org'} — {vulns_count} known vuln(s)"
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
