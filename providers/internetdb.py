import httpx

from core.http import get_client
from core.schemas import ProviderResult, now_iso

from .base import Provider, RateLimited, not_found_result


class InternetDb(Provider):
    name = "internetdb"
    tool = "ip"
    env_key = None

    def mock_raw(self, value: str) -> dict:
        return {
            "ip": value,
            "ports": [443, 80],
            "tags": ["cdn"],
            "hostnames": ["dns.google"],
            "cpes": ["cpe:/a:igor_sysoev:nginx"],
            "vulns": ["CVE-2019-1234"],
        }

    async def fetch(self, value: str) -> dict:
        r = await get_client().get(f"https://internetdb.shodan.io/{value}")
        if r.status_code == 429:
            raise RateLimited("internetdb rate limited")
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
        ports = raw.get("ports") or []
        tags = raw.get("tags") or []
        hostnames = raw.get("hostnames") or []
        cpes = (raw.get("cpes") or [])[:10]
        vulns = raw.get("vulns") or []
        vulns_count = len(vulns)
        vulns = vulns[:10]
        severity = "medium" if vulns_count else "none"
        return ProviderResult(
            source=self.name,
            ok=True,
            verdict="unknown",
            severity=severity,
            summary=f"{len(ports)} open port(s), {vulns_count} known vuln(s)",
            data={
                "ports": ports,
                "tags": tags,
                "hostnames": hostnames,
                "cpes": cpes,
                "vulns_count": vulns_count,
                "vulns": vulns,
            },
            error=None,
            retrieved_at=now_iso(),
        )
