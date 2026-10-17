import httpx

from core.http import get_client
from core.schemas import ProviderResult, now_iso

from .base import Provider, RateLimited, not_found_result

_RECORD_TYPES = ("A", "MX", "NS", "TXT")


class DnsRecords(Provider):
    name = "dns"
    tool = "domain"
    env_key = None

    def mock_raw(self, value: str) -> dict:
        return {
            "A": ["93.184.216.34"],
            "MX": ["0 ."],
            "NS": ["a.iana-servers.net"],
            "TXT": ["v=spf1 -all"],
        }

    async def fetch(self, value: str) -> dict:
        merged: dict[str, list[str]] = {record_type: [] for record_type in _RECORD_TYPES}
        for record_type in _RECORD_TYPES:
            r = await get_client().get(
                "https://dns.google/resolve",
                params={"name": value, "type": record_type},
            )
            if r.status_code == 429:
                raise RateLimited("dns rate limited")
            try:
                r.raise_for_status()
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code == 404:
                    return {"not_found": True}
                raise
            answers = r.json().get("Answer") or []
            merged[record_type] = [
                answer.get("data")
                for answer in answers
                if answer.get("data") is not None
            ]
        return merged

    def normalize(self, value: str, raw: dict) -> ProviderResult:
        if raw.get("not_found"):
            return not_found_result(self.name)
        a = (raw.get("A") or [])[:10]
        mx = (raw.get("MX") or [])[:10]
        ns = (raw.get("NS") or [])[:10]
        txt = (raw.get("TXT") or [])[:10]
        return ProviderResult(
            source=self.name,
            ok=True,
            verdict="benign",
            severity="none",
            summary=f"A:{len(a)} MX:{len(mx)} NS:{len(ns)} TXT:{len(txt)}",
            data={"a": a, "mx": mx, "ns": ns, "txt": txt},
            error=None,
            retrieved_at=now_iso(),
        )
