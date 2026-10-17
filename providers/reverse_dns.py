import ipaddress

import httpx

from core.http import get_client
from core.schemas import ProviderResult, now_iso

from .base import Provider, RateLimited, not_found_result


class ReverseDns(Provider):
    name = "reverse_dns"
    tool = "ip"
    env_key = None

    def mock_raw(self, value: str) -> dict:
        return {"ptr": ["dns.google"]}

    async def fetch(self, value: str) -> dict:
        ptr_name = ipaddress.ip_address(value).reverse_pointer
        r = await get_client().get(
            "https://dns.google/resolve",
            params={"name": ptr_name, "type": "PTR"},
        )
        if r.status_code == 429:
            raise RateLimited("reverse_dns rate limited")
        try:
            r.raise_for_status()
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                return {"not_found": True}
            raise
        answers = r.json().get("Answer") or []
        ptr = [
            answer.get("data")
            for answer in answers
            if answer.get("data") is not None
        ]
        return {"ptr": ptr}

    def normalize(self, value: str, raw: dict) -> ProviderResult:
        if raw.get("not_found"):
            return not_found_result(self.name)
        ptr = (raw.get("ptr") or [])[:10]
        summary = f"PTR: {', '.join(ptr[:3])}" if ptr else "No PTR record"
        return ProviderResult(
            source=self.name,
            ok=True,
            verdict="benign",
            severity="none",
            summary=summary,
            data={"ptr": ptr},
            error=None,
            retrieved_at=now_iso(),
        )
