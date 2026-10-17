import httpx

from core.http import get_client
from core.schemas import ProviderResult, now_iso

from .base import Provider, RateLimited, not_found_result


class CrtSh(Provider):
    name = "crtsh"
    tool = "domain"
    env_key = None

    def mock_raw(self, value: str) -> list:
        return [
            {"name_value": f"www.{value}\napi.{value}\nwww.{value}"},
        ]

    async def fetch(self, value: str) -> list:
        r = await get_client().get(
            "https://crt.sh/",
            params={"q": f"%.{value}", "output": "json"},
        )
        if r.status_code == 429:
            raise RateLimited("crtsh rate limited")
        try:
            r.raise_for_status()
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                return {"not_found": True}
            raise
        return r.json()

    def normalize(self, value: str, raw: list | dict) -> ProviderResult:
        if isinstance(raw, dict) and raw.get("not_found"):
            return not_found_result(self.name)
        names: set[str] = set()
        for entry in raw if isinstance(raw, list) else []:
            name_value = (entry or {}).get("name_value") or ""
            for line in name_value.split("\n"):
                name = line.strip().lower()
                if not name:
                    continue
                if name == value or name.endswith(f".{value}"):
                    names.add(name)
        ordered = sorted(names)
        data = {
            "subdomain_count": len(ordered),
            "subdomains": ordered[:50],
        }
        return ProviderResult(
            source=self.name,
            ok=True,
            verdict="benign",
            severity="none",
            summary=f"{len(ordered)} subdomain(s) in CT logs",
            data=data,
            error=None,
            retrieved_at=now_iso(),
        )
