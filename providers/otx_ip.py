from core.schemas import ProviderResult, now_iso

from ._otx import fetch_otx, verdict_from_pulses
from .base import Provider, not_found_result


class OtxIp(Provider):
    name = "otx_ip"
    tool = "ip"
    env_key = None

    def mock_raw(self, value: str) -> dict:
        return {
            "general": {"pulse_info": {"count": 1}, "validation": []},
            "passive_dns": {"passive_dns": [{"hostname": "dns.google"}]},
        }

    async def fetch(self, value: str) -> dict:
        general = await fetch_otx(f"IPv4/{value}/general")
        if general.get("not_found"):
            return general
        passive = await fetch_otx(f"IPv4/{value}/passive_dns")
        return {"general": general, "passive_dns": passive}

    def normalize(self, value: str, raw: dict) -> ProviderResult:
        if raw.get("not_found"):
            return not_found_result(self.name)
        general = raw.get("general") or {}
        passive = raw.get("passive_dns") or {}
        pulse_count = (general.get("pulse_info") or {}).get("count", 0) or 0
        validation = general.get("validation") or []
        hostnames: list[str] = []
        for entry in passive.get("passive_dns") or []:
            hostname = (entry or {}).get("hostname")
            if hostname and hostname not in hostnames:
                hostnames.append(hostname)
        verdict, severity = verdict_from_pulses(pulse_count)
        return ProviderResult(
            source=self.name,
            ok=True,
            verdict=verdict,
            severity=severity,
            summary=f"OTX: {pulse_count} pulse(s)",
            data={
                "pulse_count": pulse_count,
                "validation": validation,
                "passive_dns_hostnames": hostnames[:10],
            },
            error=None,
            retrieved_at=now_iso(),
        )
