from core.schemas import ProviderResult, now_iso

from ._otx import fetch_otx, verdict_from_pulses
from .base import Provider, not_found_result


class OtxFile(Provider):
    name = "otx_file"
    tool = "hash"
    env_key = None

    def mock_raw(self, value: str) -> dict:
        return {
            "general": {
                "pulse_info": {"count": 3},
                "validation": [],
                "detection_count": 5,
            }
        }

    async def fetch(self, value: str) -> dict:
        general = await fetch_otx(f"file/{value}/general")
        if general.get("not_found"):
            return {"not_found": True}
        return {"general": general}

    def normalize(self, value: str, raw: dict) -> ProviderResult:
        if raw.get("not_found"):
            return not_found_result(self.name)
        general = raw.get("general") or {}
        pulse_count = (general.get("pulse_info") or {}).get("count", 0) or 0
        validation = general.get("validation") or []
        detection_count = general.get("detection_count") or 0
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
                "detection_count": detection_count,
            },
            error=None,
            retrieved_at=now_iso(),
        )
