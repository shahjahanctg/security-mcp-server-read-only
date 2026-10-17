import httpx

from core.http import get_client
from core.schemas import ProviderResult, now_iso

from ._cvss import from_cvss
from .base import Provider, RateLimited, not_found_result

_METRIC_KEYS = ("cvssV3_1", "cvssV3_0", "cvssV4_0")


class MitreCve(Provider):
    name = "mitre_cve"
    tool = "cve"
    env_key = None

    def mock_raw(self, value: str) -> dict:
        return {
            "cveMetadata": {
                "cveId": value,
                "datePublished": "2024-02-01T00:00:00.000Z",
            },
            "containers": {
                "cna": {
                    "descriptions": [
                        {"lang": "en", "value": "A local privilege escalation issue."}
                    ],
                    "metrics": [
                        {
                            "cvssV3_1": {
                                "baseScore": 5.0,
                                "vectorString": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
                            }
                        }
                    ],
                }
            },
        }

    async def fetch(self, value: str) -> dict:
        r = await get_client().get(f"https://cveawg.mitre.org/api/cve/{value}")
        if r.status_code == 429:
            raise RateLimited("mitre_cve rate limited")
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
        cna = raw.get("containers", {}).get("cna", {})
        score = None
        vector = None
        for entry in cna.get("metrics", []):
            for key in _METRIC_KEYS:
                metric = entry.get(key)
                if metric is not None:
                    score = metric.get("baseScore")
                    vector = metric.get("vectorString")
                    break
            if score is not None:
                break
        verdict, severity = from_cvss(score)
        descriptions = cna.get("descriptions") or [{}]
        desc = str(descriptions[0].get("value", ""))[:500]
        data = {
            "cvss": score,
            "vector": vector,
            "description": desc,
            "datePublished": raw.get("cveMetadata", {}).get("datePublished"),
        }
        summary = f"CVSS {score}" if score is not None else "No CVSS score"
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
