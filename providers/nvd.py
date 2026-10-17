import os

import httpx

from core.http import get_client
from core.schemas import ProviderResult, now_iso

from ._cvss import from_cvss
from .base import Provider, RateLimited, not_found_result

_METRIC_KEYS = ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2")


class Nvd(Provider):
    name = "nvd"
    tool = "cve"
    env_key = None

    def mock_raw(self, value: str) -> dict:
        return {
            "totalResults": 1,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": value,
                        "published": "2024-03-01T00:00:00.000",
                        "descriptions": [
                            {"lang": "en", "value": "A remote code execution flaw."}
                        ],
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "cvssData": {
                                        "baseScore": 9.8,
                                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                    }
                                }
                            ]
                        },
                        "references": [{"url": "https://example.com/advisory"}],
                        "weaknesses": [
                            {"description": [{"lang": "en", "value": "CWE-79"}]}
                        ],
                    }
                }
            ],
        }

    async def fetch(self, value: str) -> dict:
        headers = {}
        api_key = os.environ.get("NVD_API_KEY")
        if api_key:
            headers["apiKey"] = api_key
        r = await get_client().get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"cveId": value},
            headers=headers,
        )
        if r.status_code == 429:
            raise RateLimited("nvd rate limited")
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
        vulns = raw.get("vulnerabilities") or []
        if raw.get("totalResults", 0) == 0 or not vulns:
            return not_found_result(self.name)
        cve = vulns[0]["cve"]
        metrics = cve.get("metrics", {})
        metric = next(
            (metrics[key][0] for key in _METRIC_KEYS if metrics.get(key)),
            None,
        )
        score = None
        vector = None
        if metric is not None:
            cvss_data = metric.get("cvssData", {})
            score = cvss_data.get("baseScore")
            vector = cvss_data.get("vectorString")
        verdict, severity = from_cvss(score)
        desc = ""
        for entry in cve.get("descriptions", []):
            if entry.get("lang") == "en":
                desc = str(entry.get("value", ""))[:500]
                break
        refs = [
            ref.get("url") for ref in cve.get("references", []) if ref.get("url")
        ][:5]
        cwe = [
            d["value"]
            for w in cve.get("weaknesses", [])
            for d in w.get("description", [])
            if str(d.get("value", "")).startswith("CWE")
        ]
        data = {
            "cvss": score,
            "vector": vector,
            "published": cve.get("published"),
            "description": desc,
            "references": refs,
            "cwe": cwe,
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
