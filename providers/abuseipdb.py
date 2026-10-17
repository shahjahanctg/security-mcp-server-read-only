import os

import httpx

from core.http import get_client
from core.schemas import ProviderResult, now_iso

from .base import Provider, RateLimited, not_found_result


class AbuseIPDB(Provider):
    name = "abuseipdb"
    tool = "ip"
    env_key = "ABUSEIPDB_API_KEY"

    def mock_raw(self, value: str) -> dict:
        return {
            "data": {
                "abuseConfidenceScore": 0,
                "countryCode": "US",
                "isp": "Google LLC",
                "usageType": "Data Center/Web Hosting/Transit",
                "totalReports": 0,
            }
        }

    async def fetch(self, value: str) -> dict:
        api_key = os.environ.get("ABUSEIPDB_API_KEY")
        r = await get_client().get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": value, "maxAgeInDays": 90},
            headers={"Key": api_key or "", "Accept": "application/json"},
        )
        if r.status_code == 429:
            raise RateLimited("abuseipdb rate limited")
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
        data = raw.get("data", {}) or {}
        score = data.get("abuseConfidenceScore", 0)
        if score == 0:
            verdict, severity = ("benign", "low")
        elif 1 <= score <= 24:
            verdict, severity = ("suspicious", "low")
        elif 25 <= score <= 74:
            verdict, severity = ("suspicious", "medium")
        elif score >= 75:
            verdict, severity = ("malicious", "high")
        else:
            if score == 0:
                verdict, severity = ("benign", "low")
            elif score > 0 and score < 25:
                verdict, severity = ("suspicious", "low")
            elif score < 75:
                verdict, severity = ("suspicious", "medium")
            else:
                verdict, severity = ("malicious", "high")
        summary = f"Abuse confidence {score}%, {data.get('totalReports', 0)} reports/90d"
        return ProviderResult(
            source=self.name,
            ok=True,
            verdict=verdict,
            severity=severity,
            summary=summary,
            data={
                "abuseConfidenceScore": data.get("abuseConfidenceScore"),
                "countryCode": data.get("countryCode"),
                "isp": data.get("isp"),
                "usageType": data.get("usageType"),
                "totalReports": data.get("totalReports"),
            },
            error=None,
            retrieved_at=now_iso(),
        )
