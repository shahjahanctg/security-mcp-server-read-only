import httpx

from core.feed import FeedCache
from core.http import get_client
from core.schemas import ProviderResult, now_iso

from .base import Provider, RateLimited

_KEV_FEED = FeedCache(ttl=21600)

_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)


async def _download_kev() -> dict:
    r = await get_client().get(_KEV_URL)
    if r.status_code == 429:
        raise RateLimited("cisa_kev rate limited")
    r.raise_for_status()
    raw = r.json()
    return {
        entry["cveID"]: entry
        for entry in raw.get("vulnerabilities", [])
        if entry.get("cveID")
    }


class CisaKev(Provider):
    name = "cisa_kev"
    tool = "cve"
    env_key = None

    def mock_raw(self, value: str) -> dict:
        return {
            "entry": {
                "cveID": "CVE-2021-44228",
                "dateAdded": "2021-12-10",
                "dueDate": "2021-12-24",
                "knownRansomwareCampaignUse": "Known",
                "requiredAction": "Apply updates",
                "vendorProject": "Apache",
                "product": "Log4j2",
            }
        }

    async def fetch(self, value: str) -> dict:
        catalog = await _KEV_FEED.get(_download_kev)
        return {"entry": catalog.get(value)}

    def normalize(self, value: str, raw: dict) -> ProviderResult:
        entry = raw.get("entry")
        if entry:
            verdict = "malicious"
            severity = "high"
            listed = True
            summary = f"KEV: {entry.get('vendorProject')} {entry.get('product')}"
        else:
            verdict = "benign"
            severity = "none"
            listed = False
            summary = "Not in CISA KEV catalog"
        return ProviderResult(
            source=self.name,
            ok=True,
            verdict=verdict,
            severity=severity,
            summary=summary,
            data={
                "listed": listed,
                "dateAdded": entry.get("dateAdded") if entry else None,
                "dueDate": entry.get("dueDate") if entry else None,
                "knownRansomwareCampaignUse": (
                    entry.get("knownRansomwareCampaignUse") if entry else None
                ),
                "requiredAction": entry.get("requiredAction") if entry else None,
                "vendorProject": entry.get("vendorProject") if entry else None,
                "product": entry.get("product") if entry else None,
            },
            error=None,
            retrieved_at=now_iso(),
        )
