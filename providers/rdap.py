from datetime import datetime, timezone

import httpx

from core.http import get_client
from core.schemas import ProviderResult, now_iso

from .base import Provider, RateLimited, not_found_result

_DATA_KEYS = (
    "registrar",
    "created",
    "expires",
    "updated",
    "statuses",
    "nameservers",
    "dnssec",
    "age_days",
)


def _age_days(created: str | None) -> int | None:
    if not created:
        return None
    try:
        parsed = datetime.fromisoformat(str(created).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - parsed).days


class Rdap(Provider):
    name = "rdap"
    tool = "domain"
    env_key = None

    def mock_raw(self, value: str) -> dict:
        return {
            "ldhName": value,
            "status": ["client transfer prohibited"],
            "secureDNS": {"delegationSigned": False},
            "nameservers": [{"ldhName": "A.IANA-SERVERS.NET"}],
            "entities": [
                {
                    "roles": ["registrar"],
                    "vcardArray": [
                        "vcard",
                        [["fn", {}, "text", "Example Registrar"]],
                    ],
                }
            ],
            "events": [
                {
                    "eventAction": "registration",
                    "eventDate": "2024-01-01T00:00:00Z",
                }
            ],
        }

    async def fetch(self, value: str) -> dict:
        r = await get_client().get(
            f"https://rdap.org/domain/{value}",
            follow_redirects=True,
        )
        if r.status_code == 429:
            raise RateLimited("rdap rate limited")
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
        registrar = None
        for entity in raw.get("entities") or []:
            if "registrar" not in (entity.get("roles") or []):
                continue
            vcard = entity.get("vcardArray") or []
            entries = vcard[1] if len(vcard) > 1 and isinstance(vcard[1], list) else []
            for entry in entries:
                if entry and entry[0] == "fn":
                    registrar = entry[3] if len(entry) > 3 else None
                    break
            if registrar is not None:
                break

        events = raw.get("events") or []

        def _event(action: str) -> str | None:
            for event in events:
                if event.get("eventAction") == action:
                    return event.get("eventDate")
            return None

        created = _event("registration")
        expires = _event("expiration")
        updated = _event("last changed")
        nameservers = [
            ns.get("ldhName")
            for ns in raw.get("nameservers") or []
            if ns.get("ldhName")
        ]
        statuses = raw.get("status") or []
        dnssec = (raw.get("secureDNS") or {}).get("delegationSigned")
        age_days = _age_days(created)
        if age_days is not None and age_days < 30:
            verdict, severity = ("suspicious", "medium")
        else:
            verdict, severity = ("benign", "none")
        data = {
            "registrar": registrar,
            "created": created,
            "expires": expires,
            "updated": updated,
            "statuses": statuses,
            "nameservers": nameservers,
            "dnssec": dnssec,
            "age_days": age_days,
        }
        summary = f"{registrar or 'unknown registrar'} — registered {created or 'unknown'}"
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
