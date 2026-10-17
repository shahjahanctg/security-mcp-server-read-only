from providers.base import Provider, ProviderError, RateLimited

PROVIDERS: list[Provider] = []


def for_tool(tool: str, only: list[str] | None) -> tuple[list[Provider], list[dict]]:
    selected: list[Provider] = []
    skipped: list[dict] = []
    if only is None:
        candidates = [p for p in PROVIDERS if p.tool == tool]
    else:
        candidates = []
        for name in only:
            match = next((p for p in PROVIDERS if p.name == name), None)
            if match is None or match.tool != tool:
                skipped.append({"provider": name, "reason": "unknown provider"})
            else:
                candidates.append(match)
    for provider in candidates:
        if provider.available():
            selected.append(provider)
        else:
            skipped.append(
                {"provider": provider.name, "reason": f"{provider.env_key} not set"}
            )
    return selected, skipped


from .abuseipdb import AbuseIPDB
from .crtsh import CrtSh
from .dns_records import DnsRecords
from .greynoise import GreyNoise
from .internetdb import InternetDb
from .ipapi import IpApi
from .ipinfo import IpInfo
from .mitre_cve import MitreCve
from .nvd import Nvd
from .osv import Osv
from .otx_domain import OtxDomain
from .otx_ip import OtxIp
from .rdap import Rdap
from .reverse_dns import ReverseDns
from .shodan import Shodan
from .urlscan import UrlScan
from .virustotal import VirusTotalIP, VirusTotalURL

PROVIDERS.extend([IpApi(), UrlScan(), Nvd(), MitreCve(), Osv()])
PROVIDERS.extend([Rdap(), DnsRecords(), CrtSh(), OtxDomain()])
PROVIDERS.extend([IpInfo(), InternetDb(), ReverseDns(), OtxIp()])
PROVIDERS.extend(
    [
        AbuseIPDB(),
        VirusTotalIP(),
        VirusTotalURL(),
        GreyNoise(),
        Shodan(),
    ]
)
