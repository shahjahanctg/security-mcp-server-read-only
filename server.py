import asyncio
from dataclasses import asdict

from fastmcp import FastMCP

from core.cache import TTLCache
from core.ratelimit import RateLimiter
from core.schemas import (
    ProviderResult,
    now_iso,
    validate_cve,
    validate_ip,
    validate_url,
)
from core.verdict import roll_up
from mock import cache_ttl
from providers import for_tool
from providers.base import RateLimited

_RATE_LIMITS = {
    "abuseipdb": 0.5,
    "virustotal_ip": 0.15,
    "virustotal_url": 0.15,
    "greynoise": 1.0,
    "shodan": 1.0,
    "ipapi": 0.66,
    "urlscan": 1.0,
    "nvd": 0.8,
    "mitre_cve": 1.0,
    "osv": 1.0,
}

_VALIDATORS = {
    "ip": validate_ip,
    "url": validate_url,
    "cve": validate_cve,
}

_CACHE = TTLCache(ttl=cache_ttl(), maxsize=1000)
_LIMITERS: dict[str, RateLimiter] = {}


async def _run_with_limit(provider, value: str) -> ProviderResult:
    limiter = _LIMITERS.setdefault(
        provider.name, RateLimiter(_RATE_LIMITS.get(provider.name, 1.0))
    )
    await limiter.acquire()
    try:
        return await provider.run(value)
    except RateLimited:
        await limiter.acquire()
        try:
            return await provider.run(value)
        except RateLimited:
            return ProviderResult(
                source=provider.name,
                ok=False,
                verdict="error",
                severity="unknown",
                summary=f"{provider.name} rate limited",
                data={},
                error="rate_limited",
                retrieved_at=now_iso(),
            )
    except Exception as exc:
        return ProviderResult(
            source=provider.name,
            ok=False,
            verdict="error",
            severity="unknown",
            summary=f"{provider.name} lookup failed",
            data={},
            error=str(exc) or type(exc).__name__,
            retrieved_at=now_iso(),
        )


async def investigate(
    tool: str, value: str, providers: list[str] | None = None
) -> dict:
    normalized = _VALIDATORS[tool](value)
    key = (tool, normalized, tuple(providers) if providers is not None else None)
    cached = _CACHE.get(key)
    if cached is not None:
        return cached
    selected, skipped = for_tool(tool, providers)
    results = await asyncio.gather(
        *(_run_with_limit(provider, normalized) for provider in selected)
    )
    verdict, severity, summary = roll_up(list(results))
    response = {
        "input": normalized,
        "type": tool,
        "verdict": verdict,
        "severity": severity,
        "summary": summary,
        "queried": [provider.name for provider in selected],
        "skipped": skipped,
        "results": [asdict(result) for result in results],
        "retrieved_at": now_iso(),
    }
    _CACHE.set(key, response)
    return response


mcp = FastMCP("security")


@mcp.tool()
async def check_ip(ip: str, providers: list[str] | None = None) -> dict:
    """Read-only IP reputation and geolocation lookup across configured providers."""
    return await investigate("ip", ip, providers)


@mcp.tool()
async def check_url(url: str, providers: list[str] | None = None) -> dict:
    """Read-only URL reputation lookup across configured providers."""
    return await investigate("url", url, providers)


@mcp.tool()
async def lookup_cve(cve_id: str, providers: list[str] | None = None) -> dict:
    """Read-only CVE vulnerability lookup across configured providers."""
    return await investigate("cve", cve_id, providers)


if __name__ == "__main__":
    mcp.run()
