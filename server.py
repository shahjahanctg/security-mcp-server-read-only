import argparse
import asyncio
import copy
import os
import signal
import sys
from dataclasses import asdict
from datetime import datetime

from fastmcp import FastMCP

from core.cache import TTLCache
from core.ratelimit import RateLimiter
from core.redact import redact
from core.schemas import (
    ProviderResult,
    now_iso,
    validate_cve,
    validate_domain,
    validate_hash,
    validate_ip,
    validate_url,
)
from core.verdict import roll_up
from mock import cache_ttl
from providers import for_tool
from providers.base import RateLimited

from core import auth, configgen, state

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
    "ipinfo": 1.0,
    "internetdb": 5.0,
    "reverse_dns": 5.0,
    "otx_ip": 0.5,
    "rdap": 1.0,
    "dns": 5.0,
    "crtsh": 0.5,
    "otx_domain": 0.5,
    "epss": 1.0,
    "cisa_kev": 0.1,
    "circl": 0.5,
    "virustotal_file": 0.15,
    "otx_file": 0.5,
}

_VALIDATORS = {
    "ip": validate_ip,
    "url": validate_url,
    "cve": validate_cve,
    "domain": validate_domain,
    "hash": validate_hash,
}

_CACHE = TTLCache(ttl=cache_ttl(), maxsize=1000)
_LIMITERS: dict[str, RateLimiter] = {}


def _error_result(source: str, error: str) -> ProviderResult:
    return ProviderResult(
        source=source,
        ok=False,
        verdict="error",
        severity="unknown",
        summary=f"{source} lookup failed",
        data={},
        error=redact(error),
        retrieved_at=now_iso(),
    )


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
            return _error_result(provider.name, str(exc) or type(exc).__name__)
    except Exception as exc:
        return _error_result(provider.name, str(exc) or type(exc).__name__)


async def investigate(
    tool: str, value: str, providers: list[str] | None = None
) -> dict:
    normalized = _VALIDATORS[tool](value)
    key = (tool, normalized, tuple(providers) if providers is not None else None)
    cached = _CACHE.get(key)
    if cached is not None:
        return copy.deepcopy(cached)
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
    _CACHE.set(key, copy.deepcopy(response))
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


@mcp.tool()
async def check_domain(domain: str, providers: list[str] | None = None) -> dict:
    """Read-only domain reputation and registration lookup across configured providers."""
    return await investigate("domain", domain, providers)


@mcp.tool()
async def check_hash(file_hash: str, providers: list[str] | None = None) -> dict:
    """Read-only file hash reputation lookup across configured providers."""
    return await investigate("hash", file_hash, providers)


def main() -> None:
    parser = argparse.ArgumentParser(prog="server.py")
    sub = parser.add_subparsers(dest="command")
    config_parser = sub.add_parser("config", help="Generate client config from running HTTP server state")
    config_parser.add_argument("--client", default=None)
    config_parser.add_argument("--all", action="store_true")
    parser.add_argument("--transport", default=None)

    args = parser.parse_args()

    if args.command == "config":
        try:
            st = state.read_state()
        except FileNotFoundError:
            sys.stderr.write("Server isn't running in HTTP mode. Start it: MCP_TRANSPORT=http .venv/bin/python server.py\n")
            sys.exit(1)
        if args.all or not args.client:
            sys.stdout.write(configgen.render_all(st) + "\n")
            return
        try:
            sys.stdout.write(configgen.render_client(args.client, st) + "\n")
            return
        except Exception as e:
            sys.stderr.write(str(e) + "\n")
            sys.exit(2)

    transport = args.transport or os.getenv("MCP_TRANSPORT") or "stdio"
    if transport == "stdio":
        mcp.run()
        return
    if transport == "http":
        host = os.getenv("MCP_HOST", "127.0.0.1")
        port_str = os.getenv("MCP_PORT", "8765")
        try:
            port = int(port_str)
        except ValueError:
            port = 8765
        key = auth.resolve_key()
        mcp.auth = auth.KeyVerifier(key)
        url = f"http://{host}:{port}/mcp"
        st = {
            "url": url,
            "key": key,
            "host": host,
            "port": port,
            "transport": "streamable-http",
            "started_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        try:
            state.write_state(st)
        except Exception:
            pass

        def _cleanup_and_reraise(signum, frame):
            state.delete_state()
            signal.signal(signum, signal.SIG_DFL)
            signal.raise_signal(signum)

        try:
            signal.signal(signal.SIGTERM, _cleanup_and_reraise)
        except ValueError:
            pass
        print("security MCP — streamable-http")
        print(f"  url:    {url}")
        print(f"  key:    {key}")
        print("  state:  ./.mcp_state.json")
        print("  config: python server.py config --client opencode|claude|cursor|cline|mcp-remote")
        try:
            mcp.run(transport="http", host=host, port=port, path="/mcp")
        finally:
            state.delete_state()
        return
    sys.stderr.write(f"Unknown transport: {transport}\n")
    sys.exit(2)


if __name__ == "__main__":
    main()
