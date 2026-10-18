import asyncio
import json
import os
import pathlib
import sys

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

_ROOT = pathlib.Path(__file__).resolve().parent.parent

_EXPECTED_TOOLS = {"check_ip", "check_url", "lookup_cve", "check_domain", "check_hash"}

_CALLS = [
    ("check_ip", {"ip": "8.8.8.8"}),
    ("check_url", {"url": "https://example.com/"}),
    ("lookup_cve", {"cve_id": "CVE-2021-44228"}),
    ("check_domain", {"domain": "example.com"}),
    ("check_hash", {"file_hash": "d41d8cd98f00b204e9800998ecf8427e"}),
]


def _parse(result) -> dict:
    for item in result.content:
        text = getattr(item, "text", None)
        if text:
            return json.loads(text)
    raise AssertionError("tool returned no text content")


async def _run() -> None:
    env = {**os.environ, "MOCK": "1"}
    params = StdioServerParameters(
        command=sys.executable,
        args=["server.py"],
        env=env,
        cwd=str(_ROOT),
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            tools = await session.list_tools()
            names = {tool.name for tool in tools.tools}
            missing = _EXPECTED_TOOLS - names
            assert not missing, f"missing tools: {sorted(missing)}"
            assert len(names) == 5, f"expected 5 tools, got {len(names)}: {sorted(names)}"
            print(f"tools/list OK: {sorted(names)}")

            for name, arguments in _CALLS:
                result = await session.call_tool(name, arguments)
                payload = _parse(result)
                assert "verdict" in payload, f"{name}: no verdict"
                assert "results" in payload, f"{name}: no results"
                print(
                    f"{name}({arguments}) OK: verdict={payload['verdict']} "
                    f"queried={payload['queried']}"
                )


def main() -> int:
    try:
        asyncio.run(_run())
    except Exception as exc:
        print(f"FAIL: {type(exc).__name__}: {exc}")
        return 1
    print("PASS: all smoke checks succeeded")
    return 0


if __name__ == "__main__":
    sys.exit(main())
