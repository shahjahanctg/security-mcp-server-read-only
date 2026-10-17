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
