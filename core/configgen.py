import json


def render_client(client: str, state: dict) -> str:
    url, key = state["url"], state["key"]
    if client == "opencode":
        return json.dumps(
            {
                "mcp": {
                    "security": {
                        "type": "remote",
                        "url": url,
                        "headers": {"Authorization": f"Bearer {key}"},
                    }
                }
            },
            indent=2,
        )
    if client == "claude":
        return json.dumps(
            {
                "mcpServers": {
                    "security": {
                        "type": "http",
                        "url": url,
                        "headers": {"Authorization": f"Bearer {key}"},
                    }
                }
            },
            indent=2,
        )
    if client == "cursor":
        return json.dumps(
            {
                "mcpServers": {
                    "security": {
                        "url": url,
                        "headers": {"Authorization": f"Bearer {key}"},
                    }
                }
            },
            indent=2,
        )
    if client == "cline":
        return json.dumps(
            {
                "mcpServers": {
                    "security": {
                        "url": url,
                        "headers": {"Authorization": f"Bearer {key}"},
                    }
                }
            },
            indent=2,
        )
    if client == "mcp-remote" or client == "generic":
        return f'npx -y mcp-remote "{url}" --header "Authorization: Bearer {key}"'
    raise ValueError(f"Unknown client: {client}")


def render_all(state: dict) -> str:
    parts = []
    for c in ["opencode", "claude", "cursor", "cline", "mcp-remote"]:
        parts.append(f"=== {c} ===")
        parts.append(render_client(c, state))
        parts.append("")
    return "\n".join(parts)
