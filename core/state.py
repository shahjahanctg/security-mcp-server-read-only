import os
import json
from typing import Optional


def write_state(state: dict, path: str | None = None) -> str:
    p = path or "./.mcp_state.json"
    with open(p, "w") as f:
        json.dump(state, f, indent=2, sort_keys=True)
    try:
        os.chmod(p, 0o600)
    except Exception:
        pass
    return p


def read_state(path: str = "./.mcp_state.json") -> dict:
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    with open(path) as f:
        return json.load(f)


def delete_state(path: str = "./.mcp_state.json") -> None:
    try:
        os.remove(path)
    except FileNotFoundError:
        pass
    except OSError:
        pass
