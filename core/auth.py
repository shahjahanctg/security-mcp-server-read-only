import os
import secrets
import hmac
from typing import Optional

from fastmcp.server.auth import TokenVerifier, AccessToken


def resolve_key() -> str:
    env_key = os.getenv("MCP_API_KEY")
    if env_key:
        return env_key
    return secrets.token_urlsafe(32)


class KeyVerifier(TokenVerifier):
    def __init__(self, key: str):
        super().__init__(base_url=None)
        self.key = key

    async def verify_token(self, token: str) -> AccessToken | None:
        if hmac.compare_digest(token or "", self.key):
            return AccessToken(token=token, client_id="mcp-client", scopes=[])
        return None
