import os
from abc import ABC, abstractmethod
from typing import final

from core.schemas import ProviderResult, now_iso


class ProviderError(Exception):
    pass


class RateLimited(ProviderError):
    pass


class Provider(ABC):
    name: str
    tool: str
    env_key: str | None = None

    def available(self) -> bool:
        if self.env_key is None:
            return True
        return bool(os.environ.get(self.env_key))

    @abstractmethod
    def mock_raw(self, value: str) -> dict:
        ...

    @abstractmethod
    async def fetch(self, value: str) -> dict:
        ...

    @abstractmethod
    def normalize(self, value: str, raw: dict) -> ProviderResult:
        ...

    @final
    async def run(self, value: str) -> ProviderResult:
        try:
            if os.environ.get("MOCK") == "1":
                raw = self.mock_raw(value)
            else:
                raw = await self.fetch(value)
            return self.normalize(value, raw)
        except RateLimited:
            raise
        except Exception as e:
            return ProviderResult(
                source=self.name,
                ok=False,
                verdict="error",
                severity="unknown",
                summary=f"{self.name} lookup failed",
                data={},
                error=str(e) or type(e).__name__,
                retrieved_at=now_iso(),
            )
