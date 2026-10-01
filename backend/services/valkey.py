import os
from typing import Any


class ValkeyService:
    def __init__(self, url: str | None = None, enabled: bool | None = None) -> None:
        self.url = url or os.getenv("VALKEY_URL", "redis://localhost:6379/0")
        self.enabled = enabled if enabled is not None else os.getenv("AGENTGUARD_ENV", "replay") != "replay"

    async def set_ephemeral(self, key: str, value: Any, ttl_seconds: int) -> bool:
        if not self.enabled:
            return False
        from redis.asyncio import Redis

        client = Redis.from_url(self.url)
        try:
            return bool(await client.set(key, str(value), ex=ttl_seconds))
        finally:
            await client.aclose()
