from __future__ import annotations
import abc
import asyncio
import logging
import time

import httpx

from ..cache import get_cache
from ..models import Finding, Identifier

log = logging.getLogger("osint")

# Exceptions worth retrying: transient network hiccups, not logic bugs.
RETRYABLE = (httpx.TimeoutException, httpx.ConnectError, httpx.ReadError, asyncio.TimeoutError)


class Source(abc.ABC):
    name: str = "base"
    handles: set = set()
    enabled: bool = True
    min_interval: float = 0.0          # per-source rate limit (seconds)
    cache_ttl: float = 86400.0         # seconds; 0 disables caching for this source
    max_retries: int = 2               # additional attempts after the first, on RETRYABLE errors
    retry_backoff: float = 0.5         # seconds, doubled each retry
    _last_call: float = 0.0

    async def rate_limit(self) -> None:
        wait = self.min_interval - (time.monotonic() - self._last_call)
        if wait > 0:
            await asyncio.sleep(wait)
        self._last_call = time.monotonic()

    @abc.abstractmethod
    async def query(self, identifier: Identifier, client: httpx.AsyncClient) -> list:
        ...

    def _cache_key(self, identifier: Identifier) -> str:
        return f"{self.name}:{identifier.key()}"

    async def safe_query(self, identifier: Identifier, client: httpx.AsyncClient) -> list:
        """Never let one dead source kill the pipeline (module-rot defense).

        Also handles result caching and retries on transient (network/timeout)
        errors so a single flaky request doesn't drop a source's findings for
        the whole run.
        """
        key = self._cache_key(identifier)
        cached = get_cache().get(key, self.cache_ttl)
        if cached is not None:
            log.debug("[%s] cache hit for %s", self.name, identifier)
            return [Finding.from_dict(d) for d in cached]

        attempt = 0
        while True:
            try:
                await self.rate_limit()
                findings = await asyncio.wait_for(self.query(identifier, client), timeout=30)
                get_cache().set(key, [f.to_dict() for f in findings])
                return findings
            except RETRYABLE as exc:
                if attempt >= self.max_retries:
                    log.warning("[%s] giving up on %s after %d attempts: %s",
                                self.name, identifier, attempt + 1, exc)
                    return []
                delay = self.retry_backoff * (2 ** attempt)
                log.info("[%s] retryable error on %s (%s), retrying in %.1fs",
                         self.name, identifier, exc, delay)
                await asyncio.sleep(delay)
                attempt += 1
            except Exception as exc:
                # Non-transient (bad JSON, bug, unexpected shape, etc.) — don't
                # retry, just log and move on so one source can't stall a run.
                log.warning("[%s] failed on %s: %s", self.name, identifier, exc)
                return []
