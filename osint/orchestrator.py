from __future__ import annotations
import asyncio
import logging
import os

import httpx

from .graph import CorrelationGraph
from .models import Identifier, IdentifierType
from .normalizers import username_candidates
from .sources import REGISTRY
from .sources.wrappers import MaigretSource, SocialscanSource
from .sources.dorks import SerperDorkSource
from .sources.telegram_phone import TelegramPhoneSource
from .sources.breaches import HibpSource

log = logging.getLogger("osint")

ACTIVE_SOURCES = REGISTRY + [MaigretSource(), SocialscanSource(),
                             SerperDorkSource(), TelegramPhoneSource(),
                             HibpSource()]

UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) osint/0.1"}


def expand(identifier: Identifier) -> list:
    """Pivot expansion: identifier -> candidate new identifiers."""
    if identifier.type == IdentifierType.NAME:
        return [Identifier(IdentifierType.USERNAME, u) for u in username_candidates(identifier.value)]
    return []


class Orchestrator:
    def __init__(self, max_depth: int = 2, proxy: str | None = None,
                 platform: str | None = None, include_sources: set[str] | None = None,
                 exclude_sources: set[str] | None = None):
        self.graph = CorrelationGraph()
        self.seen: set = set()
        self.max_depth = max_depth
        # A platform page uses a dedicated site-restricted Serper source while
        # preserving the other public and optional sources.
        sources = (REGISTRY + [MaigretSource(), SocialscanSource(),
                   SerperDorkSource(platform), TelegramPhoneSource(), HibpSource()]
                   if platform else ACTIVE_SOURCES)
        if include_sources:
            sources = [s for s in sources if s.name in include_sources]
        if exclude_sources:
            sources = [s for s in sources if s.name not in exclude_sources]
        self.sources = sources
        # Explicit proxy wins; otherwise fall back to OSINT_PROXY env var.
        self.proxy = proxy or os.environ.get("OSINT_PROXY") or None

    @staticmethod
    def _http2_available() -> bool:
        """httpx needs the optional `h2` package for http2=True; degrade to
        HTTP/1.1 instead of crashing when it's not installed."""
        try:
            import h2  # noqa: F401
            return True
        except ImportError:
            log.debug("h2 not installed — falling back to HTTP/1.1 (pip install httpx[http2] to enable)")
            return False

    async def _client(self) -> httpx.AsyncClient:
        kwargs = dict(http2=self._http2_available(), follow_redirects=True, timeout=30, headers=UA)
        if self.proxy:
            kwargs["proxy"] = self.proxy
            try:
                return httpx.AsyncClient(**kwargs)
            except TypeError:  # httpx < 0.26: use the legacy proxies mapping
                kwargs.pop("proxy")
                kwargs["proxies"] = {"all://": self.proxy}
        return httpx.AsyncClient(**kwargs)

    async def run(self, seed: Identifier) -> CorrelationGraph:
        client = await self._client()
        try:
            await self._wave([seed], 0, client)
        finally:
            await client.aclose()
        return self.graph

    async def _wave(self, batch: list, depth: int, client: httpx.AsyncClient):
        fresh = [i for i in batch if i.key() not in self.seen]
        self.seen.update(i.key() for i in fresh)
        if not fresh or depth > self.max_depth:
            return

        tasks = []
        for i in fresh:
            for s in self.sources:
                if s.enabled and i.type in s.handles:
                    tasks.append(asyncio.create_task(s.safe_query(i, client)))

        next_wave: list = []
        if tasks:
            for task in asyncio.as_completed(tasks):
                for f in await task:
                    log.info("hit: %s via %s [%s]", f.identifier, f.source, f.confidence.value)
                    self.graph.add_finding(f)
                    next_wave.extend(f.pivots)
        next_wave += [p for i in fresh for p in expand(i)]
        await self._wave(next_wave, depth + 1, client)
