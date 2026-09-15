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

log = logging.getLogger("ossint")

ACTIVE_SOURCES = REGISTRY + [MaigretSource(), SocialscanSource(),
                             SerperDorkSource(), TelegramPhoneSource(),
                             HibpSource()]

UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) ossint/0.1"}
MAX_DEPTH = 4
MAX_CONCURRENT_QUERIES = 20


def expand(identifier: Identifier) -> list:
    """Pivot expansion: identifier -> candidate new identifiers."""
    if identifier.type == IdentifierType.NAME:
        return [Identifier(IdentifierType.USERNAME, u) for u in username_candidates(identifier.value)]
    return []


class Orchestrator:
    def __init__(self, max_depth: int = 2, proxy: str | None = None,
                 platform: str | None = None, include_sources: set[str] | None = None,
                 exclude_sources: set[str] | None = None):
        if not 0 <= max_depth <= MAX_DEPTH:
            raise ValueError(f"max_depth must be between 0 and {MAX_DEPTH}")
        self.graph = CorrelationGraph()
        self.seen: set = set()
        self.max_depth = max_depth
        self._query_limit = asyncio.Semaphore(MAX_CONCURRENT_QUERIES)
        self.source_stats: dict[str, dict[str, int]] = {}
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
        # Explicit proxy wins; otherwise fall back to OSSINT_PROXY env var.
        self.proxy = proxy or os.environ.get("OSSINT_PROXY") or None

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
                    tasks.append(asyncio.create_task(self._query(s, i, client)))

        next_wave: list = []
        if tasks:
            for task in asyncio.as_completed(tasks):
                for f in await task:
                    log.info("hit: %s via %s [%s]", f.identifier, f.source, f.confidence.value)
                    self.graph.add_finding(f)
                    next_wave.extend(f.pivots)
        next_wave += [p for i in fresh for p in expand(i)]
        await self._wave(next_wave, depth + 1, client)

    async def _query(self, source, identifier, client):
        async with self._query_limit:
            findings, status, error = await source.safe_query_with_status(identifier, client)
        stats = self.source_stats.setdefault(
            source.name, {"queries": 0, "findings": 0, "cached": 0,
                          "failed": 0, "errors": {}})
        stats["queries"] += 1
        stats["findings"] += len(findings)
        stats[status] = stats.get(status, 0) + 1
        if error:
            stats["errors"][error] = stats["errors"].get(error, 0) + 1
        return findings
