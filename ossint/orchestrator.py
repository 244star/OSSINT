from __future__ import annotations
import asyncio
import logging
import os
from collections import deque

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
DEFAULT_MAX_IDENTIFIERS = 500
DEFAULT_MAX_FINDINGS = 1000
PLATFORM_DOMAINS = (
    "linkedin.com", "x.com", "instagram.com", "facebook.com", "tiktok.com",
    "github.com", "medium.com", "pinterest.com", "youtube.com", "reddit.com",
    "threads.net", "bsky.app", "twitch.tv", "snapchat.com", "t.me",
    "tumblr.com", "soundcloud.com", "kick.com", "substack.com",
)


def expand(identifier: Identifier) -> list:
    """Pivot expansion: identifier -> candidate new identifiers."""
    if identifier.type == IdentifierType.NAME:
        return [Identifier(IdentifierType.USERNAME, u) for u in username_candidates(identifier.value)]
    return []


class Orchestrator:
    def __init__(self, max_depth: int = 2, proxy: str | None = None,
                 platform: str | None = None, include_sources: set[str] | None = None,
                 exclude_sources: set[str] | None = None,
                 max_identifiers: int | None = None, max_findings: int | None = None):
        if not 0 <= max_depth <= MAX_DEPTH:
            raise ValueError(f"max_depth must be between 0 and {MAX_DEPTH}")
        self.graph = CorrelationGraph()
        self.seen: set = set()
        self.max_depth = max_depth
        self.max_identifiers = (int(os.environ.get(
            "OSSINT_MAX_IDENTIFIERS", DEFAULT_MAX_IDENTIFIERS))
            if max_identifiers is None else max_identifiers)
        self.max_findings = (int(os.environ.get(
            "OSSINT_MAX_FINDINGS", DEFAULT_MAX_FINDINGS))
            if max_findings is None else max_findings)
        if self.max_identifiers < 1 or self.max_findings < 1:
            raise ValueError("search limits must be positive")
        self._query_limit = asyncio.Semaphore(MAX_CONCURRENT_QUERIES)
        self.source_stats: dict[str, dict[str, int]] = {}
        # A platform page uses a dedicated site-restricted Serper source while
        # preserving the other public and optional sources.
        if platform == "all":
            dork_sources = [SerperDorkSource(site) for site in PLATFORM_DOMAINS]
            sources = REGISTRY + [MaigretSource(), SocialscanSource(),
                       *dork_sources, TelegramPhoneSource(), HibpSource()]
        else:
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
            await self._search_queue(seed, client)
        finally:
            await client.aclose()
        return self.graph

    async def _search_queue(self, seed: Identifier, client: httpx.AsyncClient):
        queue = deque([(seed, 0)])
        while queue and len(self.seen) < self.max_identifiers:
            batch = []
            while queue and len(batch) < MAX_CONCURRENT_QUERIES:
                identifier, depth = queue.popleft()
                if identifier.key() in self.seen or depth > self.max_depth:
                    continue
                self.seen.add(identifier.key())
                batch.append((identifier, depth))
            if not batch:
                continue

            tasks = []
            for i, depth in batch:
                for s in self.sources:
                    if s.enabled and i.type in s.handles:
                        tasks.append((asyncio.create_task(self._query(s, i, client)), depth))

            if tasks:
                results = await asyncio.gather(*(task for task, _ in tasks))
                for findings, (_, depth) in zip(results, tasks):
                    for f in findings:
                        if len(self.graph.findings) >= self.max_findings:
                            break
                        log.info("hit: %s via %s [%s]", f.identifier, f.source, f.confidence.value)
                        self.graph.add_finding(f)
                        for pivot in f.pivots:
                            if len(self.seen) + len(queue) >= self.max_identifiers:
                                break
                            queue.append((pivot, depth + 1))

            for identifier, depth in batch:
                for pivot in expand(identifier):
                    if len(self.seen) + len(queue) >= self.max_identifiers:
                        break
                    queue.append((pivot, depth + 1))

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
