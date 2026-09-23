"""Lightweight on-disk cache for source query results.

Keyed by ``source_name:identifier_key``, so re-running the same identifier
doesn't re-burn API quota (HIBP, Serper, etc.) or re-hit rate-limited
endpoints. Stored as a single JSON file — simple, human-inspectable, and
fine for the request volumes a personal OSINT run produces.

Disable globally with OSINT_NO_CACHE=1, or override a source's TTL via
its ``cache_ttl`` class attribute (0 disables caching for that source).
"""
from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from threading import Lock
from typing import Any

log = logging.getLogger("osint")

DEFAULT_PATH = Path(os.getenv("OSINT_CACHE_PATH", ".osint_cache.json"))
DEFAULT_TTL = float(os.getenv("OSINT_CACHE_TTL", 86400))  # 24h


class Cache:
    def __init__(self, path: Path = DEFAULT_PATH):
        self.path = path
        self._lock = Lock()
        self._data: dict[str, dict[str, Any]] = {}
        self._disabled = os.getenv("OSINT_NO_CACHE") == "1"
        self._load()

    def _load(self) -> None:
        if self._disabled or not self.path.exists():
            return
        try:
            self._data = json.loads(self.path.read_text())
        except (json.JSONDecodeError, OSError) as exc:
            log.warning("cache: failed to load %s (%s), starting fresh", self.path, exc)
            self._data = {}

    def _flush(self) -> None:
        if self._disabled:
            return
        try:
            self.path.write_text(json.dumps(self._data))
        except OSError as exc:
            log.warning("cache: failed to write %s (%s)", self.path, exc)

    def get(self, key: str, ttl: float) -> list | None:
        """Return cached findings (as plain dicts) if present and fresh, else None."""
        if self._disabled or ttl <= 0:
            return None
        with self._lock:
            entry = self._data.get(key)
        if entry is None:
            return None
        if time.time() - entry["ts"] > ttl:
            return None
        return entry["value"]

    def set(self, key: str, value: list) -> None:
        if self._disabled:
            return
        with self._lock:
            self._data[key] = {"ts": time.time(), "value": value}
            self._flush()

    def clear(self) -> None:
        with self._lock:
            self._data = {}
            self._flush()


# Module-level singleton: one cache file per process, shared across sources.
_instance: Cache | None = None


def get_cache() -> Cache:
    global _instance
    if _instance is None:
        _instance = Cache()
    return _instance
