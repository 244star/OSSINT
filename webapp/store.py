from __future__ import annotations
import json
import os
import re
import tempfile
import time
import uuid
import logging
from pathlib import Path

from ossint.reporting import graph_to_dict, graph_to_gml

log = logging.getLogger("ossint.web")


class ReportStore:
    """Persists each search's correlation graph (JSON + GML) in <project>/reports/."""

    def __init__(self, directory: Path):
        self.directory = directory
        self.directory.mkdir(parents=True, exist_ok=True)

    def create(self, ident, graph, source_stats: dict | None = None) -> str:
        rid = uuid.uuid4().hex[:12]
        data = {"id": rid, "seed": ident.key(), "created": time.time(),
                "graph": graph_to_dict(graph), "gml": graph_to_gml(graph),
                "source_stats": source_stats or {}}
        self._write_json(self.directory / f"{rid}.json", data)
        return rid

    def load(self, rid: str):
        if not re.fullmatch(r"[0-9a-f]{12}", rid):
            return None
        p = self.directory / f"{rid}.json"
        if not p.exists():
            return None
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            log.warning("report: failed to load %s (%s)", p, exc)
            return None

    def delete(self, rid: str) -> bool:
        if not re.fullmatch(r"[0-9a-f]{12}", rid):
            return False
        path = self.directory / f"{rid}.json"
        try:
            path.unlink()
        except FileNotFoundError:
            return False
        return True

    @staticmethod
    def _write_json(path: Path, data: dict) -> None:
        temporary_path = None
        try:
            with tempfile.NamedTemporaryFile(
                    mode="w", encoding="utf-8", dir=path.parent,
                    prefix=f".{path.name}.", suffix=".tmp", delete=False) as handle:
                temporary_path = Path(handle.name)
                json.dump(data, handle, indent=2, default=str)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_path, path)
        except OSError:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)
            raise

    def _row(self, data: dict) -> dict:
        total = len((data.get("graph") or {}).get("findings", []))
        return {"id": data["id"], "seed": data["seed"], "total": total,
                "when": time.strftime("%Y-%m-%d %H:%M",
                                      time.localtime(data["created"]))}

    def _items(self, limit: int | None = None) -> list:
        files = sorted(self.directory.glob("*.json"),
                       key=lambda f: f.stat().st_mtime, reverse=True)
        if limit:
            files = files[:limit]
        items = []
        for p in files:
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                continue
            items.append(self._row(data))
        return items

    def list_recent(self, limit: int = 10) -> list:
        return self._items(limit=limit)

    def list_all(self) -> list:
        return self._items()
