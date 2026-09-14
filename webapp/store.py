from __future__ import annotations
import json
import time
import uuid
from pathlib import Path

from ossint.reporting import graph_to_dict, graph_to_gml


class ReportStore:
    """Persists each search's correlation graph (JSON + GML) in <project>/reports/."""

    def __init__(self, directory: Path):
        self.directory = directory
        self.directory.mkdir(parents=True, exist_ok=True)

    def create(self, ident, graph) -> str:
        rid = uuid.uuid4().hex[:12]
        data = {"id": rid, "seed": ident.key(), "created": time.time(),
                "graph": graph_to_dict(graph), "gml": graph_to_gml(graph)}
        (self.directory / f"{rid}.json").write_text(
            json.dumps(data, indent=2, default=str), encoding="utf-8")
        return rid

    def load(self, rid: str):
        p = self.directory / f"{rid}.json"
        if not p.exists():
            return None
        return json.loads(p.read_text(encoding="utf-8"))

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
