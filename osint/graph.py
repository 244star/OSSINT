from __future__ import annotations
import networkx as nx

from .models import Finding


class CorrelationGraph:
    def __init__(self):
        self.g = nx.Graph()
        self.findings: list = []

    def add_finding(self, f: Finding) -> None:
        self.findings.append(f)
        src = f"src:{f.source}"
        ident_key = f.identifier.key()
        if not self.g.has_node(ident_key):
            self.g.add_node(ident_key, **{"type": f.identifier.type.value,
                                          "value": f.identifier.value,
                                          "label": "identifier"})
        if not self.g.has_node(src):
            self.g.add_node(src, **{"label": "source"})
        self.g.add_edge(ident_key, src, kind="observed_in", confidence=f.confidence.value)
        for pivot in f.pivots:
            pkey = pivot.key()
            if not self.g.has_node(pkey):
                self.g.add_node(pkey, **{"type": pivot.type.value, "value": pivot.value,
                                         "label": "identifier"})
            # edge weight accumulates corroboration across sources
            if self.g.has_edge(ident_key, pkey):
                self.g[ident_key][pkey]["weight"] += 1
            else:
                self.g.add_edge(ident_key, pkey, kind="co-occurrence", weight=1)

    def score(self, key: str) -> int:
        """Corroboration = sum of edge weights (multiple independent hits = strong)."""
        if key not in self.g:
            return 0
        return sum(d.get("weight", 1) for _, _, d in self.g.edges(key, data=True))

    def save(self, path: str) -> None:
        nx.write_gml(self.g, path)
