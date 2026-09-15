from __future__ import annotations
import io
from collections import defaultdict

import networkx as nx


def render_markdown(graph) -> str:
    """Render a human-readable markdown report from the correlation graph."""
    lines = ["# OSSINT Report", ""]
    by_type = defaultdict(list)
    for n, d in graph.g.nodes(data=True):
        if d.get("label") == "identifier":
            by_type[d["type"]].append((n, d))
    for t, nodes in sorted(by_type.items()):
        if not nodes:
            continue
        lines += [f"## {t.upper()} ({len(nodes)})", ""]
        lines += ["| Identifier | Corroboration |", "|---|---|"]
        for key, d in sorted(nodes, key=lambda x: -graph.score(x[0])):
            lines.append(f"| `{d['value']}` | {graph.score(key)} |")
        lines.append("")
    lines += ["## Findings", ""]
    for u, v, d in graph.g.edges(data=True):
        if d.get("kind") == "observed_in":
            lines.append(f"- `{u}` observed via `{v}` [{d['confidence']}]")
    return "\n".join(lines)


def graph_to_dict(graph) -> dict:
    """Serialize the correlation graph + findings into a JSON-safe dict."""
    identifiers = []
    for n, d in graph.g.nodes(data=True):
        if d.get("label") == "identifier":
            identifiers.append({"key": n, "type": d["type"], "value": d["value"],
                                "score": graph.score(n)})
    findings = []
    for f in graph.findings:
        findings.append({
            "source": f.source,
            "identifier": {"key": f.identifier.key(), "type": f.identifier.type.value,
                           "value": f.identifier.value},
            "confidence": f.confidence.value,
            "url": f.url,
            "details": f.details,
            "pivots": [p.to_dict() for p in f.pivots],
        })
    pivots = []
    for u, v, d in graph.g.edges(data=True):
        if d.get("kind") == "co-occurrence":
            pivots.append({"from": u, "to": v, "weight": d.get("weight", 1)})
    return {"identifiers": identifiers, "findings": findings, "pivots": pivots}


def _write_gml(g) -> str:
    """networkx GML writer needs a binary stream; return the decoded text."""
    buf = io.BytesIO()
    nx.write_gml(g, buf)
    return buf.getvalue().decode("ascii")


def graph_to_gml(graph) -> str:
    """Serialize the live correlation graph as GML text (Gephi / yEd compatible)."""
    return _write_gml(graph.g)


def graph_dict_to_gml(data: dict) -> str:
    """Fallback: rebuild a networkx graph from a stored graph dict, emit GML."""
    g = nx.Graph()
    for i in data.get("identifiers", []):
        g.add_node(i["key"], label="identifier", type=i.get("type", "identifier"),
                   value=i.get("value", ""), score=i.get("score", 0))
    for f in data.get("findings", []):
        ident = f.get("identifier") or {}
        src = f"src:{f.get('source', '?')}"
        ident_key = ident.get("key")
        if ident_key is None:
            continue
        if not g.has_node(ident_key):
            g.add_node(ident_key, label="identifier", type=ident.get("type", "identifier"),
                       value=ident.get("value", ident_key), score=0)
        if not g.has_node(src):
            g.add_node(src, label="source")
        g.add_edge(ident_key, src, kind="observed_in",
                   confidence=f.get("confidence", "unsure"))
    for p in data.get("pivots", []):
        g.add_edge(p["from"], p["to"], kind="co-occurrence",
                   weight=p.get("weight", 1))
    try:
        return _write_gml(g)
    except Exception:
        return ""
