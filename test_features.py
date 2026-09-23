"""Temporary self-test for the GML + proxy features (removed after verification)."""
import asyncio
import os

os.environ["OSINT_PROXY"] = "http://127.0.0.1:9999"

from osint.graph import CorrelationGraph
from osint.models import Confidence, Finding, Identifier, IdentifierType
from osint.orchestrator import Orchestrator
from osint.reporting import graph_dict_to_gml, graph_to_dict, graph_to_gml


async def make_client(orch):
    c = await orch._client()
    await c.aclose()


def main() -> None:
    # 1. proxy: explicit param wins over env, env fallback works
    o_env = Orchestrator(max_depth=1)
    assert o_env.proxy == "http://127.0.0.1:9999", o_env.proxy
    o_exp = Orchestrator(max_depth=1, proxy="http://u:p@h:8080")
    assert o_exp.proxy == "http://u:p@h:8080", o_exp.proxy
    asyncio.run(make_client(o_exp))
    # 2. GML from a live graph
    g = CorrelationGraph()
    f = Finding(source="hibp",
                identifier=Identifier(IdentifierType.EMAIL, "a@b.com"),
                confidence=Confidence.VERIFIED, url="https://x",
                details={"breaches": ["Acme 2021"]})
    g.add_finding(f)
    gml = graph_to_gml(g)
    assert "graph" in gml and "a@b.com" in gml and "hibp" in gml
    # 3. GML rebuilt from the stored dict (fallback path)
    gml2 = graph_dict_to_gml(graph_to_dict(g))
    assert "a@b.com" in gml2 and "observed_in" in gml2
    print("FEATURE_OK")


if __name__ == "__main__":
    main()
