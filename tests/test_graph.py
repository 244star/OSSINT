from ossint.graph import CorrelationGraph
from ossint.models import Confidence, Finding, Identifier, IdentifierType


def test_score_counts_sources_not_pivot_edges():
    graph = CorrelationGraph()
    identifier = Identifier(IdentifierType.EMAIL, "jane@example.com")
    pivot = Identifier(IdentifierType.USERNAME, "janedoe")
    graph.add_finding(Finding(
        source="one", identifier=identifier, confidence=Confidence.VERIFIED,
        pivots=[pivot]))
    assert graph.score(identifier.key()) == 1
    assert graph.score(pivot.key()) == 0

    graph.add_finding(Finding(
        source="two", identifier=identifier, confidence=Confidence.LIKELY))
    assert graph.score(identifier.key()) == 2
