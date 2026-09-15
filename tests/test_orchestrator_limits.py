import pytest

from ossint.orchestrator import Orchestrator


def test_search_limits_are_configurable():
    orchestrator = Orchestrator(max_identifiers=3, max_findings=4)
    assert orchestrator.max_identifiers == 3
    assert orchestrator.max_findings == 4


@pytest.mark.parametrize("kwargs", [
    {"max_identifiers": 0},
    {"max_findings": 0},
])
def test_search_limits_must_be_positive(kwargs):
    with pytest.raises(ValueError, match="limits"):
        Orchestrator(**kwargs)
