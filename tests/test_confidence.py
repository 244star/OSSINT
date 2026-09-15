import pytest

from ossint.confidence import classify
from ossint.models import Confidence, IdentifierType


class TestClassifyName:
    """Names are collision-prone: require strong corroboration."""

    def test_three_or_more_sources_is_verified(self):
        assert classify(5, 3, IdentifierType.NAME.value) == Confidence.VERIFIED

    def test_fewer_than_three_sources_is_likely(self):
        assert classify(1, 1, IdentifierType.NAME.value) == Confidence.LIKELY
        assert classify(2, 2, IdentifierType.NAME.value) == Confidence.LIKELY

    def test_zero_findings_are_unsure_for_name(self):
        assert classify(0, 0, IdentifierType.NAME.value) == Confidence.UNSURE


class TestClassifyOtherTypes:
    @pytest.mark.parametrize("ident_type", [
        IdentifierType.EMAIL.value, IdentifierType.USERNAME.value,
        IdentifierType.PHONE.value, IdentifierType.DOMAIN.value,
    ])
    def test_verified_needs_finding_and_two_sources(self, ident_type):
        assert classify(1, 2, ident_type) == Confidence.VERIFIED
        assert classify(3, 5, ident_type) == Confidence.VERIFIED

    @pytest.mark.parametrize("ident_type", [
        IdentifierType.EMAIL.value, IdentifierType.USERNAME.value,
    ])
    def test_likely_when_finding_but_single_source(self, ident_type):
        assert classify(1, 1, ident_type) == Confidence.LIKELY

    @pytest.mark.parametrize("ident_type", [
        IdentifierType.EMAIL.value, IdentifierType.USERNAME.value,
    ])
    def test_unsure_when_no_findings(self, ident_type):
        assert classify(0, 0, ident_type) == Confidence.UNSURE
