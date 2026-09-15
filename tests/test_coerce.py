import pytest

from ossint.__main__ import MAX_IDENTIFIER_LENGTH, coerce
from ossint.orchestrator import MAX_DEPTH, Orchestrator
from ossint.models import IdentifierType


class TestCoerceAutoDetect:
    def test_email(self):
        assert coerce("jane@example.com").type == IdentifierType.EMAIL

    @pytest.mark.parametrize("raw", [
        "+1 650 253 0000", "(650) 253-0000", "650-253-0000", "+16502530000",
    ])
    def test_phone_with_common_formatting(self, raw):
        # Regression: phone numbers containing spaces/parens/dashes must not
        # be misclassified as NAME just because they contain whitespace.
        assert coerce(raw).type == IdentifierType.PHONE

    def test_name_with_spaces(self):
        assert coerce("John Doe").type == IdentifierType.NAME

    def test_domain(self):
        assert coerce("example.com").type == IdentifierType.DOMAIN

    def test_bare_username(self):
        assert coerce("jdoe123").type == IdentifierType.USERNAME


class TestCoerceForcedType:
    def test_forced_type_overrides_detection(self):
        # "jane.doe" would otherwise be ambiguous (domain-shaped, but really a username)
        ident = coerce("jane.doe", forced_type="username")
        assert ident.type == IdentifierType.USERNAME
        assert ident.value == "jane.doe"

    def test_forced_domain(self):
        assert coerce("Example.COM", forced_type="domain").value == "example.com"

    def test_rejects_empty_identifier(self):
        with pytest.raises(ValueError, match="cannot be empty"):
            coerce("  ")

    def test_rejects_oversized_identifier(self):
        with pytest.raises(ValueError, match="cannot exceed"):
            coerce("x" * (MAX_IDENTIFIER_LENGTH + 1))

    @pytest.mark.parametrize("depth", [-1, MAX_DEPTH + 1])
    def test_rejects_unsafe_depth(self, depth):
        with pytest.raises(ValueError, match="max_depth"):
            Orchestrator(max_depth=depth)
