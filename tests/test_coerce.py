import pytest

from ossint.__main__ import coerce
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
