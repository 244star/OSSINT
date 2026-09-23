import pytest

from osint.models import Identifier, IdentifierType
from osint.normalizers import (
    email_permutations, gravatar_hash, looks_like_domain, normalize_domain,
    normalize_email, normalize_phone, username_candidates,
)


class TestNormalizeEmail:
    def test_valid_email_is_lowercased(self):
        ident = normalize_email("Jane.Doe@Example.COM")
        assert ident == Identifier(IdentifierType.EMAIL, "jane.doe@example.com")

    def test_strips_whitespace(self):
        ident = normalize_email("  bob@example.com  ")
        assert ident.value == "bob@example.com"

    @pytest.mark.parametrize("bad", ["not-an-email", "missing@domain", "@nodomain.com", ""])
    def test_rejects_invalid(self, bad):
        with pytest.raises(ValueError):
            normalize_email(bad)


class TestNormalizePhone:
    def test_valid_us_number_formats_e164(self):
        ident = normalize_phone("(650) 253-0000", default_region="US")
        assert ident.type == IdentifierType.PHONE
        assert ident.value == "+16502530000"

    def test_already_international_ignores_default_region(self):
        ident = normalize_phone("+44 20 7946 0958")
        assert ident.value.startswith("+44")

    def test_rejects_garbage(self):
        with pytest.raises(ValueError):
            normalize_phone("not a phone number")

    def test_rejects_too_short(self):
        with pytest.raises(ValueError):
            normalize_phone("123")


class TestLooksLikeDomain:
    @pytest.mark.parametrize("value", ["example.com", "sub.example.co.uk", "my-site.io"])
    def test_matches_real_domains(self, value):
        assert looks_like_domain(value)

    @pytest.mark.parametrize("value", ["not a domain", "nodots", "jane@example.com"])
    def test_rejects_non_domains(self, value):
        assert not looks_like_domain(value)


class TestNormalizeDomain:
    def test_valid_domain_lowercased(self):
        ident = normalize_domain("Example.COM")
        assert ident == Identifier(IdentifierType.DOMAIN, "example.com")

    def test_rejects_invalid(self):
        with pytest.raises(ValueError):
            normalize_domain("not a domain")


class TestUsernameCandidates:
    def test_generates_common_patterns(self):
        cands = username_candidates("John Doe")
        assert "johndoe" in cands
        assert "john.doe" in cands
        assert "jdoe" in cands

    def test_empty_name_returns_empty(self):
        assert username_candidates("") == []

    def test_filters_short_candidates(self):
        cands = username_candidates("A B")
        assert all(len(c) >= 3 for c in cands)


class TestEmailPermutations:
    def test_generates_candidates_across_domains(self):
        idents = email_permutations("Jane Doe", domains=("example.com",))
        values = [i.value for i in idents]
        assert "jane.doe@example.com" in values
        assert all(i.type == IdentifierType.EMAIL for i in idents)

    def test_single_word_name_returns_empty(self):
        assert email_permutations("Cher") == []


def test_gravatar_hash_is_deterministic_md5():
    assert gravatar_hash("Test@Example.com") == gravatar_hash("test@example.com  ")
