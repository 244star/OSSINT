from __future__ import annotations
import hashlib
import re

import phonenumbers
from phonenumbers import NumberParseException, PhoneNumberFormat

from .models import Identifier, IdentifierType


def normalize_email(raw: str) -> Identifier:
    value = raw.strip().lower()
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", value):
        raise ValueError(f"invalid email: {raw}")
    return Identifier(IdentifierType.EMAIL, value)


def normalize_phone(raw: str, default_region: str = "US") -> Identifier:
    try:
        num = phonenumbers.parse(raw, default_region)
    except NumberParseException as exc:
        raise ValueError(f"invalid phone: {raw}") from exc
    if not phonenumbers.is_valid_number(num):
        raise ValueError(f"phone not valid: {raw}")
    return Identifier(IdentifierType.PHONE, phonenumbers.format_number(num, PhoneNumberFormat.E164))


def _name_parts(name: str) -> list:
    parts = [re.sub(r"[^a-z0-9]", "", p.lower()) for p in name.split()]
    return [p for p in parts if p]


def username_candidates(name: str) -> list:
    """jdoe, johndoe, john.doe, john-doe, doe.john, j_doe ..."""
    parts = _name_parts(name)
    if not parts:
        return []
    first, last = parts[0], parts[-1]
    cands = {
        first + last, first + "." + last, first + "-" + last,
        first[0] + last, first[0] + "." + last, first + "_" + last,
        last + first, last + "." + first, first, last,
    }
    return sorted(c for c in cands if len(c) >= 3)


def email_permutations(name: str, domains=("gmail.com", "outlook.com", "yahoo.com")) -> list:
    parts = _name_parts(name)
    if len(parts) < 2:
        return []
    f, l = parts[0], parts[-1]
    patterns = {f"{f}.{l}", f"{f}{l}", f"{f[0]}{l}", f"{f[0]}.{l}"}
    return [
        Identifier(IdentifierType.EMAIL, f"{p}@{d}")
        for p in patterns if len(p) >= 4
        for d in domains
    ]


def gravatar_hash(email: str) -> str:
    return hashlib.md5(email.strip().lower().encode()).hexdigest()


_DOMAIN_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*\.[a-z]{2,24}$")


def looks_like_domain(raw: str) -> bool:
    """Heuristic only — a two-label lowercase token with a plausible TLD.

    Deliberately conservative: usernames like "john.doe" also match this
    shape, so callers should check this *before* falling back to USERNAME,
    not instead of letting the user force a type explicitly.
    """
    value = raw.strip().lower()
    return "." in value and " " not in value and bool(_DOMAIN_RE.match(value))


def normalize_domain(raw: str) -> Identifier:
    value = raw.strip().lower()
    if not looks_like_domain(value):
        raise ValueError(f"invalid domain: {raw}")
    return Identifier(IdentifierType.DOMAIN, value)
