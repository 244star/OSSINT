from __future__ import annotations

import logging

import httpx
import phonenumbers
from phonenumbers import carrier, geocoder, timezone as tz

from ..models import Confidence, Finding, Identifier, IdentifierType
from ..normalizers import gravatar_hash
from .base import Source

log = logging.getLogger("osint")


class NativeSource(Source):
    """Shared plumbing: verified HTTP checks with confidence=VERIFIED."""

    def finding(self, identifier, url=None, **details):
        return Finding(source=self.name, identifier=identifier,
                       confidence=Confidence.VERIFIED, url=url, details=details)


class GravatarSource(NativeSource):
    name = "gravatar"
    handles = {IdentifierType.EMAIL}

    async def query(self, identifier, client):
        r = await client.get(f"https://en.gravatar.com/{gravatar_hash(identifier.value)}.json")
        if r.status_code != 200:
            return []
        entry = (r.json().get("entry") or [{}])[0]
        if not entry:
            return []
        f = self.finding(identifier, url=f"https://gravatar.com/{entry.get('preferredUsername','')}",
                         display=entry.get("displayName"))
        if entry.get("preferredUsername"):
            f.pivots.append(Identifier(IdentifierType.USERNAME, entry["preferredUsername"]))
        if entry.get("name", {}).get("formatted"):
            f.pivots.append(Identifier(IdentifierType.NAME, entry["name"]["formatted"]))
        for u in entry.get("urls", []):
            f.details.setdefault("profile_urls", []).append(u.get("value"))
        return [f]


class GithubUserSource(NativeSource):
    name = "github"
    handles = {IdentifierType.USERNAME}

    async def query(self, identifier, client):
        r = await client.get(f"https://api.github.com/users/{identifier.value}")
        if r.status_code == 200:
            data = r.json()
            f = self.finding(identifier, url=data.get("html_url"),
                             created=data.get("created_at"), bio=data.get("bio"))
            if data.get("name"):
                f.pivots.append(Identifier(IdentifierType.NAME, data["name"]))
            if data.get("email"):
                f.pivots.append(Identifier(IdentifierType.EMAIL, data["email"]))
            return [f]
        return []


class RedditUserSource(NativeSource):
    name = "reddit"
    handles = {IdentifierType.USERNAME}

    async def query(self, identifier, client):
        r = await client.get(f"https://www.reddit.com/user/{identifier.value}/about.json",
                             headers={"User-Agent": "osint/0.1 research"})
        if r.status_code == 200:
            data = r.json().get("data", {})
            return [self.finding(identifier, url=f"https://reddit.com/u/{identifier.value}",
                                 created=data.get("created_utc"), karma=data.get("total_karma"))]
        return []


class TelegramUsernameSource(NativeSource):
    name = "telegram"
    handles = {IdentifierType.USERNAME}

    async def query(self, identifier, client):
        r = await client.get(f"https://t.me/{identifier.value}")
        if r.status_code == 200 and "tgme_page_title" in r.text:
            return [self.finding(identifier, url=f"https://t.me/{identifier.value}")]
        return []


class PhoneMetaSource(NativeSource):
    name = "phone-meta"
    handles = {IdentifierType.PHONE}
    cache_ttl = 0  # pure local computation — no point caching, no API to save quota on

    async def query(self, identifier, client):
        try:
            num = phonenumbers.parse(identifier.value, None)
        except phonenumbers.NumberParseException as exc:
            log.warning("[phone-meta] could not parse %s: %s", identifier, exc)
            return []
        tzfn = getattr(tz, "time_zones_for_number", None) or getattr(tz, "timezones_for_number", None)
        try:
            tzs = str(tzfn(num))
        except Exception:
            tzs = "n/a"
        f = self.finding(identifier,
                         country=geocoder.description_for_number(num, "en"),
                         carrier=carrier.name_for_number(num, "en"),
                         timezones=tzs,
                         line_type=str(phonenumbers.number_type(num)))
        return [f]


class DomainRdapSource(NativeSource):
    """Domain registration data via RDAP (WHOIS's structured successor).

    Uses rdap.org as a bootstrap redirector so we don't need a per-registry
    RDAP server list or an extra dependency (whois libraries are frequently
    unmaintained / scrape-based). No API key required.
    """
    name = "domain-rdap"
    handles = {IdentifierType.DOMAIN}

    async def query(self, identifier, client):
        r = await client.get(f"https://rdap.org/domain/{identifier.value}",
                             follow_redirects=True)
        if r.status_code != 200:
            return []
        data = r.json()
        registrar = next(
            (e.get("vcardArray", [None, []])[1]
             for e in data.get("entities", [])
             if "registrar" in e.get("roles", [])),
            None,
        )
        events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}
        nameservers = [ns.get("ldhName") for ns in data.get("nameservers", []) if ns.get("ldhName")]
        f = self.finding(
            identifier,
            url=f"https://rdap.org/domain/{identifier.value}",
            registered=events.get("registration"),
            expires=events.get("expiration"),
            last_changed=events.get("last changed"),
            nameservers=nameservers,
            status=data.get("status", []),
        )
        return [f]


REGISTRY = [GravatarSource(), GithubUserSource(), RedditUserSource(),
            TelegramUsernameSource(), PhoneMetaSource(), DomainRdapSource()]
