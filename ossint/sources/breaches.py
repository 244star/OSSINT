from __future__ import annotations
import os
from urllib.parse import quote

from ..models import Confidence, Finding, Identifier, IdentifierType
from .base import Source


class HibpSource(Source):
    """Have I Been Pwned breach exposure. Needs HIBP_API_KEY (free at haveibeenpwned.com).
    HTTP 200 = email appears in known breaches; 404 = no public breaches."""
    name = "hibp"
    handles = {IdentifierType.EMAIL}
    min_interval = 2.0

    async def query(self, identifier: Identifier, client):
        key = os.getenv("HIBP_API_KEY")
        if not key:
            return []
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(identifier.value)}"
        headers = {"hibp-api-key": key, "User-Agent": "ossint/0.1"}
        r = await client.get(url, headers=headers,
                             params={"truncateResponse": "true",
                                     "includeUnverified": "false"})
        if r.status_code == 200:
            names = r.json()
            return [Finding(source="hibp", identifier=identifier,
                            confidence=Confidence.VERIFIED,
                            url="https://haveibeenpwned.com",
                            details={"breaches": names})]
        if r.status_code == 429:
            return []  # HIBP rate limit: skip quietly, next run picks it up
        return []
