from __future__ import annotations
import os
from urllib.parse import urlparse

import httpx

from ..models import Confidence, Finding, Identifier, IdentifierType
from .base import Source

# Request a deeper result set to surface less-prominent, publicly indexed
# accounts. Serper searches its full public-web index without a site allowlist.
RESULTS_PER_QUERY = 100

DORK = {
    IdentifierType.NAME:     '"{q}"',
    IdentifierType.USERNAME: '"{q}"',
    # Email addresses and phone numbers are often indexed outside the three
    # social networks used in the original query.  Use Serper's full index so
    # a report does not hide otherwise relevant, publicly indexed results.
    IdentifierType.EMAIL:    '{q}',
    IdentifierType.PHONE:    '{q}',
}


class SerperDorkSource(Source):
    """Search-engine x-ray. Needs SERPER_API_KEY (serper.dev, generous free tier)."""
    name = "serper-dorks"
    handles = {IdentifierType.NAME, IdentifierType.USERNAME,
               IdentifierType.EMAIL, IdentifierType.PHONE}
    min_interval = 1.0

    def __init__(self, site: str | None = None):
        self.site = site

    async def query(self, identifier: Identifier, client: httpx.AsyncClient):
        key = os.getenv("SERPER_API_KEY")
        if not key:
            return []
        findings = []
        query = DORK[identifier.type].format(q=identifier.value)
        queries = [f"{query} site:{self.site}" if self.site else query]
        for q in queries:
            r = await client.post("https://google.serper.dev/search",
                                  headers={"X-API-KEY": key, "Content-Type": "application/json"},
                                  json={"q": q, "num": RESULTS_PER_QUERY})
            if r.status_code != 200:
                continue
            for hit in r.json().get("organic", []):
                url = hit.get("link")
                domain = urlparse(url).netloc.removeprefix("www.") if url else "web"
                findings.append(Finding(
                    # Serper supplies the search result; the domain is the
                    # actual public source the investigator should assess.
                    source=f"web:{domain}", identifier=identifier,
                    confidence=Confidence.LIKELY,  # search-engine hit = corroborate, don't trust
                    url=url,
                    details={"title": hit.get("title"), "snippet": hit.get("snippet")}))
        return findings
