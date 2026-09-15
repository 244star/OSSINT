import httpx
import pytest

from ossint.models import Identifier, IdentifierType
from ossint.sources.base import Source


class SuccessfulSource(Source):
    name = "test-success"
    handles = {IdentifierType.EMAIL}
    cache_ttl = 0

    async def query(self, identifier, client):
        return []


class FailingSource(Source):
    name = "test-failure"
    handles = {IdentifierType.EMAIL}
    cache_ttl = 0

    async def query(self, identifier, client):
        raise ValueError("bad response")


@pytest.mark.asyncio
async def test_source_status_distinguishes_success_and_failure():
    identifier = Identifier(IdentifierType.EMAIL, "jane@example.com")
    async with httpx.AsyncClient() as client:
        findings, status, error = await SuccessfulSource().safe_query_with_status(
            identifier, client)
        assert findings == []
        assert status == "success"
        assert error is None

        findings, status, error = await FailingSource().safe_query_with_status(
            identifier, client)
        assert findings == []
        assert status == "failed"
        assert error == "ValueError"


@pytest.mark.asyncio
async def test_legacy_safe_query_still_returns_findings_list():
    identifier = Identifier(IdentifierType.EMAIL, "jane@example.com")
    async with httpx.AsyncClient() as client:
        findings = await SuccessfulSource().safe_query(identifier, client)
    assert findings == []


@pytest.mark.asyncio
async def test_missing_configuration_is_reported_as_unavailable():
    source = FailingSource()
    source.availability = lambda: (False, "test configuration")
    identifier = Identifier(IdentifierType.EMAIL, "jane@example.com")
    async with httpx.AsyncClient() as client:
        findings, status, reason = await source.safe_query_with_status(identifier, client)
    assert findings == []
    assert status == "unavailable"
    assert reason == "test configuration"
