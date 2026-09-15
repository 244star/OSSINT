import httpx
import pytest

from webapp.server import app


@pytest.mark.asyncio
async def test_home_page_is_available():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/")
    assert response.status_code == 200
    assert "OSSINT" in response.text


@pytest.mark.asyncio
async def test_missing_report_returns_not_found():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/report/0123456789ab")
    assert response.status_code == 404
