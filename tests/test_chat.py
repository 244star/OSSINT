import httpx
import pytest

from webapp.server import app, local_chat_answer


def test_local_chat_answers_navigation_questions():
    answer = local_chat_answer("How do I search all platforms?")
    assert "all listed platforms" in answer


@pytest.mark.asyncio
async def test_chat_endpoint_works_without_external_api():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/chat", json={"question": "What does unavailable mean?"})
    assert response.status_code == 200
    assert "unavailable" in response.json()["answer"]


@pytest.mark.asyncio
async def test_chat_endpoint_validates_questions():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/chat", json={"question": ""})
    assert response.status_code == 400
