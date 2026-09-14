from __future__ import annotations
import os

from ..models import Confidence, Finding, Identifier, IdentifierType
from .base import Source


class TelegramPhoneSource(Source):
    """Phone -> Telegram existence via contact import. Requires TELEGRAM_API_ID and
    TELEGRAM_API_HASH env vars (my.telegram.org) and a one-time interactive login.
    Telethon is imported lazily so the core pipeline works without it installed."""
    name = "telegram-phone"
    handles = {IdentifierType.PHONE}

    async def query(self, identifier: Identifier, client):
        api_id, api_hash = os.getenv("TELEGRAM_API_ID"), os.getenv("TELEGRAM_API_HASH")
        if not (api_id and api_hash):
            return []
        from telethon import TelegramClient, functions, types  # optional dep
        async with TelegramClient("ossint_session", int(api_id), api_hash) as tg:
            result = await tg(functions.contacts.ImportContactsRequest(
                contacts=[types.InputPhoneContact(client_id=0, phone=identifier.value,
                                                  first_name="", last_name="")]))
            if result.imported_contacts:
                c = result.imported_contacts[0]
                return [Finding(source="telegram", identifier=identifier,
                                confidence=Confidence.VERIFIED,
                                url=f"https://t.me/+{identifier.value.lstrip('+')}",
                                details={"user_id": str(c.user_id)})]
        return []
