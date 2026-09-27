# Microsoft Graph API service

import httpx
from typing import Optional
from app.config import get_settings

settings = get_settings()
GRAPH_BASE = "https://graph.microsoft.com/v1.0"


class GraphClient:
    def __init__(self, access_token: str):
        self.access_token = access_token
        self.headers = {"Authorization": f"Bearer {access_token}"}
        self.client = httpx.AsyncClient(headers=self.headers, timeout=30.0, base_url=GRAPH_BASE)

    async def get_message(self, message_id: str) -> Optional[dict]:
        """Fetch full message with headers and body."""
        try:
            response = await self.client.get(
                f"/me/messages/{message_id}",
                params={
                    "$select": "internetMessageHeaders,body,from,sender,receivedDateTime,subject,toRecipients,ccRecipients"
                }
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                return None
            raise

    async def get_message_headers(self, message_id: str) -> Optional[dict]:
        """Fetch only message headers."""
        try:
            response = await self.client.get(
                f"/me/messages/{message_id}",
                params={"$select": "internetMessageHeaders"}
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                return None
            raise

    async def list_messages(self, folder: str = "inbox", top: int = 100) -> list[dict]:
        """List messages in a folder."""
        try:
            response = await self.client.get(
                f"/me/mailFolders/{folder}/messages",
                params={"$top": top, "$select": "id,subject,from,sender,receivedDateTime"}
            )
            response.raise_for_status()
            return response.json().get("value", [])
        except httpx.HTTPStatusError:
            return []

    async def close(self):
        await self.client.aclose()