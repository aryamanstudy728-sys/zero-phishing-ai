# Gmail API service

from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from typing import Optional


class GmailClient:
    def __init__(self, access_token: str):
        self.credentials = Credentials(token=access_token)
        self.service = build('gmail', 'v1', credentials=self.credentials)

    def get_message_raw(self, message_id: str) -> Optional[str]:
        """Fetch raw email message."""
        try:
            message = self.service.users().messages().get(
                userId='me',
                id=message_id,
                format='raw'
            ).execute()
            return message.get('raw')
        except HttpError as e:
            if e.resp.status == 404:
                return None
            raise

    def get_message_metadata(self, message_id: str) -> Optional[dict]:
        """Fetch message metadata (headers only)."""
        try:
            message = self.service.users().messages().get(
                userId='me',
                id=message_id,
                format='metadata',
                metadataHeaders=['From', 'To', 'Subject', 'Date', 'Received', 'Authentication-Results']
            ).execute()
            return message
        except HttpError as e:
            if e.resp.status == 404:
                return None
            raise

    def list_messages(self, query: str = '', max_results: int = 100) -> list[dict]:
        """List messages matching query."""
        try:
            results = self.service.users().messages().list(
                userId='me',
                q=query,
                maxResults=max_results
            ).execute()
            return results.get('messages', [])
        except HttpError:
            return []