"""
InternShield — Gmail Scanner
==============================
Connects to Gmail via OAuth2 and fetches job/internship emails.
"""

import os
import base64
import json
import re
from email import message_from_bytes
from typing import List, Dict, Any

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from . import config


class GmailScanner:
    def __init__(self):
        self.service = None
        self.creds   = None

    # ──────────────────────────────────────────────────────────────────────────
    # AUTH
    # ──────────────────────────────────────────────────────────────────────────
    def set_credentials(self, creds: Credentials):
        """Inject credentials from a session or external flow."""
        self.creds = creds
        self.service = build("gmail", "v1", credentials=creds)

    def authenticate(self) -> bool:
        """
        Run OAuth2 flow for LOCAL usage.
        For WEB usage, use views to get creds and call set_credentials().
        """
        if self.creds:
            return True

        creds = None
        # Check for local token (Local dev only)
        if os.path.exists(config.GMAIL_TOKEN_FILE):
            creds = Credentials.from_authorized_user_file(
                config.GMAIL_TOKEN_FILE, config.GMAIL_SCOPES
            )

        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                # In Production, we fail if no token exists (web flow handles this)
                if not os.path.exists(config.GMAIL_CREDENTIALS_FILE):
                    return False
                flow = InstalledAppFlow.from_client_secrets_file(
                    config.GMAIL_CREDENTIALS_FILE, config.GMAIL_SCOPES
                )
                creds = flow.run_local_server(port=0)
            
            # Local token persistence (Dev only)
            try:
                with open(config.GMAIL_TOKEN_FILE, "w") as token:
                    token.write(creds.to_json())
            except Exception: pass

        self.creds   = creds
        self.service = build("gmail", "v1", credentials=creds)
        return True

    # ──────────────────────────────────────────────────────────────────────────
    # FETCH
    # ──────────────────────────────────────────────────────────────────────────
    def fetch_emails(self, query: str = None, max_results: int = None) -> List[Dict]:
        """Return a list of parsed email dicts."""
        if not self.service:
            raise RuntimeError("Not authenticated. Call authenticate() first.")

        query       = query       or config.EMAIL_SCAN_QUERY
        max_results = max_results or config.MAX_EMAILS_TO_SCAN

        try:
            result = (
                self.service.users()
                .messages()
                .list(userId="me", q=query, maxResults=max_results)
                .execute()
            )
        except HttpError as e:
            raise RuntimeError(f"Gmail API error: {e}")

        messages = result.get("messages", [])
        emails   = []
        for msg in messages:
            parsed = self._get_email(msg["id"])
            if parsed:
                emails.append(parsed)
        return emails

    def _get_email(self, msg_id: str) -> Dict[str, Any]:
        """Fetch and parse a single email."""
        try:
            raw = (
                self.service.users()
                .messages()
                .get(userId="me", id=msg_id, format="raw")
                .execute()
            )
        except HttpError:
            return {}

        raw_data = base64.urlsafe_b64decode(raw["raw"].encode("ASCII"))
        msg      = message_from_bytes(raw_data)

        subject     = self._decode_header(msg.get("Subject", ""))
        sender      = msg.get("From", "")
        date        = msg.get("Date", "")
        body, html  = self._extract_body(msg)
        attachments = self._list_attachments(msg)
        links       = self._extract_links(html or body)
        sender_email = self._extract_email_address(sender)
        sender_domain = self._extract_domain(sender_email)

        return {
            "id":            msg_id,
            "subject":       subject,
            "sender":        sender,
            "sender_email":  sender_email,
            "sender_domain": sender_domain,
            "date":          date,
            "body":          body,
            "html":          html,
            "attachments":   attachments,
            "links":         links,
        }

    # ──────────────────────────────────────────────────────────────────────────
    # HELPERS
    # ──────────────────────────────────────────────────────────────────────────
    @staticmethod
    def _decode_header(value: str) -> str:
        from email.header import decode_header
        parts = decode_header(value)
        decoded = []
        for part, enc in parts:
            if isinstance(part, bytes):
                decoded.append(part.decode(enc or "utf-8", errors="replace"))
            else:
                decoded.append(str(part))
        return " ".join(decoded)

    @staticmethod
    def _extract_body(msg) -> tuple:
        body = ""
        html = ""
        if msg.is_multipart():
            for part in msg.walk():
                ct  = part.get_content_type()
                cte = str(part.get("Content-Transfer-Encoding", ""))
                if ct == "text/plain" and not body:
                    payload = part.get_payload(decode=True)
                    if payload:
                        body = payload.decode("utf-8", errors="replace")
                elif ct == "text/html" and not html:
                    payload = part.get_payload(decode=True)
                    if payload:
                        html = payload.decode("utf-8", errors="replace")
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                if msg.get_content_type() == "text/html":
                    html = payload.decode("utf-8", errors="replace")
                else:
                    body = payload.decode("utf-8", errors="replace")
        return body, html

    @staticmethod
    def _list_attachments(msg) -> List[str]:
        attachments = []
        for part in msg.walk():
            if part.get_content_disposition() == "attachment":
                filename = part.get_filename()
                if filename:
                    attachments.append(filename)
        return attachments

    @staticmethod
    def _extract_links(content: str) -> List[str]:
        if not content:
            return []
        return re.findall(r'https?://[^\s\'"<>]+', content)

    @staticmethod
    def _extract_email_address(sender: str) -> str:
        match = re.search(r'[\w.+-]+@[\w.-]+\.\w+', sender)
        return match.group(0).lower() if match else sender.lower()

    @staticmethod
    def _extract_domain(email: str) -> str:
        if "@" in email:
            return email.split("@")[-1].lower()
        return email.lower()

    # ──────────────────────────────────────────────────────────────────────────
    # ATTACHMENT CONTENT DOWNLOAD
    # ──────────────────────────────────────────────────────────────────────────
    def download_attachment(self, msg_id: str, save_dir: str = "temp_attachments") -> List[str]:
        """Download all attachments for a given email."""
        os.makedirs(save_dir, exist_ok=True)
        saved = []
        try:
            msg_data = (
                self.service.users()
                .messages()
                .get(userId="me", id=msg_id, format="full")
                .execute()
            )
        except HttpError:
            return saved

        parts = msg_data.get("payload", {}).get("parts", [])
        for part in parts:
            if part.get("filename") and part.get("body", {}).get("attachmentId"):
                att_id = part["body"]["attachmentId"]
                att = (
                    self.service.users()
                    .messages()
                    .attachments()
                    .get(userId="me", messageId=msg_id, id=att_id)
                    .execute()
                )
                data = base64.urlsafe_b64decode(att["data"])
                path = os.path.join(save_dir, part["filename"])
                with open(path, "wb") as f:
                    f.write(data)
                saved.append(path)
        return saved
