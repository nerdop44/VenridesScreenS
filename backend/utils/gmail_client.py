"""
Gmail API Client for Internal Chat System
Reads emails directly from Gmail without storing them in database
"""
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import os
import pickle
import base64
from email.mime.text import MIMEText
from typing import List, Dict, Optional
import logging

logger = logging.getLogger("VenrideScreenS.Gmail")

# Gmail API scopes
SCOPES = ['https://www.googleapis.com/auth/gmail.modify']

class GmailClient:
    """Gmail API client for reading and sending emails"""
    
    def __init__(self, credentials_path: str = "credentials.json", token_path: str = "token.pickle"):
        """
        Initialize Gmail client
        
        Args:
            credentials_path: Path to OAuth2 credentials JSON file
            token_path: Path to save/load authentication token
        """
        self.credentials_path = credentials_path
        self.token_path = token_path
        self.service = None
        self._authenticate()
    
    def _authenticate(self):
        """Authenticate with Gmail API"""
        creds = None
        
        # Load existing token
        if os.path.exists(self.token_path):
            with open(self.token_path, 'rb') as token:
                creds = pickle.load(token)
        
        # Refresh or create new token
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                if not os.path.exists(self.credentials_path):
                    raise FileNotFoundError(
                        f"Gmail credentials not found at {self.credentials_path}. "
                        "Please download OAuth2 credentials from Google Cloud Console."
                    )
                flow = InstalledAppFlow.from_client_secrets_file(
                    self.credentials_path, SCOPES)
                creds = flow.run_local_server(port=0)
            
            # Save token
            with open(self.token_path, 'wb') as token:
                pickle.dump(creds, token)
        
        self.service = build('gmail', 'v1', credentials=creds)
        logger.info("Gmail API authenticated successfully")
    
    def get_threads(self, max_results: int = 50, label_ids: List[str] = None) -> List[Dict]:
        """
        Get email threads
        
        Args:
            max_results: Maximum number of threads to return
            label_ids: Filter by label IDs (e.g., ['INBOX', 'UNREAD'])
        
        Returns:
            List of thread dictionaries
        """
        try:
            query_params = {
                'userId': 'me',
                'maxResults': max_results
            }
            
            if label_ids:
                query_params['labelIds'] = label_ids
            
            results = self.service.users().threads().list(**query_params).execute()
            threads = results.get('threads', [])
            
            logger.info(f"Retrieved {len(threads)} threads")
            return threads
            
        except HttpError as error:
            logger.error(f"Error getting threads: {error}")
            return []
    
    def get_thread_messages(self, thread_id: str) -> List[Dict]:
        """
        Get all messages in a thread
        
        Args:
            thread_id: Gmail thread ID
        
        Returns:
            List of message dictionaries with parsed content
        """
        try:
            thread = self.service.users().threads().get(
                userId='me',
                id=thread_id,
                format='full'
            ).execute()
            
            messages = []
            for msg in thread.get('messages', []):
                parsed_msg = self._parse_message(msg)
                messages.append(parsed_msg)
            
            return messages
            
        except HttpError as error:
            logger.error(f"Error getting thread messages: {error}")
            return []
    
    def _parse_message(self, message: Dict) -> Dict:
        """Parse Gmail message to extract useful information"""
        headers = message.get('payload', {}).get('headers', [])
        
        # Extract headers
        subject = next((h['value'] for h in headers if h['name'] == 'Subject'), '')
        from_email = next((h['value'] for h in headers if h['name'] == 'From'), '')
        to_email = next((h['value'] for h in headers if h['name'] == 'To'), '')
        date = next((h['value'] for h in headers if h['name'] == 'Date'), '')
        
        # Extract body
        body = self._get_message_body(message.get('payload', {}))
        
        return {
            'id': message['id'],
            'thread_id': message['threadId'],
            'subject': subject,
            'from': from_email,
            'to': to_email,
            'date': date,
            'body': body,
            'snippet': message.get('snippet', ''),
            'labels': message.get('labelIds', [])
        }
    
    def _get_message_body(self, payload: Dict) -> str:
        """Extract message body from payload"""
        if 'parts' in payload:
            # Multipart message
            for part in payload['parts']:
                if part['mimeType'] == 'text/plain':
                    data = part.get('body', {}).get('data', '')
                    if data:
                        return base64.urlsafe_b64decode(data).decode('utf-8')
        else:
            # Simple message
            data = payload.get('body', {}).get('data', '')
            if data:
                return base64.urlsafe_b64decode(data).decode('utf-8')
        
        return ''
    
    def send_message(self, to: str, subject: str, body: str, thread_id: Optional[str] = None) -> bool:
        """
        Send an email message
        
        Args:
            to: Recipient email address
            subject: Email subject
            body: Email body (plain text)
            thread_id: Optional thread ID to reply to
        
        Returns:
            True if sent successfully, False otherwise
        """
        try:
            message = MIMEText(body)
            message['to'] = to
            message['subject'] = subject
            
            raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode('utf-8')
            
            send_params = {
                'userId': 'me',
                'body': {'raw': raw_message}
            }
            
            if thread_id:
                send_params['body']['threadId'] = thread_id
            
            self.service.users().messages().send(**send_params).execute()
            logger.info(f"Message sent to {to}")
            return True
            
        except HttpError as error:
            logger.error(f"Error sending message: {error}")
            return False
    
    def mark_as_read(self, message_id: str) -> bool:
        """Mark a message as read"""
        try:
            self.service.users().messages().modify(
                userId='me',
                id=message_id,
                body={'removeLabelIds': ['UNREAD']}
            ).execute()
            return True
        except HttpError as error:
            logger.error(f"Error marking message as read: {error}")
            return False
    
    def get_unread_count(self) -> int:
        """Get count of unread messages"""
        try:
            results = self.service.users().threads().list(
                userId='me',
                labelIds=['UNREAD'],
                maxResults=1
            ).execute()
            return results.get('resultSizeEstimate', 0)
        except HttpError as error:
            logger.error(f"Error getting unread count: {error}")
            return 0
