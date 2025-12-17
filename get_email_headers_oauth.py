#!/usr/bin/env python3
"""
Gmail API Email Header Retrieval Script - OAuth Version
Uses OAuth 2.0 flow where an admin authenticates interactively.

Usage:
    python get_email_headers_oauth.py

Prerequisites:
    pip install google-auth google-auth-oauthlib google-api-python-client python-dotenv

Setup:
    1. In Google Cloud Console, create OAuth 2.0 Client ID (Desktop app type)
    2. Download the JSON and save as 'oauth-credentials.json'
"""

import os
import base64
import pickle
from pathlib import Path
from dotenv import load_dotenv
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build

# Load environment variables
load_dotenv()

# Configuration
OAUTH_CREDENTIALS_FILE = 'oauth-credentials.json'
TOKEN_FILE = 'token.pickle'
TARGET_USER = os.getenv('DELEGATED_USER', 'lori.maynard@askmoss.com')

# Scopes - need admin scope to access other users' mail
SCOPES = [
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/admin.directory.user.readonly',
]

# Email search parameters
TARGET_MESSAGE_ID = os.getenv('TARGET_MESSAGE_ID', '<BLAPR19MB4417865E74C24B347DCCF7F7E2D9A@BLAPR19MB4417.namprd19.prod.outlook.com>')
TARGET_FROM = os.getenv('TARGET_FROM', 'jhalstead-wiggins@ssdhvac.com')
TARGET_SUBJECT_KEYWORDS = '125604 Moss Mechanical'


def get_credentials():
    """Get OAuth credentials, prompting for login if needed."""
    creds = None

    # Load existing token if available
    if Path(TOKEN_FILE).exists():
        with open(TOKEN_FILE, 'rb') as token:
            creds = pickle.load(token)

    # If no valid credentials, do OAuth flow
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            print("[*] Refreshing expired credentials...")
            creds.refresh(Request())
        else:
            if not Path(OAUTH_CREDENTIALS_FILE).exists():
                print(f"[-] ERROR: {OAUTH_CREDENTIALS_FILE} not found!")
                print("\nTo create OAuth credentials:")
                print("1. Go to Google Cloud Console → APIs & Services → Credentials")
                print("2. Click 'Create Credentials' → 'OAuth client ID'")
                print("3. Select 'Desktop app' as application type")
                print("4. Download JSON and save as 'oauth-credentials.json'")
                return None

            print("[*] Starting OAuth flow - a browser will open...")
            flow = InstalledAppFlow.from_client_secrets_file(OAUTH_CREDENTIALS_FILE, SCOPES)
            creds = flow.run_local_server(port=0)

        # Save credentials for next run
        with open(TOKEN_FILE, 'wb') as token:
            pickle.dump(creds, token)
        print("[+] Credentials saved for future use")

    return creds


def get_gmail_service(credentials, user_email='me'):
    """Create Gmail API service."""
    service = build('gmail', 'v1', credentials=credentials)
    return service


def search_email(service, user_id='me'):
    """Search for the target email."""
    search_queries = [
        f'rfc822msgid:{TARGET_MESSAGE_ID}',
        f'from:{TARGET_FROM} subject:"{TARGET_SUBJECT_KEYWORDS}"',
        f'from:{TARGET_FROM} after:2025/12/01 before:2025/12/10',
    ]

    for query in search_queries:
        print(f"\n[*] Searching with query: {query}")
        try:
            results = service.users().messages().list(
                userId=user_id,
                q=query,
                maxResults=10
            ).execute()

            messages = results.get('messages', [])
            if messages:
                print(f"[+] Found {len(messages)} message(s)")
                return messages
            else:
                print("[-] No messages found with this query")
        except Exception as e:
            print(f"[-] Search failed: {e}")

    return []


def get_full_headers(service, message_id, user_id='me'):
    """Retrieve full email headers."""
    message = service.users().messages().get(
        userId=user_id,
        id=message_id,
        format='full'
    ).execute()
    return message


def get_raw_message(service, message_id, user_id='me'):
    """Retrieve raw email."""
    message = service.users().messages().get(
        userId=user_id,
        id=message_id,
        format='raw'
    ).execute()

    raw_data = message.get('raw', '')
    if raw_data:
        decoded = base64.urlsafe_b64decode(raw_data).decode('utf-8', errors='replace')
        return decoded
    return None


def extract_headers(message):
    """Extract headers from message payload."""
    headers = {}
    payload = message.get('payload', {})
    header_list = payload.get('headers', [])

    for header in header_list:
        name = header.get('name', '')
        value = header.get('value', '')
        if name in headers:
            if isinstance(headers[name], list):
                headers[name].append(value)
            else:
                headers[name] = [headers[name], value]
        else:
            headers[name] = value

    return headers


def print_forensic_headers(headers):
    """Print headers relevant to email forensics."""
    print("\n" + "="*80)
    print("FORENSIC EMAIL HEADER ANALYSIS")
    print("="*80)

    # Critical headers
    critical_headers = ['From', 'Reply-To', 'Return-Path', 'Sender', 'X-Original-Sender', 'X-Original-From']

    print("\n[CRITICAL - Reply Destination Headers]")
    print("-"*40)
    for h in critical_headers:
        value = headers.get(h, 'NOT PRESENT')
        flag = ""
        if h == 'Reply-To' and value != 'NOT PRESENT':
            from_addr = headers.get('From', '')
            if value.lower() != from_addr.lower():
                flag = "  <<<< DIFFERS FROM 'From' HEADER!"
        print(f"{h}: {value}{flag}")

    # Message routing
    print("\n[Message Routing]")
    print("-"*40)
    for h in ['To', 'Cc', 'Delivered-To']:
        value = headers.get(h, 'NOT PRESENT')
        if value != 'NOT PRESENT':
            print(f"{h}: {value}")

    # Message ID
    print("\n[Message Identification]")
    print("-"*40)
    for h in ['Message-ID', 'Message-Id', 'In-Reply-To', 'References']:
        value = headers.get(h, 'NOT PRESENT')
        if value != 'NOT PRESENT':
            print(f"{h}: {value}")

    # Authentication
    print("\n[Authentication Results]")
    print("-"*40)
    for h in ['Authentication-Results', 'ARC-Authentication-Results', 'Received-SPF']:
        value = headers.get(h, 'NOT PRESENT')
        if value != 'NOT PRESENT':
            print(f"{h}: {str(value)[:300]}...")

    # Date
    print("\n[Timestamp]")
    print("-"*40)
    print(f"Date: {headers.get('Date', 'NOT PRESENT')}")

    # Received headers
    print("\n[Mail Path - Received Headers]")
    print("-"*40)
    received = headers.get('Received', [])
    if isinstance(received, str):
        received = [received]
    for i, r in enumerate(received[:5]):  # First 5 hops
        print(f"\n[Hop {i+1}]")
        print(f"{r[:400]}..." if len(r) > 400 else r)

    # All headers
    print("\n" + "="*80)
    print("ALL HEADERS")
    print("="*80)
    for name, value in sorted(headers.items()):
        if isinstance(value, list):
            for v in value:
                print(f"{name}: {str(v)[:150]}..." if len(str(v)) > 150 else f"{name}: {v}")
        else:
            print(f"{name}: {str(value)[:150]}..." if len(str(value)) > 150 else f"{name}: {value}")


def main():
    print("="*80)
    print("Gmail API Email Header Retrieval (OAuth Version)")
    print("="*80)
    print(f"\nTarget User: {TARGET_USER}")
    print(f"Target From: {TARGET_FROM}")

    print("\n" + "-"*80)
    print("NOTE: This script will access YOUR mailbox (the authenticated user).")
    print(f"If the email was sent TO {TARGET_USER}, you need to either:")
    print("  1. Have that user run this script, OR")
    print("  2. Use domain-wide delegation (service account), OR")
    print("  3. Have the email forwarded to you / exported as .eml")
    print("-"*80)

    try:
        print("\n[*] Getting OAuth credentials...")
        creds = get_credentials()
        if not creds:
            return
        print("[+] Authentication successful")

        service = get_gmail_service(creds)

        print("\n[*] Searching for target email in YOUR mailbox...")
        messages = search_email(service)

        if not messages:
            print("\n[-] No matching emails found in your mailbox.")
            print("\nAlternative: Export the email as .eml from the user's mailbox")
            print("and use a different script to parse it locally.")
            return

        for msg in messages:
            gmail_id = msg['id']
            print(f"\n[*] Retrieving headers for message ID: {gmail_id}")

            full_message = get_full_headers(service, gmail_id)
            headers = extract_headers(full_message)
            raw_message = get_raw_message(service, gmail_id)

            print_forensic_headers(headers)

            # Save to file
            output_file = f'email_headers_{gmail_id}.txt'
            with open(output_file, 'w') as f:
                f.write(f"Gmail Message ID: {gmail_id}\n")
                f.write("="*80 + "\n\n")
                for name, value in sorted(headers.items()):
                    if isinstance(value, list):
                        for v in value:
                            f.write(f"{name}: {v}\n")
                    else:
                        f.write(f"{name}: {value}\n")
                if raw_message:
                    f.write("\n" + "="*80 + "\n")
                    f.write("RAW MESSAGE:\n")
                    f.write(raw_message[:15000])

            print(f"\n[+] Headers saved to: {output_file}")
            break

    except Exception as e:
        print(f"\n[-] ERROR: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()
