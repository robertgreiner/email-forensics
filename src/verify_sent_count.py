#!/usr/bin/env python3
"""
Re-verify the Gmail SENT count for Dec 1-17 to understand discrepancy.
"""

import os
from dotenv import load_dotenv
import google.auth
from google.auth import iam
from google.auth.transport import requests as auth_requests
from google.oauth2 import service_account
from googleapiclient.discovery import build

load_dotenv()

SERVICE_ACCOUNT_EMAIL = os.getenv('SERVICE_ACCOUNT_EMAIL')
TARGET_USER = 'lori.maynard@askmoss.com'
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']


def get_credentials(target_user):
    source_credentials, project = google.auth.default(scopes=['https://www.googleapis.com/auth/cloud-platform'])
    request = auth_requests.Request()
    signer = iam.Signer(request=request, credentials=source_credentials, service_account_email=SERVICE_ACCOUNT_EMAIL)
    return service_account.Credentials(
        signer=signer, service_account_email=SERVICE_ACCOUNT_EMAIL,
        token_uri='https://oauth2.googleapis.com/token', scopes=SCOPES, subject=target_user
    )


def main():
    creds = get_credentials(TARGET_USER)
    service = build('gmail', 'v1', credentials=creds)

    # Query for SENT emails Dec 1-17, 2025
    query = 'in:sent after:2025/12/01 before:2025/12/18'
    print(f"Query: {query}")

    all_messages = []
    page_token = None
    while True:
        results = service.users().messages().list(
            userId='me', q=query, pageToken=page_token, maxResults=500
        ).execute()
        all_messages.extend(results.get('messages', []))
        page_token = results.get('nextPageToken')
        if not page_token:
            break

    print(f"Total messages in SENT folder Dec 1-17: {len(all_messages)}")

    # Also check with label:sent
    query2 = 'label:sent after:2025/12/01 before:2025/12/18'
    print(f"\nQuery2: {query2}")

    all_messages2 = []
    page_token = None
    while True:
        results = service.users().messages().list(
            userId='me', q=query2, pageToken=page_token, maxResults=500
        ).execute()
        all_messages2.extend(results.get('messages', []))
        page_token = results.get('nextPageToken')
        if not page_token:
            break

    print(f"Total messages with SENT label Dec 1-17: {len(all_messages2)}")

    # Check total sent in entire mailbox
    query3 = 'in:sent'
    results = service.users().messages().list(userId='me', q=query3, maxResults=1).execute()
    print(f"\nTotal in SENT folder (all time): {results.get('resultSizeEstimate', 'unknown')}")

    # Now let's count by getting actual Message-IDs
    print("\n" + "=" * 60)
    print("Fetching actual Message-IDs from Gmail...")

    message_ids = set()
    for msg in all_messages[:100]:  # Sample first 100
        full_msg = service.users().messages().get(
            userId='me', id=msg['id'], format='metadata',
            metadataHeaders=['Message-ID']
        ).execute()
        headers = full_msg.get('payload', {}).get('headers', [])
        for h in headers:
            if h['name'].lower() == 'message-id':
                message_ids.add(h['value'])

    print(f"Sample of first 100 - unique Message-IDs: {len(message_ids)}")


if __name__ == '__main__':
    main()
