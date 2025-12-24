#!/usr/bin/env python3
"""
Search for "missing" emails in other locations (Trash, All Mail, etc.)
"""

import os
import csv
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


def get_missing_message_ids():
    """Get Message-IDs from admin log that are not in Gmail SENT."""
    # First get Gmail SENT Message-IDs
    creds = get_credentials(TARGET_USER)
    service = build('gmail', 'v1', credentials=creds)

    query = 'in:sent after:2025/12/01 before:2025/12/18'
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

    gmail_ids = set()
    for msg in all_messages:
        full_msg = service.users().messages().get(
            userId='me', id=msg['id'], format='metadata',
            metadataHeaders=['Message-ID']
        ).execute()
        headers = {h['name'].lower(): h['value'] for h in full_msg.get('payload', {}).get('headers', [])}
        mid = headers.get('message-id', '')
        if mid:
            gmail_ids.add(mid)

    # Now get admin log IDs
    admin_ids = {}
    with open('/home/robert/Downloads/lori-send.csv', 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            msg_id = row.get('Message ID', '')
            if msg_id and msg_id not in admin_ids:
                admin_ids[msg_id] = row.get('Subject', '')

    missing = {mid: subj for mid, subj in admin_ids.items() if mid not in gmail_ids}
    return service, missing


def main():
    service, missing = get_missing_message_ids()
    print(f"Searching for {len(missing)} 'missing' emails in Gmail...")

    found_in = {'trash': 0, 'all_mail': 0, 'not_found': 0}

    # Sample check - search for first 20 missing emails
    for i, (mid, subj) in enumerate(list(missing.items())[:20]):
        # Escape the Message-ID for search
        # Gmail search uses rfc822msgid: operator
        search_query = f'rfc822msgid:{mid}'

        try:
            results = service.users().messages().list(
                userId='me', q=search_query, maxResults=1
            ).execute()

            if results.get('messages'):
                msg = results['messages'][0]
                # Get labels
                full_msg = service.users().messages().get(
                    userId='me', id=msg['id'], format='metadata'
                ).execute()
                labels = full_msg.get('labelIds', [])

                if 'TRASH' in labels:
                    found_in['trash'] += 1
                    print(f"  TRASH: {subj[:50]}")
                else:
                    found_in['all_mail'] += 1
                    print(f"  FOUND (labels: {labels[:3]}): {subj[:40]}")
            else:
                found_in['not_found'] += 1

        except Exception as e:
            print(f"  Error: {e}")

    print()
    print("=" * 60)
    print(f"Sample results (first 20):")
    print(f"  Found in Trash: {found_in['trash']}")
    print(f"  Found elsewhere: {found_in['all_mail']}")
    print(f"  Not found at all: {found_in['not_found']}")


if __name__ == '__main__':
    main()
