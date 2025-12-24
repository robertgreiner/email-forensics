#!/usr/bin/env python3
"""
Check ALL emails FROM Lori (not just SENT folder).
"""

import os
from collections import defaultdict
from dotenv import load_dotenv
import google.auth
from google.auth import iam
from google.auth.transport import requests as auth_requests
from google.oauth2 import service_account
from googleapiclient.discovery import build
from datetime import datetime

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

    # Query for ALL emails from Lori (not just SENT folder)
    query = 'from:lori.maynard@askmoss.com after:2025/12/01 before:2025/12/18'

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

    print(f"Total emails FROM Lori (Dec 1-17): {len(all_messages)}")
    print()

    # Get dates and labels
    by_date = defaultdict(int)
    labels_seen = defaultdict(int)

    for msg in all_messages:
        full_msg = service.users().messages().get(
            userId='me', id=msg['id'], format='metadata',
            metadataHeaders=['Date']
        ).execute()

        # Get internal date
        internal_date = full_msg.get('internalDate', 0)
        dt = datetime.fromtimestamp(int(internal_date) / 1000)
        date_str = dt.strftime('%Y-%m-%d')
        by_date[date_str] += 1

        # Track labels
        for label in full_msg.get('labelIds', []):
            labels_seen[label] += 1

    print("Emails per day:")
    for date in sorted(by_date.keys()):
        print(f"  {date}: {by_date[date]}")

    print()
    print("Labels on these emails:")
    for label, count in sorted(labels_seen.items(), key=lambda x: -x[1])[:10]:
        print(f"  {label}: {count}")


if __name__ == '__main__':
    main()
