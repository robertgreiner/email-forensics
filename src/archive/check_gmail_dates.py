#!/usr/bin/env python3
"""
Check the date distribution of the 62 emails in Gmail SENT folder.
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

    print(f"Total emails in Gmail SENT (Dec 1-17): {len(all_messages)}")
    print()

    # Get dates
    by_date = defaultdict(int)
    for msg in all_messages:
        full_msg = service.users().messages().get(
            userId='me', id=msg['id'], format='metadata',
            metadataHeaders=['Date']
        ).execute()

        # Get internal date (more reliable)
        internal_date = full_msg.get('internalDate', 0)
        dt = datetime.fromtimestamp(int(internal_date) / 1000)
        date_str = dt.strftime('%Y-%m-%d')
        by_date[date_str] += 1

    print("Emails per day in Gmail SENT folder:")
    for date in sorted(by_date.keys()):
        print(f"  {date}: {by_date[date]}")

    print()
    print("Date range covered:", min(by_date.keys()), "to", max(by_date.keys()))


if __name__ == '__main__':
    main()
