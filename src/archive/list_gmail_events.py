#!/usr/bin/env python3
"""
List all Gmail event types in audit logs.
"""

import os
from collections import Counter
from dotenv import load_dotenv
import google.auth
from google.auth import iam
from google.auth.transport import requests as auth_requests
from google.oauth2 import service_account
from googleapiclient.discovery import build

load_dotenv()

SERVICE_ACCOUNT_EMAIL = os.getenv('SERVICE_ACCOUNT_EMAIL')
ADMIN_USER = os.getenv('ADMIN_USER')
TARGET_USER = 'lori.maynard@askmoss.com'


def get_credentials(admin_email, scopes):
    source_credentials, project = google.auth.default(scopes=['https://www.googleapis.com/auth/cloud-platform'])
    request = auth_requests.Request()
    signer = iam.Signer(request=request, credentials=source_credentials, service_account_email=SERVICE_ACCOUNT_EMAIL)
    return service_account.Credentials(
        signer=signer, service_account_email=SERVICE_ACCOUNT_EMAIL,
        token_uri='https://oauth2.googleapis.com/token', scopes=scopes, subject=admin_email
    )


def main():
    creds = get_credentials(ADMIN_USER, ['https://www.googleapis.com/auth/admin.reports.audit.readonly'])
    service = build('admin', 'reports_v1', credentials=creds)

    print("Gmail event types Dec 1-17, 2025:")
    print("=" * 70)

    results = service.activities().list(
        userKey=TARGET_USER,
        applicationName='gmail',
        startTime='2025-12-01T00:00:00.000Z',
        endTime='2025-12-18T00:00:00.000Z',
        maxResults=1000
    ).execute()

    events = results.get('items', [])
    print(f"Total events: {len(events)}")

    # Count event types
    event_types = Counter()
    event_ips = {}

    for event in events:
        ip = event.get('ipAddress', 'Unknown')
        for e in event.get('events', []):
            name = e.get('name', 'Unknown')
            event_types[name] += 1
            if name not in event_ips:
                event_ips[name] = set()
            event_ips[name].add(ip)

    print("\nEvent types found:")
    for evt, count in event_types.most_common():
        ips = event_ips[evt]
        unique_ips = len(ips)
        print(f"  {evt}: {count} (from {unique_ips} unique IPs)")


if __name__ == '__main__':
    main()
