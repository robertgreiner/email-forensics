#!/usr/bin/env python3
"""
Check what Gmail event types are actually available in the Reports API.
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

    # Check Lori's Gmail events to see what types exist
    print("Checking Gmail event types for lori.maynard@askmoss.com...")
    print("=" * 60)

    results = service.activities().list(
        userKey='lori.maynard@askmoss.com',
        applicationName='gmail',
        startTime='2025-12-01T00:00:00.000Z',
        endTime='2025-12-17T00:00:00.000Z',
        maxResults=500
    ).execute()

    events = results.get('items', [])
    print(f"Total events retrieved: {len(events)}")

    # Count event types
    event_types = Counter()
    for item in events:
        for e in item.get('events', []):
            event_types[e.get('name', 'unknown')] += 1

    print("\nEvent types found:")
    for event_type, count in event_types.most_common():
        print(f"  {event_type}: {count}")

    # Look for any delete-related events
    print("\n" + "=" * 60)
    print("Searching for delete-related events...")

    delete_keywords = ['delete', 'trash', 'remove', 'purge']
    found_delete = False

    for item in events:
        ip = item.get('ipAddress', '')
        time_str = item.get('id', {}).get('time', '')
        for e in item.get('events', []):
            event_name = e.get('name', '').lower()
            if any(kw in event_name for kw in delete_keywords):
                found_delete = True
                print(f"  {time_str} | {ip} | {e.get('name')}")

    if not found_delete:
        print("  No delete-related events found in Reports API")
        print("\n  NOTE: Delete events may only be available in Admin Email Log Search")
        print("        (the CSV export method we used for lori-all.csv)")

if __name__ == '__main__':
    main()
