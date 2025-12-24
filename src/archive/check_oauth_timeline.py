#!/usr/bin/env python3
"""
Check OAuth/token events timeline, especially around Dec 10 and Dec 15.
"""

import os
from datetime import datetime
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

    # Check Dec 1-17 for OAuth events
    print("OAuth/Token events Dec 1-17, 2025:")
    print("=" * 70)

    results = service.activities().list(
        userKey=TARGET_USER,
        applicationName='token',
        startTime='2025-12-01T00:00:00.000Z',
        endTime='2025-12-18T00:00:00.000Z',
        maxResults=200
    ).execute()

    events = results.get('items', [])
    print(f"Total events: {len(events)}\n")

    # Group by date
    by_date = {}
    for event in events:
        time_str = event.get('id', {}).get('time', '')
        ip = event.get('ipAddress', '')

        if time_str:
            date = time_str[:10]
            if date not in by_date:
                by_date[date] = []

            for e in event.get('events', []):
                params = {p['name']: p.get('value', '') for p in e.get('parameters', [])}
                by_date[date].append({
                    'time': time_str,
                    'ip': ip,
                    'event': e.get('name'),
                    'app': params.get('app_name', 'Unknown'),
                    'scopes': params.get('scope', [])
                })

    # Show key dates
    key_dates = ['2025-12-01', '2025-12-10', '2025-12-15']
    for date in key_dates:
        if date in by_date:
            print(f"\n{date}:")
            for evt in by_date[date]:
                scope_str = str(evt['scopes'])[:50] if evt['scopes'] else ''
                print(f"  {evt['time'][11:19]} | {evt['ip']:<20} | {evt['event']:<20} | {evt['app']}")
                if 'send' in scope_str.lower() or 'compose' in scope_str.lower():
                    print(f"    *** SEND SCOPE: {scope_str} ***")
        else:
            print(f"\n{date}: No OAuth events")

    # Check for any authorize events with gmail.send scope
    print("\n" + "=" * 70)
    print("Checking for Gmail SEND permissions:")
    for event in events:
        for e in event.get('events', []):
            params = {p['name']: p.get('value', p.get('multiValue', '')) for p in e.get('parameters', [])}
            scopes = params.get('scope', [])
            if isinstance(scopes, list):
                for s in scopes:
                    if 'send' in s.lower() or 'compose' in s.lower() or 'mail.google' in s.lower():
                        print(f"\n  App: {params.get('app_name')}")
                        print(f"  Event: {e.get('name')}")
                        print(f"  Scope: {s}")
                        print(f"  Time: {event.get('id', {}).get('time')}")
                        print(f"  IP: {event.get('ipAddress')}")


if __name__ == '__main__':
    main()
