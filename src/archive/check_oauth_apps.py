#!/usr/bin/env python3
"""
Check OAuth apps with access to Lori's account.
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
ADMIN_USER = os.getenv('ADMIN_USER')
TARGET_USER = 'lori.maynard@askmoss.com'
SCOPES = ['https://www.googleapis.com/auth/admin.reports.audit.readonly']


def get_credentials(admin_email):
    source_credentials, project = google.auth.default(scopes=['https://www.googleapis.com/auth/cloud-platform'])
    request = auth_requests.Request()
    signer = iam.Signer(request=request, credentials=source_credentials, service_account_email=SERVICE_ACCOUNT_EMAIL)
    return service_account.Credentials(
        signer=signer, service_account_email=SERVICE_ACCOUNT_EMAIL,
        token_uri='https://oauth2.googleapis.com/token', scopes=SCOPES, subject=admin_email
    )


def main():
    creds = get_credentials(ADMIN_USER)
    service = build('admin', 'reports_v1', credentials=creds)

    print("Checking OAuth token authorizations for Lori...")
    print("=" * 70)

    # Query for oauth token events
    results = service.activities().list(
        userKey=TARGET_USER,
        applicationName='token',
        maxResults=200
    ).execute()

    events = results.get('items', [])
    print(f"Found {len(events)} token events\n")

    # Track unique apps
    apps = {}
    for event in events:
        for e in event.get('events', []):
            params = {p['name']: p.get('value', p.get('multiValue', '')) for p in e.get('parameters', [])}
            app_name = params.get('app_name', 'Unknown')
            client_id = params.get('client_id', '')
            scope = params.get('scope', [])

            if app_name not in apps:
                apps[app_name] = {
                    'client_id': client_id,
                    'scopes': set(),
                    'event_count': 0
                }
            apps[app_name]['event_count'] += 1
            if isinstance(scope, list):
                apps[app_name]['scopes'].update(scope)
            else:
                apps[app_name]['scopes'].add(scope)

    print("OAuth Apps with access to Lori's account:")
    print("-" * 70)
    for app_name, info in sorted(apps.items()):
        print(f"\nApp: {app_name}")
        print(f"  Events: {info['event_count']}")
        print(f"  Scopes: {', '.join(list(info['scopes'])[:5])}")

        # Flag if has email send scope
        dangerous_scopes = ['gmail.send', 'gmail.compose', 'gmail.modify', 'mail.google.com']
        for scope in info['scopes']:
            if any(d in str(scope).lower() for d in dangerous_scopes):
                print(f"  *** HAS EMAIL SEND PERMISSION: {scope} ***")


if __name__ == '__main__':
    main()
