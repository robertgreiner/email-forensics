#!/usr/bin/env python3
"""
Find email deletion events (mail_event_type=27) in Gmail audit logs.
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

OFFICE_IP = '199.200.88.186'
ATTACKER_IPS = {'172.120.137.37', '45.87.125.150', '46.232.34.229'}
SUSPICIOUS_IP = '158.51.123.14'


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

    print("Searching for email deletion events (mail_event_type=27)")
    print("=" * 70)

    # Query Gmail delivery events Dec 1-17
    results = service.activities().list(
        userKey=TARGET_USER,
        applicationName='gmail',
        startTime='2025-12-01T00:00:00.000Z',
        endTime='2025-12-18T00:00:00.000Z',
        maxResults=1000
    ).execute()

    events = results.get('items', [])
    print(f"Total Gmail events: {len(events)}")

    deletion_events = []
    all_event_types = set()

    for event in events:
        ip = event.get('ipAddress', '')
        time = event.get('id', {}).get('time', '')

        for e in event.get('events', []):
            # Get all parameters
            params = {}
            for p in e.get('parameters', []):
                name = p.get('name', '')
                value = p.get('value', p.get('intValue', p.get('multiValue', '')))
                params[name] = value

            # Track event types seen
            event_type = params.get('event_info.mail_event_type', params.get('mail_event_type', ''))
            if event_type:
                all_event_types.add(str(event_type))

            # Check for deletion (type 27)
            if event_type == '27' or event_type == 27:
                deletion_events.append({
                    'time': time,
                    'ip': ip,
                    'params': params
                })

    print(f"\nEvent types found: {sorted(all_event_types)}")
    print(f"\nDeletion events (type 27): {len(deletion_events)}")

    if deletion_events:
        print("\nDeletion events:")
        for de in deletion_events[:20]:
            print(f"\n  Time: {de['time']}")
            print(f"  IP: {de['ip']}")
            if de['ip'] in ATTACKER_IPS or de['ip'] == SUSPICIOUS_IP:
                print("  *** SUSPICIOUS IP! ***")
            # Print relevant params
            for k, v in de['params'].items():
                if 'message' in k.lower() or 'subject' in k.lower() or 'recipient' in k.lower():
                    print(f"  {k}: {v}")
    else:
        print("\nNo deletion events found in this period!")

    # Also check for any events from suspicious IPs
    print("\n" + "=" * 70)
    print("Events from suspicious IPs:")
    for event in events:
        ip = event.get('ipAddress', '')
        if ip in ATTACKER_IPS or ip == SUSPICIOUS_IP:
            print(f"\n  IP: {ip}")
            print(f"  Time: {event.get('id', {}).get('time')}")
            for e in event.get('events', []):
                print(f"  Event: {e.get('name')}")


if __name__ == '__main__':
    main()
