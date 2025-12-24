#!/usr/bin/env python3
"""
Check for email deletion events in Gmail audit logs.
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

    # Check Dec 1-17 for deletion events
    print("Checking for email deletion events Dec 1-17, 2025:")
    print("=" * 70)

    results = service.activities().list(
        userKey=TARGET_USER,
        applicationName='gmail',
        eventName='email_deleted',
        startTime='2025-12-01T00:00:00.000Z',
        endTime='2025-12-18T00:00:00.000Z',
        maxResults=500
    ).execute()

    events = results.get('items', [])
    print(f"Total email_deleted events: {len(events)}")

    if events:
        for event in events:
            ip = event.get('ipAddress', 'Unknown')
            time = event.get('id', {}).get('time', '')
            print(f"\n  Time: {time}")
            print(f"  IP: {ip}")

            # Flag suspicious
            if ip in ATTACKER_IPS or ip == SUSPICIOUS_IP:
                print(f"  *** SUSPICIOUS IP! ***")

    # Also check for trash events
    print("\n" + "=" * 70)
    print("Checking for trash/move events:")

    # Gmail doesn't have a specific trash event, but check for label changes
    results = service.activities().list(
        userKey=TARGET_USER,
        applicationName='gmail',
        startTime='2025-12-01T00:00:00.000Z',
        endTime='2025-12-18T00:00:00.000Z',
        maxResults=500
    ).execute()

    events = results.get('items', [])
    print(f"Total Gmail events in period: {len(events)}")

    # Look for non-office IPs
    suspicious_events = []
    for event in events:
        ip = event.get('ipAddress', '')
        if ip and ip != OFFICE_IP and not ip.startswith('199.200.'):
            for e in event.get('events', []):
                event_name = e.get('name', '')
                if 'delete' in event_name.lower() or 'trash' in event_name.lower() or 'remove' in event_name.lower():
                    suspicious_events.append({
                        'time': event.get('id', {}).get('time'),
                        'ip': ip,
                        'event': event_name
                    })

    if suspicious_events:
        print("\nDeletion-related events from non-office IPs:")
        for se in suspicious_events:
            print(f"  {se['time']} | {se['ip']} | {se['event']}")
    else:
        print("\nNo deletion events from non-office IPs")


if __name__ == '__main__':
    main()
