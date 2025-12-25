#!/usr/bin/env python3
"""
Focused audit of vaughn@mossutilities.com - Dec 2 attack window.
"""

import os
from datetime import datetime, timedelta
from dotenv import load_dotenv
import google.auth
from google.auth.transport import requests as auth_requests
from googleapiclient.discovery import build

load_dotenv('/home/robert/Work/_archive/email-forensics/.env.mossutilities')

SERVICE_ACCOUNT_EMAIL = os.getenv('SERVICE_ACCOUNT_EMAIL')
ADMIN_USER = os.getenv('ADMIN_USER')

TARGET_USER = 'vaughn@mossutilities.com'

# Known attacker IPs from Dec 2, 2025
ATTACKER_IPS = {
    '45.159.127.16',    # Singularity Telecom
    '156.229.254.40',   # Unknown
    '45.192.39.3',      # IT_HOST_BLSYNC
    '38.69.8.106',      # VIRTUO NETWORKS
    '142.111.254.241',  # ITHOSTLINE
}


def get_credentials():
    """Get credentials with domain-wide delegation via ADC impersonation."""
    from google.auth import iam
    from google.oauth2 import service_account

    SCOPES = [
        'https://www.googleapis.com/auth/admin.reports.audit.readonly',
    ]

    source_credentials, project = google.auth.default(scopes=['https://www.googleapis.com/auth/cloud-platform'])
    request = auth_requests.Request()

    signer = iam.Signer(
        request=request,
        credentials=source_credentials,
        service_account_email=SERVICE_ACCOUNT_EMAIL
    )

    delegated_credentials = service_account.Credentials(
        signer=signer,
        service_account_email=SERVICE_ACCOUNT_EMAIL,
        token_uri='https://oauth2.googleapis.com/token',
        scopes=SCOPES,
        subject=ADMIN_USER
    )

    return delegated_credentials


def get_events(credentials, user_email, application, start_date, end_date):
    """Get events for a specific user and application within date range."""
    service = build('admin', 'reports_v1', credentials=credentials)

    events = []
    page_token = None

    try:
        while True:
            results = service.activities().list(
                userKey=user_email,
                applicationName=application,
                startTime=start_date.strftime('%Y-%m-%dT%H:%M:%SZ'),
                endTime=end_date.strftime('%Y-%m-%dT%H:%M:%SZ'),
                maxResults=1000,
                pageToken=page_token
            ).execute()

            events.extend(results.get('items', []))
            page_token = results.get('nextPageToken')

            if not page_token:
                break
    except Exception as e:
        print(f"  Error fetching {application} events: {e}")

    return events


def parse_event(event):
    """Parse an event into a readable format."""
    ip = event.get('ipAddress', 'Unknown')
    timestamp = event.get('id', {}).get('time', '')

    event_details = []
    for evt in event.get('events', []):
        name = evt.get('name', 'unknown')
        params = {}
        for param in evt.get('parameters', []):
            param_name = param.get('name')
            param_value = param.get('value') or param.get('boolValue') or param.get('intValue')
            if param_value:
                params[param_name] = param_value
        event_details.append({'name': name, 'params': params})

    return {
        'timestamp': timestamp,
        'ip': ip,
        'is_attacker': ip in ATTACKER_IPS,
        'events': event_details,
    }


def main():
    print("=" * 80)
    print(f"FOCUSED AUDIT: {TARGET_USER}")
    print("=" * 80)
    print(f"Known attacker IPs: {ATTACKER_IPS}")
    print()

    credentials = get_credentials()

    # Focus on attack window: Dec 1-10, 2025
    start_date = datetime(2025, 12, 1, 0, 0, 0)
    end_date = datetime(2025, 12, 10, 23, 59, 59)

    print(f"Scanning attack window: {start_date.date()} to {end_date.date()}")
    print()

    # Applications to audit
    applications = ['login', 'user_accounts', 'token', 'admin']

    all_events = []

    for app in applications:
        print(f"Fetching {app} events...")
        events = get_events(credentials, TARGET_USER, app, start_date, end_date)
        print(f"  Found {len(events)} {app} events")

        for event in events:
            parsed = parse_event(event)
            parsed['application'] = app
            all_events.append(parsed)

    # Sort by timestamp
    all_events.sort(key=lambda x: x['timestamp'])

    print()
    print("=" * 80)
    print("ATTACK WINDOW TIMELINE (Dec 1-10)")
    print("=" * 80)

    current_date = None
    for event in all_events:
        ts = event['timestamp'][:10] if event['timestamp'] else 'Unknown'

        if ts != current_date:
            current_date = ts
            print(f"\n{'='*40}")
            print(f"--- {current_date} ---")
            print(f"{'='*40}")

        flag = "🚨 ATTACKER IP" if event['is_attacker'] else ""
        time_only = event['timestamp'][11:19] if len(event['timestamp']) > 19 else event['timestamp']

        for evt in event['events']:
            params_str = ', '.join(f"{k}={v}" for k, v in evt['params'].items()) if evt['params'] else ''

            # Highlight important events
            important = any(kw in evt['name'].lower() for kw in
                ['password', '2sv', '2fa', 'recovery', 'suspicious', 'risky', 'challenge',
                 'success', 'failure', 'logout', 'backup', 'enrolled', 'disabled'])

            marker = ">>> " if important or event['is_attacker'] else "    "

            print(f"{marker}[{time_only}] [{event['application']}] {evt['name']} from {event['ip']} {flag}")
            if params_str:
                print(f"           {params_str}")

    print()
    print("=" * 80)
    print("ATTACKER ACTIVITY SUMMARY")
    print("=" * 80)

    attacker_events = [e for e in all_events if e['is_attacker']]
    print(f"\nFound {len(attacker_events)} events from attacker IPs:\n")

    for event in attacker_events:
        time_str = event['timestamp'][:19] if event['timestamp'] else 'Unknown'
        for evt in event['events']:
            params_str = ', '.join(f"{k}={v}" for k, v in evt['params'].items()) if evt['params'] else ''
            print(f"  🚨 [{time_str}] [{event['application']}] {evt['name']} from {event['ip']}")
            if params_str:
                print(f"           {params_str}")

    print()
    print("=" * 80)
    print("PASSWORD & 2FA CHANGES")
    print("=" * 80)

    security_events = []
    for event in all_events:
        for evt in event['events']:
            if any(kw in evt['name'].lower() for kw in ['password', '2sv', '2fa', 'recovery', 'backup', 'enrolled']):
                security_events.append((event, evt))

    if security_events:
        for event, evt in security_events:
            flag = "🚨 ATTACKER" if event['is_attacker'] else ""
            time_str = event['timestamp'][:19] if event['timestamp'] else 'Unknown'
            params_str = ', '.join(f"{k}={v}" for k, v in evt['params'].items()) if evt['params'] else ''
            print(f"  [{time_str}] {evt['name']} from {event['ip']} {flag}")
            if params_str:
                print(f"           {params_str}")
    else:
        print("  No password or 2FA changes found in attack window")


if __name__ == '__main__':
    main()
