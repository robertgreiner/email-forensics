#!/usr/bin/env python3
"""
Check when Vaughn's password/2FA was changed and if attacker tried after.
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

ATTACKER_IPS = {
    '45.159.127.16',
    '156.229.254.40',
    '45.192.39.3',
    '38.69.8.106',
    '142.111.254.241',
}


def get_credentials():
    from google.auth import iam
    from google.oauth2 import service_account

    source_credentials, project = google.auth.default(scopes=['https://www.googleapis.com/auth/cloud-platform'])
    request = auth_requests.Request()

    signer = iam.Signer(
        request=request,
        credentials=source_credentials,
        service_account_email=SERVICE_ACCOUNT_EMAIL
    )

    return service_account.Credentials(
        signer=signer,
        service_account_email=SERVICE_ACCOUNT_EMAIL,
        token_uri='https://oauth2.googleapis.com/token',
        scopes=['https://www.googleapis.com/auth/admin.reports.audit.readonly'],
        subject=ADMIN_USER
    )


def main():
    credentials = get_credentials()
    service = build('admin', 'reports_v1', credentials=credentials)

    # Get last 30 days of login events
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(days=30)

    print("=" * 80)
    print("REMEDIATION CHECK: vaughn@mossutilities.com")
    print("=" * 80)

    # Check for password/2FA changes
    print("\n--- PASSWORD & 2FA CHANGES ---\n")

    results = service.activities().list(
        userKey=TARGET_USER,
        applicationName='login',
        startTime=start_time.strftime('%Y-%m-%dT%H:%M:%SZ'),
        endTime=end_time.strftime('%Y-%m-%dT%H:%M:%SZ'),
        maxResults=1000
    ).execute()

    events = results.get('items', [])

    security_events = []
    all_login_events = []

    for event in events:
        ip = event.get('ipAddress', 'Unknown')
        timestamp = event.get('id', {}).get('time', '')

        for evt in event.get('events', []):
            event_name = evt.get('name', '')

            # Track security changes
            if any(kw in event_name.lower() for kw in ['password', '2sv', '2fa', 'recovery', 'enrolled', 'passkey']):
                security_events.append({
                    'timestamp': timestamp,
                    'event': event_name,
                    'ip': ip,
                })

            # Track all login attempts
            if 'login' in event_name.lower() or 'challenge' in event_name.lower():
                all_login_events.append({
                    'timestamp': timestamp,
                    'event': event_name,
                    'ip': ip,
                    'is_attacker': ip in ATTACKER_IPS,
                })

    # Sort by timestamp
    security_events.sort(key=lambda x: x['timestamp'])
    all_login_events.sort(key=lambda x: x['timestamp'])

    if security_events:
        for evt in security_events:
            print(f"  [{evt['timestamp'][:19]}] {evt['event']} from {evt['ip']}")
    else:
        print("  No password/2FA changes found in logs")

    # Find remediation date (last password change or 2FA enrollment)
    remediation_date = None
    for evt in reversed(security_events):
        if 'password' in evt['event'].lower() or '2sv' in evt['event'].lower() or 'enrolled' in evt['event'].lower():
            remediation_date = evt['timestamp']
            break

    if remediation_date:
        print(f"\n  📅 Remediation appears to be around: {remediation_date[:19]}")

    print("\n--- ATTACKER ACTIVITY AFTER REMEDIATION ---\n")

    if remediation_date:
        post_remediation = [e for e in all_login_events if e['timestamp'] > remediation_date and e['is_attacker']]

        if post_remediation:
            print(f"  ⚠️ Found {len(post_remediation)} events from attacker IPs after remediation:\n")
            for evt in post_remediation:
                print(f"    🚨 [{evt['timestamp'][:19]}] {evt['event']} from {evt['ip']}")
        else:
            print("  ✅ No attacker activity detected after remediation!")
    else:
        print("  Could not determine remediation date")

    print("\n--- ALL ATTACKER LOGIN ATTEMPTS (chronological) ---\n")

    attacker_logins = [e for e in all_login_events if e['is_attacker']]
    if attacker_logins:
        for evt in attacker_logins:
            print(f"  [{evt['timestamp'][:19]}] {evt['event']} from {evt['ip']}")
    else:
        print("  No login attempts from attacker IPs in last 30 days")

    print("\n--- LAST 10 LOGIN EVENTS ---\n")

    for evt in all_login_events[-10:]:
        flag = "🚨 ATTACKER" if evt['is_attacker'] else ""
        print(f"  [{evt['timestamp'][:19]}] {evt['event']} from {evt['ip']} {flag}")


if __name__ == '__main__':
    main()
