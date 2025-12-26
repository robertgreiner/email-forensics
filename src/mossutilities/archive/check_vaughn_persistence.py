#!/usr/bin/env python3
"""
Check Vaughn's account for attacker persistence mechanisms:
- Email forwarding rules
- OAuth app grants
- Delegates
- Filters
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


def get_credentials(scopes):
    """Get credentials with domain-wide delegation."""
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
        scopes=scopes,
        subject=ADMIN_USER
    )


def check_gmail_settings():
    """Check Gmail settings for forwarding, delegates, filters."""
    print("\n" + "=" * 60)
    print("GMAIL SETTINGS CHECK")
    print("=" * 60)

    # Need to impersonate Vaughn to check their Gmail settings
    from google.auth import iam
    from google.oauth2 import service_account

    source_credentials, project = google.auth.default(scopes=['https://www.googleapis.com/auth/cloud-platform'])
    request = auth_requests.Request()

    signer = iam.Signer(
        request=request,
        credentials=source_credentials,
        service_account_email=SERVICE_ACCOUNT_EMAIL
    )

    # Impersonate Vaughn to check their settings
    vaughn_creds = service_account.Credentials(
        signer=signer,
        service_account_email=SERVICE_ACCOUNT_EMAIL,
        token_uri='https://oauth2.googleapis.com/token',
        scopes=['https://www.googleapis.com/auth/gmail.settings.basic',
                'https://www.googleapis.com/auth/gmail.readonly'],
        subject=TARGET_USER
    )

    try:
        gmail = build('gmail', 'v1', credentials=vaughn_creds)

        # Check forwarding addresses
        print("\n--- Forwarding Addresses ---")
        try:
            forwards = gmail.users().settings().forwardingAddresses().list(userId='me').execute()
            if forwards.get('forwardingAddresses'):
                for fwd in forwards['forwardingAddresses']:
                    print(f"  ⚠️ FORWARDING TO: {fwd.get('forwardingEmail')} (status: {fwd.get('verificationStatus')})")
            else:
                print("  ✓ No forwarding addresses configured")
        except Exception as e:
            print(f"  Error checking forwarding: {e}")

        # Check auto-forwarding setting
        print("\n--- Auto-Forwarding Setting ---")
        try:
            auto_fwd = gmail.users().settings().getAutoForwarding(userId='me').execute()
            if auto_fwd.get('enabled'):
                print(f"  ⚠️ AUTO-FORWARDING ENABLED TO: {auto_fwd.get('emailAddress')}")
            else:
                print("  ✓ Auto-forwarding is disabled")
        except Exception as e:
            print(f"  Error checking auto-forwarding: {e}")

        # Check delegates
        print("\n--- Email Delegates ---")
        try:
            delegates = gmail.users().settings().delegates().list(userId='me').execute()
            if delegates.get('delegates'):
                for delegate in delegates['delegates']:
                    print(f"  ⚠️ DELEGATE: {delegate.get('delegateEmail')} (status: {delegate.get('verificationStatus')})")
            else:
                print("  ✓ No email delegates configured")
        except Exception as e:
            print(f"  Error checking delegates: {e}")

        # Check filters
        print("\n--- Email Filters ---")
        try:
            filters = gmail.users().settings().filters().list(userId='me').execute()
            if filters.get('filter'):
                print(f"  Found {len(filters['filter'])} filters:")
                for f in filters['filter']:
                    criteria = f.get('criteria', {})
                    action = f.get('action', {})

                    # Look for suspicious filters
                    suspicious = False
                    if action.get('forward'):
                        suspicious = True
                        print(f"  ⚠️ FILTER FORWARDS TO: {action.get('forward')}")
                    if action.get('removeLabelIds') and 'INBOX' in action.get('removeLabelIds', []):
                        suspicious = True
                        print(f"  ⚠️ FILTER SKIPS INBOX")
                    if action.get('addLabelIds') and 'TRASH' in action.get('addLabelIds', []):
                        suspicious = True

                    if suspicious:
                        print(f"      Criteria: from={criteria.get('from')}, subject={criteria.get('subject')}, query={criteria.get('query')}")
            else:
                print("  ✓ No email filters configured")
        except Exception as e:
            print(f"  Error checking filters: {e}")

    except Exception as e:
        print(f"Error accessing Gmail API: {e}")


def check_token_grants():
    """Check OAuth token grants during attack window."""
    print("\n" + "=" * 60)
    print("OAUTH TOKEN GRANTS (Dec 2-10)")
    print("=" * 60)

    credentials = get_credentials(['https://www.googleapis.com/auth/admin.reports.audit.readonly'])
    service = build('admin', 'reports_v1', credentials=credentials)

    start_date = datetime(2025, 12, 2, 0, 0, 0)
    end_date = datetime(2025, 12, 10, 23, 59, 59)

    results = service.activities().list(
        userKey=TARGET_USER,
        applicationName='token',
        startTime=start_date.strftime('%Y-%m-%dT%H:%M:%SZ'),
        endTime=end_date.strftime('%Y-%m-%dT%H:%M:%SZ'),
        maxResults=500
    ).execute()

    events = results.get('items', [])

    # Known attacker IPs
    attacker_ips = {'45.159.127.16', '156.229.254.40', '45.192.39.3', '38.69.8.106', '142.111.254.241'}

    # Known legitimate apps
    legit_apps = {'Abnormal Security', 'WiseStamp for Teams', 'Google Chrome', 'Microsoft apps & services'}

    print(f"\nFound {len(events)} token events")
    print("\n--- Token grants from ATTACKER IPs ---")

    attacker_grants = []
    suspicious_grants = []

    for event in events:
        ip = event.get('ipAddress', 'Unknown')
        timestamp = event.get('id', {}).get('time', '')[:19]

        for evt in event.get('events', []):
            app_name = None
            for param in evt.get('parameters', []):
                if param.get('name') == 'app_name':
                    app_name = param.get('value')

            if ip in attacker_ips:
                attacker_grants.append({
                    'timestamp': timestamp,
                    'ip': ip,
                    'event': evt.get('name'),
                    'app': app_name
                })
            elif app_name and app_name not in legit_apps and evt.get('name') == 'authorize':
                suspicious_grants.append({
                    'timestamp': timestamp,
                    'ip': ip,
                    'event': evt.get('name'),
                    'app': app_name
                })

    if attacker_grants:
        for grant in attacker_grants:
            print(f"  🚨 [{grant['timestamp']}] {grant['event']} - {grant['app']} from {grant['ip']}")
    else:
        print("  ✓ No token grants from attacker IPs")

    print("\n--- Suspicious app grants (non-standard apps) ---")
    if suspicious_grants:
        for grant in suspicious_grants:
            print(f"  ⚠️ [{grant['timestamp']}] {grant['event']} - {grant['app']} from {grant['ip']}")
    else:
        print("  ✓ No suspicious app grants found")


def check_risky_action():
    """Check what the risky_sensitive_action_allowed was on Dec 5."""
    print("\n" + "=" * 60)
    print("RISKY SENSITIVE ACTION DETAILS (Dec 5)")
    print("=" * 60)

    credentials = get_credentials(['https://www.googleapis.com/auth/admin.reports.audit.readonly'])
    service = build('admin', 'reports_v1', credentials=credentials)

    # Get events around Dec 5
    start_date = datetime(2025, 12, 5, 20, 0, 0)
    end_date = datetime(2025, 12, 5, 21, 0, 0)

    results = service.activities().list(
        userKey=TARGET_USER,
        applicationName='login',
        startTime=start_date.strftime('%Y-%m-%dT%H:%M:%SZ'),
        endTime=end_date.strftime('%Y-%m-%dT%H:%M:%SZ'),
        maxResults=100
    ).execute()

    events = results.get('items', [])

    for event in sorted(events, key=lambda x: x.get('id', {}).get('time', '')):
        ip = event.get('ipAddress', 'Unknown')
        timestamp = event.get('id', {}).get('time', '')[:19]

        for evt in event.get('events', []):
            event_name = evt.get('name')
            params = {}
            for param in evt.get('parameters', []):
                params[param.get('name')] = param.get('value') or param.get('boolValue')

            flag = "🚨" if ip == '38.69.8.106' else ""
            print(f"  {flag} [{timestamp}] {event_name} from {ip}")
            if params:
                for k, v in params.items():
                    print(f"       {k}: {v}")


def main():
    print("=" * 80)
    print(f"PERSISTENCE CHECK: {TARGET_USER}")
    print("=" * 80)

    check_risky_action()
    check_token_grants()
    check_gmail_settings()


if __name__ == '__main__':
    main()
