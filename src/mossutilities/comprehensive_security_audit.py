#!/usr/bin/env python3
"""
Comprehensive Security Audit for mossutilities.com
Checks all users for:
- Malicious email filters
- OAuth app grants
- Email forwarding
- Admin changes during compromise window
- Mobile devices
"""

import os
import time
from datetime import datetime, timedelta
from collections import defaultdict
from dotenv import load_dotenv
import google.auth
from google.auth import iam
from google.auth.transport import requests as auth_requests
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

load_dotenv('/home/robert/Work/_archive/email-forensics/.env.mossutilities')

SERVICE_ACCOUNT_EMAIL = os.getenv('SERVICE_ACCOUNT_EMAIL')
ADMIN_USER = os.getenv('ADMIN_USER')

# Attack window for this tenant
ATTACK_START = datetime(2025, 12, 2, 0, 0, 0)
ATTACK_END = datetime(2025, 12, 17, 0, 0, 0)

# Known attacker IPs for this tenant
ATTACKER_IPS = {
    '45.159.127.16',
    '156.229.254.40',
    '45.192.39.3',
    '38.69.8.106',
    '142.111.254.241',
}


def get_admin_credentials(scopes):
    """Get credentials with domain-wide delegation as admin."""
    source_credentials, project = google.auth.default(scopes=['https://www.googleapis.com/auth/cloud-platform'])
    request = auth_requests.Request()
    signer = iam.Signer(request=request, credentials=source_credentials, service_account_email=SERVICE_ACCOUNT_EMAIL)
    return service_account.Credentials(
        signer=signer, service_account_email=SERVICE_ACCOUNT_EMAIL,
        token_uri='https://oauth2.googleapis.com/token', scopes=scopes, subject=ADMIN_USER
    )


def get_user_credentials(user_email, scopes):
    """Get credentials impersonating a specific user."""
    source_credentials, project = google.auth.default(scopes=['https://www.googleapis.com/auth/cloud-platform'])
    request = auth_requests.Request()
    signer = iam.Signer(request=request, credentials=source_credentials, service_account_email=SERVICE_ACCOUNT_EMAIL)
    return service_account.Credentials(
        signer=signer, service_account_email=SERVICE_ACCOUNT_EMAIL,
        token_uri='https://oauth2.googleapis.com/token', scopes=scopes, subject=user_email
    )


def get_all_users():
    """Get all active users from the domain."""
    creds = get_admin_credentials(['https://www.googleapis.com/auth/admin.directory.user.readonly'])
    service = build('admin', 'directory_v1', credentials=creds)

    users = []
    page_token = None

    while True:
        results = service.users().list(
            customer='my_customer',
            maxResults=500,
            pageToken=page_token,
            orderBy='email'
        ).execute()

        users.extend(results.get('users', []))
        page_token = results.get('nextPageToken')
        if not page_token:
            break

    return [u for u in users if not u.get('suspended', False)]


def check_user_gmail_settings(user_email):
    """Check a user's Gmail settings for suspicious configurations."""
    issues = []

    try:
        creds = get_user_credentials(user_email, [
            'https://www.googleapis.com/auth/gmail.settings.basic',
            'https://www.googleapis.com/auth/gmail.readonly'
        ])
        gmail = build('gmail', 'v1', credentials=creds)

        # Check filters
        try:
            filters = gmail.users().settings().filters().list(userId='me').execute()
            for f in filters.get('filter', []):
                criteria = f.get('criteria', {})
                action = f.get('action', {})

                # Check for suspicious patterns
                is_suspicious = False
                reasons = []

                if action.get('forward'):
                    is_suspicious = True
                    reasons.append(f"forwards to {action['forward']}")

                if action.get('removeLabelIds') and 'INBOX' in action.get('removeLabelIds', []):
                    is_suspicious = True
                    reasons.append("skips inbox")

                if action.get('addLabelIds') and 'TRASH' in action.get('addLabelIds', []):
                    is_suspicious = True
                    reasons.append("moves to trash")

                if is_suspicious:
                    issues.append({
                        'type': 'FILTER',
                        'user': user_email,
                        'criteria': criteria,
                        'reasons': reasons,
                        'filter_id': f.get('id')
                    })

        except Exception as e:
            pass  # User may not have filters

        # Check auto-forwarding
        try:
            auto_fwd = gmail.users().settings().getAutoForwarding(userId='me').execute()
            if auto_fwd.get('enabled'):
                issues.append({
                    'type': 'FORWARDING',
                    'user': user_email,
                    'forward_to': auto_fwd.get('emailAddress'),
                    'disposition': auto_fwd.get('disposition')
                })
        except Exception as e:
            pass

        # Check forwarding addresses (even if not enabled)
        try:
            forwards = gmail.users().settings().forwardingAddresses().list(userId='me').execute()
            for fwd in forwards.get('forwardingAddresses', []):
                issues.append({
                    'type': 'FORWARDING_ADDRESS',
                    'user': user_email,
                    'address': fwd.get('forwardingEmail'),
                    'status': fwd.get('verificationStatus')
                })
        except Exception as e:
            pass

        # Check delegates
        try:
            delegates = gmail.users().settings().delegates().list(userId='me').execute()
            for delegate in delegates.get('delegates', []):
                issues.append({
                    'type': 'DELEGATE',
                    'user': user_email,
                    'delegate': delegate.get('delegateEmail'),
                    'status': delegate.get('verificationStatus')
                })
        except Exception as e:
            pass

    except Exception as e:
        # Likely scope issue - we'll report this separately
        return None  # Indicates we couldn't check this user

    return issues


def check_admin_changes():
    """Check for admin-level changes during the compromise window."""
    print("\n" + "=" * 80)
    print("ADMIN CHANGES DURING COMPROMISE WINDOW (Dec 2-17)")
    print("=" * 80)

    creds = get_admin_credentials(['https://www.googleapis.com/auth/admin.reports.audit.readonly'])
    service = build('admin', 'reports_v1', credentials=creds)

    results = service.activities().list(
        userKey='all',
        applicationName='admin',
        startTime=ATTACK_START.strftime('%Y-%m-%dT%H:%M:%SZ'),
        endTime=ATTACK_END.strftime('%Y-%m-%dT%H:%M:%SZ'),
        maxResults=1000
    ).execute()

    events = results.get('items', [])
    print(f"\nFound {len(events)} admin events during compromise window")

    # Categorize events
    suspicious_events = []
    user_changes = []
    security_changes = []

    for event in events:
        ip = event.get('ipAddress', 'Unknown')
        actor = event.get('actor', {}).get('email', 'Unknown')
        timestamp = event.get('id', {}).get('time', '')[:19]

        for evt in event.get('events', []):
            event_name = evt.get('name', '')
            params = {p.get('name'): p.get('value') for p in evt.get('parameters', []) if p.get('value')}

            event_data = {
                'timestamp': timestamp,
                'actor': actor,
                'ip': ip,
                'event': event_name,
                'params': params
            }

            # Check if from attacker IP
            if ip in ATTACKER_IPS:
                event_data['is_attacker'] = True
                suspicious_events.append(event_data)

            # Categorize by event type
            if 'USER' in event_name or 'user' in event_name.lower():
                user_changes.append(event_data)
            if 'SECURITY' in event_name or '2SV' in event_name or 'PASSWORD' in event_name:
                security_changes.append(event_data)

    # Report suspicious events from attacker IPs
    print("\n--- EVENTS FROM ATTACKER IPs ---")
    if suspicious_events:
        for evt in suspicious_events:
            print(f"  🚨 [{evt['timestamp']}] {evt['event']}")
            print(f"      Actor: {evt['actor']} from {evt['ip']}")
            if evt['params']:
                for k, v in evt['params'].items():
                    print(f"      {k}: {v}")
    else:
        print("  ✅ No admin events from attacker IPs")

    # Report user creation/deletion
    print("\n--- USER ACCOUNT CHANGES ---")
    user_creates = [e for e in user_changes if 'CREATE' in e['event']]
    user_deletes = [e for e in user_changes if 'DELETE' in e['event']]

    if user_creates:
        print(f"  Users created: {len(user_creates)}")
        for evt in user_creates:
            print(f"    [{evt['timestamp']}] {evt['event']} by {evt['actor']}")
    else:
        print("  No user accounts created")

    if user_deletes:
        print(f"  Users deleted: {len(user_deletes)}")
        for evt in user_deletes:
            print(f"    [{evt['timestamp']}] {evt['event']} by {evt['actor']}")
    else:
        print("  No user accounts deleted")

    # Report security changes
    print("\n--- SECURITY SETTING CHANGES ---")
    if security_changes:
        for evt in security_changes[:20]:  # Limit output
            flag = "🚨" if evt.get('is_attacker') else ""
            print(f"  {flag} [{evt['timestamp']}] {evt['event']}")
            print(f"      Actor: {evt['actor']}")
    else:
        print("  No security setting changes")

    return suspicious_events


def check_oauth_tokens():
    """Check OAuth token grants during compromise window."""
    print("\n" + "=" * 80)
    print("OAUTH TOKEN GRANTS DURING COMPROMISE WINDOW")
    print("=" * 80)

    creds = get_admin_credentials(['https://www.googleapis.com/auth/admin.reports.audit.readonly'])
    service = build('admin', 'reports_v1', credentials=creds)

    results = service.activities().list(
        userKey='all',
        applicationName='token',
        startTime=ATTACK_START.strftime('%Y-%m-%dT%H:%M:%SZ'),
        endTime=ATTACK_END.strftime('%Y-%m-%dT%H:%M:%SZ'),
        maxResults=1000
    ).execute()

    events = results.get('items', [])
    print(f"\nFound {len(events)} token events during compromise window")

    # Known legitimate apps (add more as needed)
    legit_apps = {
        'Google Chrome', 'Gmail', 'Google Drive', 'Google Docs', 'Google Sheets',
        'Google Calendar', 'Abnormal Security', 'WiseStamp', 'WiseStamp for Teams',
        'Microsoft apps & services', 'Slack', 'Zoom', 'Adobe', 'Dropbox'
    }

    suspicious_grants = []
    attacker_grants = []

    for event in events:
        ip = event.get('ipAddress', 'Unknown')
        actor = event.get('actor', {}).get('email', 'Unknown')
        timestamp = event.get('id', {}).get('time', '')[:19]

        for evt in event.get('events', []):
            event_name = evt.get('name', '')
            params = {p.get('name'): p.get('value') for p in evt.get('parameters', []) if p.get('value')}
            app_name = params.get('app_name', 'Unknown')
            scopes = params.get('scope', '')

            grant_data = {
                'timestamp': timestamp,
                'user': actor,
                'ip': ip,
                'event': event_name,
                'app': app_name,
                'scopes': scopes
            }

            if ip in ATTACKER_IPS:
                attacker_grants.append(grant_data)
            elif event_name == 'authorize' and app_name not in legit_apps:
                # Check for sensitive scopes
                if any(s in scopes.lower() for s in ['mail', 'gmail', 'drive', 'admin']):
                    suspicious_grants.append(grant_data)

    print("\n--- TOKEN GRANTS FROM ATTACKER IPs ---")
    if attacker_grants:
        for grant in attacker_grants:
            print(f"  🚨 [{grant['timestamp']}] {grant['event']}")
            print(f"      User: {grant['user']}")
            print(f"      App: {grant['app']}")
            print(f"      IP: {grant['ip']}")
    else:
        print("  ✅ No token grants from attacker IPs")

    print("\n--- SUSPICIOUS APP GRANTS (unknown apps with sensitive scopes) ---")
    if suspicious_grants:
        for grant in suspicious_grants[:20]:  # Limit output
            print(f"  ⚠️ [{grant['timestamp']}] {grant['app']}")
            print(f"      User: {grant['user']}")
            print(f"      Scopes: {grant['scopes'][:100]}...")
    else:
        print("  ✅ No suspicious app grants found")

    return attacker_grants, suspicious_grants


def check_mobile_devices():
    """Check mobile devices for compromised users."""
    print("\n" + "=" * 80)
    print("MOBILE DEVICES FOR COMPROMISED USERS")
    print("=" * 80)

    # Focus on known compromised user
    compromised_user = 'vaughn@mossutilities.com'

    try:
        creds = get_admin_credentials(['https://www.googleapis.com/auth/admin.directory.device.mobile.readonly'])
        service = build('admin', 'directory_v1', credentials=creds)

        results = service.mobiledevices().list(
            customerId='my_customer',
            query=f"email:{compromised_user}",
            maxResults=100
        ).execute()

        devices = results.get('mobiledevices', [])
        print(f"\nDevices for {compromised_user}: {len(devices)}")

        for device in devices:
            print(f"\n  Device: {device.get('model', 'Unknown')}")
            print(f"    Type: {device.get('type', 'Unknown')}")
            print(f"    OS: {device.get('os', 'Unknown')}")
            print(f"    First Sync: {device.get('firstSync', 'Unknown')}")
            print(f"    Last Sync: {device.get('lastSync', 'Unknown')}")
            print(f"    Status: {device.get('status', 'Unknown')}")

            # Flag devices synced during attack window
            first_sync = device.get('firstSync', '')
            if first_sync and '2025-12-' in first_sync:
                sync_day = int(first_sync[8:10]) if len(first_sync) > 10 else 0
                if 2 <= sync_day <= 17:
                    print(f"    ⚠️ DEVICE ADDED DURING ATTACK WINDOW!")

    except HttpError as e:
        if e.resp.status == 403:
            print("\n  ⚠️ Insufficient permissions to list mobile devices")
            print("     Need: admin.directory.device.mobile.readonly scope")
        else:
            print(f"\n  Error: {e}")
    except Exception as e:
        print(f"\n  Error checking mobile devices: {e}")


def main():
    print("=" * 80)
    print("COMPREHENSIVE SECURITY AUDIT - mossutilities.com")
    print(f"Attack Window: {ATTACK_START.strftime('%Y-%m-%d')} to {ATTACK_END.strftime('%Y-%m-%d')}")
    print("=" * 80)

    # 1. Check admin changes
    admin_suspicious = check_admin_changes()

    # 2. Check OAuth tokens
    attacker_tokens, suspicious_tokens = check_oauth_tokens()

    # 3. Check mobile devices
    check_mobile_devices()

    # 4. Check all users for Gmail settings (filters, forwarding, delegates)
    print("\n" + "=" * 80)
    print("ALL-USER GMAIL SETTINGS AUDIT (filters, forwarding, delegates)")
    print("=" * 80)

    users = get_all_users()
    print(f"\nChecking {len(users)} users...")
    print("(This requires gmail.settings.basic scope for domain-wide delegation)")

    all_issues = []
    checked = 0
    failed = 0

    for user in users:
        email = user.get('primaryEmail', '')
        checked += 1

        if checked % 20 == 0:
            print(f"  Progress: {checked}/{len(users)}...")

        issues = check_user_gmail_settings(email)

        if issues is None:
            failed += 1
            if failed == 1:
                print(f"\n  ⚠️ Cannot check Gmail settings - scope not configured")
                print(f"     Need to add gmail.settings.basic to domain-wide delegation")
                break
        elif issues:
            all_issues.extend(issues)
            print(f"  ⚠️ Found {len(issues)} issue(s) for {email}")

        time.sleep(0.1)  # Rate limiting

    if failed == 0:
        print(f"\n  Checked: {checked} users")
        print(f"  Issues found: {len(all_issues)}")

        if all_issues:
            print("\n--- SUSPICIOUS GMAIL SETTINGS ---\n")

            # Group by type
            by_type = defaultdict(list)
            for issue in all_issues:
                by_type[issue['type']].append(issue)

            for issue_type, issues in by_type.items():
                print(f"  {issue_type}: {len(issues)} found")
                for issue in issues:
                    if issue_type == 'FILTER':
                        print(f"    🚨 {issue['user']}: {', '.join(issue['reasons'])}")
                        print(f"       Criteria: {issue['criteria']}")
                    elif issue_type == 'FORWARDING':
                        print(f"    🚨 {issue['user']}: forwards to {issue['forward_to']}")
                    elif issue_type == 'FORWARDING_ADDRESS':
                        print(f"    ⚠️ {issue['user']}: has forwarding address {issue['address']} ({issue['status']})")
                    elif issue_type == 'DELEGATE':
                        print(f"    ⚠️ {issue['user']}: delegate {issue['delegate']} ({issue['status']})")
                print()
        else:
            print("\n  ✅ No suspicious Gmail settings found!")

    # Summary
    print("\n" + "=" * 80)
    print("AUDIT SUMMARY")
    print("=" * 80)

    issues_found = len(admin_suspicious) + len(attacker_tokens) + len(all_issues)

    if issues_found == 0 and failed == 0:
        print("\n  ✅ No suspicious activity found in this audit")
    else:
        if admin_suspicious:
            print(f"\n  🚨 Admin events from attacker IPs: {len(admin_suspicious)}")
        if attacker_tokens:
            print(f"  🚨 Token grants from attacker IPs: {len(attacker_tokens)}")
        if all_issues:
            print(f"  ⚠️ Suspicious Gmail settings: {len(all_issues)}")
        if failed > 0:
            print(f"\n  ⚠️ Gmail settings check incomplete - add scope to domain-wide delegation:")
            print(f"     https://www.googleapis.com/auth/gmail.settings.basic")


if __name__ == '__main__':
    main()
