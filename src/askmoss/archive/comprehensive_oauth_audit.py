#!/usr/bin/env python3
"""
Comprehensive OAuth audit for forensic investigation.
Checks:
1. All OAuth grants from attacker IPs
2. Unknown/suspicious app IDs
3. Token revocations during remediation
4. Currently active dangerous scopes
5. App passwords (if any)
"""

import os
from datetime import datetime
from collections import defaultdict
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

# Known attacker IPs
ATTACKER_IPS = {
    '172.120.137.37',   # Login - Dec 1
    '45.87.125.150',    # Login - Dec 1
    '46.232.34.229',    # Login - Dec 1
    '147.124.205.9',    # Operations - Dec 4
    '158.51.123.14',    # Operations - Dec 4-15
}

# Known legitimate apps
KNOWN_APPS = {
    'Abnormal Security': 'Email security - LEGITIMATE',
    'WiseStamp for Teams': 'Email signatures - LEGITIMATE',
    'Android device': 'Mobile access - LEGITIMATE',
    'iOS device': 'Mobile access - LEGITIMATE',
    'Google Chrome': 'Browser - LEGITIMATE',
}

# Dangerous scopes that could be abused
DANGEROUS_SCOPES = [
    'gmail.send',
    'gmail.compose',
    'gmail.modify',
    'gmail.insert',
    'mail.google.com',
    'gmail.settings',
]


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

    print("=" * 80)
    print("COMPREHENSIVE OAUTH AUDIT FOR FORENSIC INVESTIGATION")
    print(f"Target: {TARGET_USER}")
    print("=" * 80)

    # Get ALL token events (not just 200)
    all_events = []
    page_token = None

    while True:
        results = service.activities().list(
            userKey=TARGET_USER,
            applicationName='token',
            startTime='2025-11-01T00:00:00.000Z',  # Go back further
            endTime='2025-12-24T00:00:00.000Z',
            maxResults=500,
            pageToken=page_token
        ).execute()

        all_events.extend(results.get('items', []))
        page_token = results.get('nextPageToken')
        if not page_token:
            break

    print(f"\nTotal OAuth events analyzed: {len(all_events)}")

    # ================================================================
    # CHECK 1: OAuth grants from attacker IPs
    # ================================================================
    print("\n" + "=" * 80)
    print("CHECK 1: OAuth grants from ATTACKER IPs")
    print("=" * 80)

    attacker_oauth = []
    for event in all_events:
        ip = event.get('ipAddress', '')
        if ip in ATTACKER_IPS:
            time_str = event.get('id', {}).get('time', '')
            for e in event.get('events', []):
                params = {p['name']: p.get('value', p.get('multiValue', '')) for p in e.get('parameters', [])}
                attacker_oauth.append({
                    'time': time_str,
                    'ip': ip,
                    'event': e.get('name'),
                    'app': params.get('app_name', 'Unknown'),
                    'scopes': params.get('scope', [])
                })

    if attacker_oauth:
        print(f"\n*** CRITICAL: {len(attacker_oauth)} OAuth events from attacker IPs! ***\n")
        for evt in attacker_oauth:
            print(f"  Time: {evt['time']}")
            print(f"  IP: {evt['ip']}")
            print(f"  Event: {evt['event']}")
            print(f"  App: {evt['app']}")
            print(f"  Scopes: {evt['scopes']}")
            print()
    else:
        print("\n  ✅ No OAuth grants from known attacker IPs")

    # ================================================================
    # CHECK 2: Unknown/Suspicious app IDs
    # ================================================================
    print("\n" + "=" * 80)
    print("CHECK 2: Unknown or Suspicious App IDs")
    print("=" * 80)

    apps_seen = defaultdict(lambda: {'count': 0, 'scopes': set(), 'first_seen': None, 'last_seen': None, 'ips': set()})

    for event in all_events:
        ip = event.get('ipAddress', '')
        time_str = event.get('id', {}).get('time', '')
        for e in event.get('events', []):
            params = {p['name']: p.get('value', p.get('multiValue', '')) for p in e.get('parameters', [])}
            app_name = params.get('app_name', 'Unknown')
            scopes = params.get('scope', [])

            apps_seen[app_name]['count'] += 1
            apps_seen[app_name]['ips'].add(ip)
            if isinstance(scopes, list):
                apps_seen[app_name]['scopes'].update(scopes)
            else:
                apps_seen[app_name]['scopes'].add(str(scopes))

            if not apps_seen[app_name]['first_seen'] or time_str < apps_seen[app_name]['first_seen']:
                apps_seen[app_name]['first_seen'] = time_str
            if not apps_seen[app_name]['last_seen'] or time_str > apps_seen[app_name]['last_seen']:
                apps_seen[app_name]['last_seen'] = time_str

    print("\nAll apps with OAuth access:")
    print("-" * 80)

    for app_name, info in sorted(apps_seen.items(), key=lambda x: x[1]['count'], reverse=True):
        status = KNOWN_APPS.get(app_name, '⚠️ UNKNOWN - INVESTIGATE')

        # Check if it's a numeric ID (potentially suspicious)
        is_numeric = app_name.isdigit()
        if is_numeric:
            status = '⚠️ NUMERIC ID - INVESTIGATE'

        print(f"\n  App: {app_name}")
        print(f"  Status: {status}")
        print(f"  Events: {info['count']}")
        print(f"  First seen: {info['first_seen']}")
        print(f"  Last seen: {info['last_seen']}")
        print(f"  Unique IPs: {len(info['ips'])}")

        # Check for dangerous scopes
        dangerous = []
        for scope in info['scopes']:
            for d in DANGEROUS_SCOPES:
                if d in str(scope).lower():
                    dangerous.append(scope)
                    break

        if dangerous:
            print(f"  *** DANGEROUS SCOPES: {dangerous} ***")

    # ================================================================
    # CHECK 3: Remediation events (Dec 17)
    # ================================================================
    print("\n" + "=" * 80)
    print("CHECK 3: Remediation Events (Dec 17)")
    print("=" * 80)

    remediation_events = []
    for event in all_events:
        time_str = event.get('id', {}).get('time', '')
        if time_str.startswith('2025-12-17'):
            ip = event.get('ipAddress', '')
            for e in event.get('events', []):
                params = {p['name']: p.get('value', p.get('multiValue', '')) for p in e.get('parameters', [])}
                remediation_events.append({
                    'time': time_str,
                    'ip': ip,
                    'event': e.get('name'),
                    'app': params.get('app_name', 'Unknown')
                })

    if remediation_events:
        print(f"\n  Found {len(remediation_events)} OAuth events on Dec 17:")
        for evt in sorted(remediation_events, key=lambda x: x['time']):
            print(f"    {evt['time'][11:19]} | {evt['event']:<15} | {evt['app']}")
    else:
        print("\n  No OAuth events on Dec 17 (remediation day)")

    # ================================================================
    # CHECK 4: Token revocations
    # ================================================================
    print("\n" + "=" * 80)
    print("CHECK 4: Token Revocations")
    print("=" * 80)

    revocations = []
    for event in all_events:
        time_str = event.get('id', {}).get('time', '')
        for e in event.get('events', []):
            if e.get('name') == 'revoke':
                params = {p['name']: p.get('value', '') for p in e.get('parameters', [])}
                revocations.append({
                    'time': time_str,
                    'app': params.get('app_name', 'Unknown')
                })

    if revocations:
        print(f"\n  Found {len(revocations)} token revocations:")
        for rev in sorted(revocations, key=lambda x: x['time']):
            print(f"    {rev['time']} | {rev['app']}")
    else:
        print("\n  ⚠️ NO token revocations found - tokens may still be active!")

    # ================================================================
    # CHECK 5: Dec 1 OAuth activity (compromise day)
    # ================================================================
    print("\n" + "=" * 80)
    print("CHECK 5: Dec 1 OAuth Activity (Compromise Day)")
    print("=" * 80)

    dec1_events = []
    for event in all_events:
        time_str = event.get('id', {}).get('time', '')
        if time_str.startswith('2025-12-01'):
            ip = event.get('ipAddress', '')
            for e in event.get('events', []):
                params = {p['name']: p.get('value', p.get('multiValue', '')) for p in e.get('parameters', [])}
                dec1_events.append({
                    'time': time_str,
                    'ip': ip,
                    'event': e.get('name'),
                    'app': params.get('app_name', 'Unknown'),
                    'scopes': params.get('scope', [])
                })

    if dec1_events:
        print(f"\n  Found {len(dec1_events)} OAuth events on Dec 1:")
        for evt in sorted(dec1_events, key=lambda x: x['time']):
            is_attacker = '*** ATTACKER ***' if evt['ip'] in ATTACKER_IPS else ''
            print(f"    {evt['time'][11:19]} | {evt['ip']:<20} | {evt['event']:<15} | {evt['app']} {is_attacker}")
    else:
        print("\n  No OAuth events on Dec 1")

    # ================================================================
    # SUMMARY
    # ================================================================
    print("\n" + "=" * 80)
    print("SUMMARY & RECOMMENDATIONS")
    print("=" * 80)

    print("\n  Apps currently with OAuth access:")
    for app in apps_seen.keys():
        if app not in KNOWN_APPS:
            print(f"    ⚠️ {app} - NEEDS INVESTIGATION")
        else:
            print(f"    ✅ {app}")

    if not revocations:
        print("\n  ⚠️ WARNING: No token revocations detected!")
        print("     Recommendation: Manually revoke all OAuth tokens in Admin Console")
        print("     Path: Admin Console > Users > Lori > Security > Connected applications")

    print("\n  Next steps:")
    print("    1. Identify the numeric app ID: 105411135070597341742")
    print("    2. Revoke any unknown OAuth grants")
    print("    3. Check for app passwords in Admin Console")
    print("    4. Consider revoking ALL OAuth tokens as precaution")


if __name__ == '__main__':
    main()
