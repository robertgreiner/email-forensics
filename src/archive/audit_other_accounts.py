#!/usr/bin/env python3
"""
Audit high-risk accounts for attacker IP activity.
Checks madelin.martinez and invoices@ for any signs of compromise.
"""

import os
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

# High-risk accounts to audit
TARGET_USERS = [
    'madelin.martinez@askmoss.com',
    'invoices@askmoss.com',
]

# All 5 known attacker IPs
ATTACKER_IPS = {
    '172.120.137.37',   # Login - Dec 1
    '45.87.125.150',    # Login - Dec 1
    '46.232.34.229',    # Login - Dec 1
    '147.124.205.9',    # Operations - Dec 4
    '158.51.123.14',    # Operations - Dec 4-15
}

# Known legitimate IPs
OFFICE_IP = '199.200.88.186'


def get_credentials(admin_email, scopes):
    source_credentials, project = google.auth.default(scopes=['https://www.googleapis.com/auth/cloud-platform'])
    request = auth_requests.Request()
    signer = iam.Signer(request=request, credentials=source_credentials, service_account_email=SERVICE_ACCOUNT_EMAIL)
    return service_account.Credentials(
        signer=signer, service_account_email=SERVICE_ACCOUNT_EMAIL,
        token_uri='https://oauth2.googleapis.com/token', scopes=scopes, subject=admin_email
    )


def audit_user(service, user_email):
    """Audit a single user for attacker IP activity."""
    print(f"\n{'='*80}")
    print(f"AUDITING: {user_email}")
    print('='*80)

    results = {
        'login_events': [],
        'gmail_events': [],
        'token_events': [],
        'attacker_activity': [],
        'suspicious_ips': set(),
    }

    # ================================================================
    # CHECK 1: Login events
    # ================================================================
    print("\n  [1/4] Checking login events...")
    try:
        login_results = service.activities().list(
            userKey=user_email,
            applicationName='login',
            startTime='2025-11-01T00:00:00.000Z',
            endTime='2025-12-24T00:00:00.000Z',
            maxResults=500
        ).execute()

        login_events = login_results.get('items', [])
        results['login_events'] = login_events
        print(f"       Found {len(login_events)} login events")

        # Check for attacker IPs
        for event in login_events:
            ip = event.get('ipAddress', '')
            if ip in ATTACKER_IPS:
                time_str = event.get('id', {}).get('time', '')
                results['attacker_activity'].append({
                    'type': 'LOGIN',
                    'time': time_str,
                    'ip': ip,
                    'user': user_email
                })
                print(f"       *** ATTACKER IP FOUND: {ip} at {time_str} ***")

    except Exception as e:
        print(f"       Error: {e}")

    # ================================================================
    # CHECK 2: Gmail events
    # ================================================================
    print("\n  [2/4] Checking Gmail activity events...")
    try:
        gmail_results = service.activities().list(
            userKey=user_email,
            applicationName='gmail',
            startTime='2025-12-01T00:00:00.000Z',
            endTime='2025-12-24T00:00:00.000Z',
            maxResults=500
        ).execute()

        gmail_events = gmail_results.get('items', [])
        results['gmail_events'] = gmail_events
        print(f"       Found {len(gmail_events)} Gmail events")

        # Check for attacker IPs and suspicious activity
        ip_activity = defaultdict(int)
        for event in gmail_events:
            ip = event.get('ipAddress', '')
            if ip:
                ip_activity[ip] += 1
            if ip in ATTACKER_IPS:
                time_str = event.get('id', {}).get('time', '')
                for e in event.get('events', []):
                    results['attacker_activity'].append({
                        'type': 'GMAIL',
                        'time': time_str,
                        'ip': ip,
                        'event': e.get('name', ''),
                        'user': user_email
                    })
                    print(f"       *** ATTACKER IP FOUND: {ip} - {e.get('name', '')} at {time_str} ***")

        # Report IPs seen
        print(f"\n       IPs with Gmail activity:")
        for ip, count in sorted(ip_activity.items(), key=lambda x: -x[1]):
            status = ""
            if ip in ATTACKER_IPS:
                status = "*** ATTACKER ***"
            elif ip == OFFICE_IP or ip.startswith('199.200.'):
                status = "(office)"
            elif ip.startswith(('44.', '52.', '35.', '54.', '3.', '107.23')):
                status = "(AWS/Abnormal)"
            print(f"         {ip}: {count} events {status}")

    except Exception as e:
        print(f"       Error: {e}")

    # ================================================================
    # CHECK 3: Token/OAuth events
    # ================================================================
    print("\n  [3/4] Checking OAuth/token events...")
    try:
        token_results = service.activities().list(
            userKey=user_email,
            applicationName='token',
            startTime='2025-11-01T00:00:00.000Z',
            endTime='2025-12-24T00:00:00.000Z',
            maxResults=200
        ).execute()

        token_events = token_results.get('items', [])
        results['token_events'] = token_events
        print(f"       Found {len(token_events)} token events")

        # Check for attacker IPs
        for event in token_events:
            ip = event.get('ipAddress', '')
            if ip in ATTACKER_IPS:
                time_str = event.get('id', {}).get('time', '')
                for e in event.get('events', []):
                    params = {p['name']: p.get('value', '') for p in e.get('parameters', [])}
                    results['attacker_activity'].append({
                        'type': 'OAUTH',
                        'time': time_str,
                        'ip': ip,
                        'event': e.get('name', ''),
                        'app': params.get('app_name', 'Unknown'),
                        'user': user_email
                    })
                    print(f"       *** ATTACKER OAUTH: {ip} - {params.get('app_name', '')} at {time_str} ***")

    except Exception as e:
        print(f"       Error: {e}")

    # ================================================================
    # CHECK 4: Look for datacenter/VPS IPs
    # ================================================================
    print("\n  [4/4] Checking for suspicious datacenter IPs...")

    all_ips = set()
    for event in results['login_events']:
        ip = event.get('ipAddress', '')
        if ip:
            all_ips.add(ip)
    for event in results['gmail_events']:
        ip = event.get('ipAddress', '')
        if ip:
            all_ips.add(ip)

    suspicious = []
    for ip in all_ips:
        # Skip known good
        if ip in ATTACKER_IPS:
            continue
        if ip == OFFICE_IP or ip.startswith('199.200.'):
            continue
        if ip.startswith(('44.', '52.', '35.', '54.', '3.', '107.23', '50.17', '13.59')):  # AWS
            continue
        if ip.startswith('209.85.'):  # Google
            continue
        if ':' in ip:  # IPv6 mobile
            continue
        if ip.startswith(('2600:', '2607:')):  # IPv6
            continue

        # Check for datacenter-like patterns
        # These are heuristics - IPs that don't look like residential/office
        suspicious.append(ip)

    if suspicious:
        print(f"       Potentially suspicious IPs found: {suspicious}")
        results['suspicious_ips'] = set(suspicious)
    else:
        print("       No obviously suspicious IPs detected")

    return results


def main():
    creds = get_credentials(ADMIN_USER, ['https://www.googleapis.com/auth/admin.reports.audit.readonly'])
    service = build('admin', 'reports_v1', credentials=creds)

    print("="*80)
    print("HIGH-RISK ACCOUNT AUDIT")
    print("Checking for attacker IP activity in other accounts")
    print("="*80)
    print(f"\nAttacker IPs being searched:")
    for ip in ATTACKER_IPS:
        print(f"  - {ip}")

    all_results = {}
    all_attacker_activity = []

    for user in TARGET_USERS:
        results = audit_user(service, user)
        all_results[user] = results
        all_attacker_activity.extend(results['attacker_activity'])

    # ================================================================
    # SUMMARY
    # ================================================================
    print("\n" + "="*80)
    print("SUMMARY")
    print("="*80)

    if all_attacker_activity:
        print(f"\n*** CRITICAL: {len(all_attacker_activity)} events from attacker IPs! ***\n")
        for activity in sorted(all_attacker_activity, key=lambda x: x['time']):
            print(f"  {activity['time']} | {activity['user']}")
            print(f"    Type: {activity['type']}")
            print(f"    IP: {activity['ip']}")
            if 'event' in activity:
                print(f"    Event: {activity['event']}")
            print()
    else:
        print("\n  ✅ NO attacker IP activity found in audited accounts")

    print("\nAccount Status:")
    for user, results in all_results.items():
        attacker_count = len([a for a in results['attacker_activity']])
        suspicious_count = len(results['suspicious_ips'])

        if attacker_count > 0:
            status = f"⚠️ COMPROMISED - {attacker_count} attacker events"
        elif suspicious_count > 0:
            status = f"⚠️ INVESTIGATE - {suspicious_count} suspicious IPs"
        else:
            status = "✅ CLEAN"

        print(f"  {user}: {status}")
        print(f"    - Login events: {len(results['login_events'])}")
        print(f"    - Gmail events: {len(results['gmail_events'])}")
        print(f"    - OAuth events: {len(results['token_events'])}")


if __name__ == '__main__':
    main()
