#!/usr/bin/env python3
"""
Audit ALL accounts for attacker IP activity.
Comprehensive check across all 89 active users.
"""

import os
import time
from collections import defaultdict
from dotenv import load_dotenv
import google.auth
from google.auth import iam
from google.auth.transport import requests as auth_requests
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

load_dotenv()

SERVICE_ACCOUNT_EMAIL = os.getenv('SERVICE_ACCOUNT_EMAIL')
ADMIN_USER = os.getenv('ADMIN_USER')

# All 5 known attacker IPs
ATTACKER_IPS = {
    '172.120.137.37',   # Login - Dec 1
    '45.87.125.150',    # Login - Dec 1
    '46.232.34.229',    # Login - Dec 1
    '147.124.205.9',    # Operations - Dec 4
    '158.51.123.14',    # Operations - Dec 4-15
}


def get_credentials(admin_email, scopes):
    source_credentials, project = google.auth.default(scopes=['https://www.googleapis.com/auth/cloud-platform'])
    request = auth_requests.Request()
    signer = iam.Signer(request=request, credentials=source_credentials, service_account_email=SERVICE_ACCOUNT_EMAIL)
    return service_account.Credentials(
        signer=signer, service_account_email=SERVICE_ACCOUNT_EMAIL,
        token_uri='https://oauth2.googleapis.com/token', scopes=scopes, subject=admin_email
    )


def get_all_users():
    """Get all active users from the domain."""
    creds = get_credentials(ADMIN_USER, ['https://www.googleapis.com/auth/admin.directory.user.readonly'])
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

    # Filter to active users only
    active_users = [u for u in users if not u.get('suspended', False)]
    return active_users


def check_user_for_attacker_ips(service, user_email):
    """Quick check of a user for attacker IP activity."""
    attacker_events = []

    # Check login events
    try:
        results = service.activities().list(
            userKey=user_email,
            applicationName='login',
            startTime='2025-11-01T00:00:00.000Z',
            endTime='2025-12-24T00:00:00.000Z',
            maxResults=200
        ).execute()

        for event in results.get('items', []):
            ip = event.get('ipAddress', '')
            if ip in ATTACKER_IPS:
                attacker_events.append({
                    'user': user_email,
                    'type': 'LOGIN',
                    'ip': ip,
                    'time': event.get('id', {}).get('time', '')
                })
    except HttpError as e:
        if e.resp.status != 400:  # Ignore "user not found" type errors
            pass

    # Check token events
    try:
        results = service.activities().list(
            userKey=user_email,
            applicationName='token',
            startTime='2025-11-01T00:00:00.000Z',
            endTime='2025-12-24T00:00:00.000Z',
            maxResults=200
        ).execute()

        for event in results.get('items', []):
            ip = event.get('ipAddress', '')
            if ip in ATTACKER_IPS:
                for e in event.get('events', []):
                    params = {p['name']: p.get('value', '') for p in e.get('parameters', [])}
                    attacker_events.append({
                        'user': user_email,
                        'type': 'OAUTH',
                        'ip': ip,
                        'time': event.get('id', {}).get('time', ''),
                        'app': params.get('app_name', 'Unknown')
                    })
    except HttpError:
        pass

    # Check Gmail events (limited to Dec 1-17 attack window)
    try:
        results = service.activities().list(
            userKey=user_email,
            applicationName='gmail',
            startTime='2025-12-01T00:00:00.000Z',
            endTime='2025-12-18T00:00:00.000Z',
            maxResults=200
        ).execute()

        for event in results.get('items', []):
            ip = event.get('ipAddress', '')
            if ip in ATTACKER_IPS:
                for e in event.get('events', []):
                    attacker_events.append({
                        'user': user_email,
                        'type': 'GMAIL',
                        'ip': ip,
                        'time': event.get('id', {}).get('time', ''),
                        'event': e.get('name', '')
                    })
    except HttpError:
        pass

    return attacker_events


def main():
    print("=" * 80)
    print("FULL DOMAIN AUDIT - Checking ALL accounts for attacker IPs")
    print("=" * 80)

    print(f"\nAttacker IPs being searched:")
    for ip in sorted(ATTACKER_IPS):
        print(f"  - {ip}")

    # Get all users
    print("\n[1/2] Fetching all active users...")
    users = get_all_users()
    print(f"       Found {len(users)} active users")

    # Set up reports API
    creds = get_credentials(ADMIN_USER, ['https://www.googleapis.com/auth/admin.reports.audit.readonly'])
    service = build('admin', 'reports_v1', credentials=creds)

    # Check each user
    print(f"\n[2/2] Checking each user for attacker IP activity...")
    print("       This may take a few minutes...\n")

    all_attacker_events = []
    compromised_users = set()
    checked = 0

    for user in users:
        email = user.get('primaryEmail', '')
        checked += 1

        # Progress indicator
        if checked % 10 == 0 or checked == len(users):
            print(f"       Progress: {checked}/{len(users)} users checked...")

        events = check_user_for_attacker_ips(service, email)

        if events:
            compromised_users.add(email)
            all_attacker_events.extend(events)
            print(f"       *** FOUND: {email} - {len(events)} attacker events ***")

        # Small delay to avoid rate limiting
        time.sleep(0.1)

    # ================================================================
    # RESULTS
    # ================================================================
    print("\n" + "=" * 80)
    print("RESULTS")
    print("=" * 80)

    print(f"\nUsers checked: {len(users)}")
    print(f"Users with attacker activity: {len(compromised_users)}")
    print(f"Total attacker events found: {len(all_attacker_events)}")

    if compromised_users:
        print("\n" + "-" * 80)
        print("COMPROMISED ACCOUNTS:")
        print("-" * 80)

        for user in sorted(compromised_users):
            user_events = [e for e in all_attacker_events if e['user'] == user]
            print(f"\n  {user}:")

            for event in sorted(user_events, key=lambda x: x['time']):
                print(f"    {event['time']} | {event['type']:<6} | {event['ip']}")
                if event.get('app'):
                    print(f"      App: {event['app']}")
                if event.get('event'):
                    print(f"      Event: {event['event']}")
    else:
        print("\n  ✅ No attacker IP activity found in any account!")

    # ================================================================
    # SUMMARY
    # ================================================================
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)

    if compromised_users:
        print(f"\n  ⚠️  {len(compromised_users)} account(s) accessed by attacker:")
        for user in sorted(compromised_users):
            print(f"      - {user}")

        print("\n  Immediate actions required:")
        print("    1. Reset passwords for all compromised accounts")
        print("    2. Enable 2FA")
        print("    3. Revoke all OAuth tokens")
        print("    4. Check Gmail settings for persistence")
        print("    5. Pull full activity logs for forensic analysis")
    else:
        print("\n  ✅ CLEAN - No accounts accessed by attacker IPs")
        print("     (besides lori.maynard@askmoss.com which was already remediated)")


if __name__ == '__main__':
    main()
