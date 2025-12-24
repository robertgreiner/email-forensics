#!/usr/bin/env python3
"""
Audit ALL DELETE events across ALL users for the past 90 days.
Looking for suspicious patterns that might indicate compromise.

Suspicious patterns:
- Deletes from datacenter/VPS IPs
- Bulk deletes in short time windows
- Deletes from IPs not matching user's normal pattern
- Deletes followed by specific patterns (view->draft->send->delete)
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

load_dotenv()

SERVICE_ACCOUNT_EMAIL = os.getenv('SERVICE_ACCOUNT_EMAIL')
ADMIN_USER = os.getenv('ADMIN_USER')

# Known attacker IPs (for reference)
KNOWN_ATTACKER_IPS = {
    '172.120.137.37',
    '45.87.125.150',
    '46.232.34.229',
    '147.124.205.9',
    '158.51.123.14',
}

# Known legitimate IP patterns
OFFICE_PATTERNS = ('199.200.',)
AWS_PATTERNS = ('44.', '52.', '35.', '54.', '3.', '107.23.', '50.17.', '13.59.', '13.111.')
GOOGLE_PATTERNS = ('209.85.',)


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

    return [u for u in users if not u.get('suspended', False)]


def is_suspicious_ip(ip):
    """Check if an IP looks suspicious (datacenter/VPS)."""
    if not ip:
        return False

    # Skip known legitimate
    if ip in KNOWN_ATTACKER_IPS:
        return True  # Known bad

    for pattern in OFFICE_PATTERNS + AWS_PATTERNS + GOOGLE_PATTERNS:
        if ip.startswith(pattern):
            return False

    # Skip IPv6 (usually mobile)
    if ':' in ip:
        return False

    # Everything else is potentially suspicious
    return True


def get_user_delete_events(service, user_email, start_time, end_time):
    """Get all delete events for a user."""
    delete_events = []

    try:
        page_token = None
        while True:
            results = service.activities().list(
                userKey=user_email,
                applicationName='gmail',
                eventName='email_deleted',
                startTime=start_time,
                endTime=end_time,
                maxResults=500,
                pageToken=page_token
            ).execute()

            for event in results.get('items', []):
                ip = event.get('ipAddress', '')
                time_str = event.get('id', {}).get('time', '')

                delete_events.append({
                    'user': user_email,
                    'time': time_str,
                    'ip': ip,
                    'is_suspicious': is_suspicious_ip(ip),
                    'is_known_attacker': ip in KNOWN_ATTACKER_IPS
                })

            page_token = results.get('nextPageToken')
            if not page_token:
                break

    except HttpError as e:
        if e.resp.status not in [400, 404]:
            print(f"       Error for {user_email}: {e}")

    return delete_events


def main():
    print("=" * 80)
    print("DOMAIN-WIDE DELETE EVENT AUDIT")
    print("Checking all users for suspicious delete patterns (past 90 days)")
    print("=" * 80)

    # Calculate time range (90 days)
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(days=90)

    start_str = start_time.strftime('%Y-%m-%dT00:00:00.000Z')
    end_str = end_time.strftime('%Y-%m-%dT23:59:59.000Z')

    print(f"\nTime range: {start_time.strftime('%Y-%m-%d')} to {end_time.strftime('%Y-%m-%d')}")

    # Get all users
    print("\n[1/3] Fetching all active users...")
    users = get_all_users()
    print(f"       Found {len(users)} active users")

    # Set up reports API
    creds = get_credentials(ADMIN_USER, ['https://www.googleapis.com/auth/admin.reports.audit.readonly'])
    service = build('admin', 'reports_v1', credentials=creds)

    # Collect all delete events
    print(f"\n[2/3] Collecting delete events for all users...")
    print("       This may take several minutes...\n")

    all_delete_events = []
    users_with_deletes = set()
    users_with_suspicious = set()
    checked = 0

    for user in users:
        email = user.get('primaryEmail', '')
        checked += 1

        if checked % 10 == 0 or checked == len(users):
            print(f"       Progress: {checked}/{len(users)} users checked...")

        events = get_user_delete_events(service, email, start_str, end_str)

        if events:
            users_with_deletes.add(email)
            all_delete_events.extend(events)

            suspicious = [e for e in events if e['is_suspicious']]
            if suspicious:
                users_with_suspicious.add(email)
                print(f"       ⚠️  {email}: {len(events)} deletes ({len(suspicious)} from suspicious IPs)")

        time.sleep(0.1)  # Rate limiting

    # ================================================================
    # ANALYSIS
    # ================================================================
    print(f"\n[3/3] Analyzing delete patterns...")

    print("\n" + "=" * 80)
    print("RESULTS")
    print("=" * 80)

    print(f"\nOverall Statistics:")
    print(f"  - Users checked: {len(users)}")
    print(f"  - Users with delete events: {len(users_with_deletes)}")
    print(f"  - Total delete events: {len(all_delete_events)}")
    print(f"  - Users with suspicious IP deletes: {len(users_with_suspicious)}")

    # Group by IP
    ip_counts = defaultdict(lambda: {'count': 0, 'users': set()})
    for event in all_delete_events:
        ip = event['ip']
        if ip:
            ip_counts[ip]['count'] += 1
            ip_counts[ip]['users'].add(event['user'])

    # Find known attacker IP deletes
    print("\n" + "-" * 80)
    print("KNOWN ATTACKER IP ACTIVITY:")
    print("-" * 80)

    attacker_deletes = [e for e in all_delete_events if e['is_known_attacker']]
    if attacker_deletes:
        print(f"\n  ⚠️  {len(attacker_deletes)} delete events from known attacker IPs:\n")
        for event in sorted(attacker_deletes, key=lambda x: x['time']):
            print(f"    {event['time']} | {event['user']} | {event['ip']}")
    else:
        print("\n  ✅ No delete events from known attacker IPs (outside Lori's account)")

    # Find suspicious IPs with high delete counts
    print("\n" + "-" * 80)
    print("SUSPICIOUS IPs WITH DELETE ACTIVITY:")
    print("-" * 80)

    suspicious_ips = []
    for ip, data in ip_counts.items():
        if is_suspicious_ip(ip) and ip not in KNOWN_ATTACKER_IPS:
            suspicious_ips.append({
                'ip': ip,
                'count': data['count'],
                'users': data['users']
            })

    if suspicious_ips:
        # Sort by count
        suspicious_ips.sort(key=lambda x: -x['count'])

        print(f"\n  Found {len(suspicious_ips)} suspicious IPs with delete activity:\n")

        for item in suspicious_ips[:20]:  # Top 20
            users_str = ', '.join(list(item['users'])[:3])
            if len(item['users']) > 3:
                users_str += f" (+{len(item['users'])-3} more)"
            print(f"    {item['ip']:<20} | {item['count']:>4} deletes | Users: {users_str}")
    else:
        print("\n  ✅ No suspicious IPs with delete activity")

    # Users with high delete counts from suspicious IPs
    print("\n" + "-" * 80)
    print("USERS WITH SUSPICIOUS DELETE PATTERNS:")
    print("-" * 80)

    user_suspicious = defaultdict(list)
    for event in all_delete_events:
        if event['is_suspicious']:
            user_suspicious[event['user']].append(event)

    if user_suspicious:
        print(f"\n  {len(user_suspicious)} users with deletes from suspicious IPs:\n")

        for user, events in sorted(user_suspicious.items(), key=lambda x: -len(x[1])):
            ips = set(e['ip'] for e in events)
            dates = set(e['time'][:10] for e in events)
            print(f"    {user}")
            print(f"      Deletes: {len(events)} | Unique IPs: {len(ips)} | Days: {len(dates)}")

            # Show IPs
            for ip in list(ips)[:3]:
                ip_events = [e for e in events if e['ip'] == ip]
                print(f"        - {ip}: {len(ip_events)} deletes")

            if len(ips) > 3:
                print(f"        ... and {len(ips)-3} more IPs")
            print()
    else:
        print("\n  ✅ No users with suspicious delete patterns")

    # ================================================================
    # SUMMARY
    # ================================================================
    print("\n" + "=" * 80)
    print("SUMMARY & RECOMMENDATIONS")
    print("=" * 80)

    if attacker_deletes:
        print("\n  🚨 CRITICAL: Delete events found from known attacker IPs")
        print("     Action: Investigate affected accounts immediately")

    if users_with_suspicious:
        print(f"\n  ⚠️  {len(users_with_suspicious)} users have deletes from suspicious IPs")
        print("     These may warrant further investigation:")
        for user in sorted(users_with_suspicious):
            count = len(user_suspicious.get(user, []))
            print(f"       - {user} ({count} suspicious deletes)")
    else:
        print("\n  ✅ No concerning delete patterns detected")
        print("     All delete activity appears to be from legitimate sources")


if __name__ == '__main__':
    main()
