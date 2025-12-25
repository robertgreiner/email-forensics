#!/usr/bin/env python3
"""
Scan all mossutilities.com users for suspicious login activity.
Look for datacenter IPs, known attacker IPs, and anomalies.
"""

import os
from datetime import datetime, timedelta
from collections import defaultdict
from dotenv import load_dotenv
import google.auth
from google.auth.transport import requests as auth_requests
from googleapiclient.discovery import build

load_dotenv()

SERVICE_ACCOUNT_EMAIL = os.getenv('SERVICE_ACCOUNT_EMAIL')
ADMIN_USER = os.getenv('ADMIN_USER')

# Known Vaughn attacker IPs (Dec 2, 2025)
KNOWN_ATTACKER_IPS = {
    '45.159.127.16',    # Singularity Telecom
    '156.229.254.40',   # Unknown
    '45.192.39.3',      # IT_HOST_BLSYNC
    '38.69.8.106',      # VIRTUO NETWORKS
    '142.111.254.241',  # ITHOSTLINE
}

# Known legitimate IPs (office, etc.)
KNOWN_LEGIT_IPS = {
    '138.199.114.2',    # Office IP
}

# Datacenter/VPS IP prefixes to flag
DATACENTER_PREFIXES = (
    '45.', '46.', '38.', '142.111.', '156.', '172.', '185.', '193.',
    '31.', '37.', '51.', '62.', '77.', '78.', '79.', '80.', '81.',
    '82.', '83.', '84.', '85.', '86.', '87.', '88.', '89.', '91.',
    '92.', '93.', '94.', '95.', '103.', '104.', '107.', '108.',
    '141.', '144.', '145.', '146.', '147.', '148.', '149.', '150.',
    '151.', '154.', '155.', '157.', '158.', '159.', '160.', '161.',
    '162.', '163.', '164.', '165.', '166.', '167.', '168.', '169.',
    '170.', '171.', '173.', '174.', '175.', '176.', '177.', '178.',
    '179.', '180.', '181.', '182.', '183.', '184.', '185.', '186.',
    '187.', '188.', '189.', '190.', '191.', '192.', '193.', '194.',
    '195.', '196.', '197.', '198.', '199.', '200.', '201.', '202.',
    '203.', '204.', '205.', '206.', '207.', '208.', '209.', '210.',
    '211.', '212.', '213.', '214.', '215.', '216.', '217.', '218.',
    '219.', '220.', '221.', '222.', '223.',
)

# Skip service accounts and automation
SKIP_USERS = {
    'abnormal-security@mossutilities.com',
    'automations@mossutilities.com',
    'donotreply@mossutilities.com',
    'contego@mossutilities.com',
    'kinetic@mossutilities.com',
    'kinetictg@mossutilities.com',
}


def get_credentials():
    """Get credentials with domain-wide delegation via ADC impersonation."""
    from google.auth import iam
    from google.auth.transport import requests as auth_requests
    from google.oauth2 import service_account

    SCOPES = [
        'https://www.googleapis.com/auth/admin.directory.user.readonly',
        'https://www.googleapis.com/auth/admin.reports.audit.readonly',
    ]

    # Get ADC credentials (already impersonating the service account via gcloud)
    source_credentials, project = google.auth.default(scopes=['https://www.googleapis.com/auth/cloud-platform'])

    request = auth_requests.Request()

    # Use IAM Credentials API to sign JWTs for domain-wide delegation
    signer = iam.Signer(
        request=request,
        credentials=source_credentials,
        service_account_email=SERVICE_ACCOUNT_EMAIL
    )

    # Create service account credentials with the signer and subject for domain-wide delegation
    delegated_credentials = service_account.Credentials(
        signer=signer,
        service_account_email=SERVICE_ACCOUNT_EMAIL,
        token_uri='https://oauth2.googleapis.com/token',
        scopes=SCOPES,
        subject=ADMIN_USER
    )

    return delegated_credentials


def get_all_users(credentials):
    """Get all users from the domain."""
    from googleapiclient.discovery import build

    service = build('admin', 'directory_v1', credentials=credentials)

    users = []
    page_token = None

    while True:
        results = service.users().list(
            customer='my_customer',
            maxResults=500,
            orderBy='email',
            pageToken=page_token
        ).execute()

        users.extend(results.get('users', []))
        page_token = results.get('nextPageToken')

        if not page_token:
            break

    return users


def get_login_events(credentials, user_email, days=30):
    """Get login events for a specific user."""
    service = build('admin', 'reports_v1', credentials=credentials)

    end_time = datetime.utcnow()
    start_time = end_time - timedelta(days=days)

    events = []
    page_token = None

    try:
        while True:
            results = service.activities().list(
                userKey=user_email,
                applicationName='login',
                startTime=start_time.strftime('%Y-%m-%dT%H:%M:%SZ'),
                endTime=end_time.strftime('%Y-%m-%dT%H:%M:%SZ'),
                maxResults=1000,
                pageToken=page_token
            ).execute()

            events.extend(results.get('items', []))
            page_token = results.get('nextPageToken')

            if not page_token:
                break
    except Exception as e:
        pass  # Some users may not have login events

    return events


def analyze_login(event):
    """Analyze a login event and return details."""
    ip = event.get('ipAddress', 'Unknown')
    event_name = event.get('events', [{}])[0].get('name', 'unknown')
    timestamp = event.get('id', {}).get('time', '')

    # Check parameters for more details
    params = {}
    for evt in event.get('events', []):
        for param in evt.get('parameters', []):
            params[param.get('name')] = param.get('value')

    return {
        'timestamp': timestamp,
        'event': event_name,
        'ip': ip,
        'params': params,
        'is_known_attacker': ip in KNOWN_ATTACKER_IPS,
        'is_known_legit': ip in KNOWN_LEGIT_IPS or ip.startswith('2600:'),  # IPv6 mobile
    }


def main():
    print("=" * 80)
    print("MOSSUTILITIES.COM - COMPREHENSIVE LOGIN AUDIT")
    print("=" * 80)
    print(f"Known attacker IPs: {KNOWN_ATTACKER_IPS}")
    print(f"Scanning last 30 days...")
    print()

    credentials = get_credentials()
    users = get_all_users(credentials)

    print(f"Found {len(users)} users to scan")
    print()

    # Track findings
    compromised_users = []
    suspicious_users = []
    all_attacker_ips = defaultdict(set)  # IP -> set of users

    for i, user in enumerate(users):
        email = user.get('primaryEmail', '')
        name = user.get('name', {}).get('fullName', '')

        # Skip service accounts
        if email in SKIP_USERS:
            continue

        # Skip suspended users
        if user.get('suspended', False):
            continue

        # Progress indicator
        if i % 20 == 0:
            print(f"Scanning user {i+1}/{len(users)}...")

        events = get_login_events(credentials, email)

        if not events:
            continue

        user_findings = {
            'email': email,
            'name': name,
            'attacker_logins': [],
            'suspicious_logins': [],
            'login_failures': [],
        }

        for event in events:
            analysis = analyze_login(event)

            # Check for known attacker IPs
            if analysis['is_known_attacker']:
                user_findings['attacker_logins'].append(analysis)
                all_attacker_ips[analysis['ip']].add(email)

            # Check for login failures from suspicious IPs
            elif 'failure' in analysis['event'] or 'challenge' in analysis['event']:
                if not analysis['is_known_legit']:
                    user_findings['login_failures'].append(analysis)

            # Check for successful logins from non-legit IPs
            elif 'success' in analysis['event']:
                if not analysis['is_known_legit'] and not analysis['ip'].startswith('2600:'):
                    # Check if it's a datacenter IP
                    ip = analysis['ip']
                    if any(ip.startswith(prefix) for prefix in ['45.', '46.', '38.', '142.', '156.', '172.', '158.', '147.']):
                        user_findings['suspicious_logins'].append(analysis)

        # Categorize user
        if user_findings['attacker_logins']:
            compromised_users.append(user_findings)
        elif user_findings['suspicious_logins'] or len(user_findings['login_failures']) > 3:
            suspicious_users.append(user_findings)

    # Report
    print()
    print("=" * 80)
    print("RESULTS")
    print("=" * 80)

    print(f"\n*** CONFIRMED COMPROMISED ({len(compromised_users)} users) ***")
    print("These users had successful logins from known attacker IPs:")
    for user in compromised_users:
        print(f"\n  {user['email']} ({user['name']})")
        for login in user['attacker_logins']:
            print(f"    [{login['timestamp']}] {login['event']} from {login['ip']}")

    print(f"\n*** SUSPICIOUS ACTIVITY ({len(suspicious_users)} users) ***")
    print("These users had suspicious logins or multiple failures from unknown IPs:")
    for user in suspicious_users[:20]:  # Limit output
        print(f"\n  {user['email']} ({user['name']})")
        for login in user['suspicious_logins'][:5]:
            print(f"    [{login['timestamp']}] {login['event']} from {login['ip']}")
        if user['login_failures']:
            print(f"    + {len(user['login_failures'])} login failures from suspicious IPs")

    if len(suspicious_users) > 20:
        print(f"\n  ... and {len(suspicious_users) - 20} more users with suspicious activity")

    print(f"\n*** ATTACKER IP SUMMARY ***")
    for ip, users in sorted(all_attacker_ips.items(), key=lambda x: len(x[1]), reverse=True):
        print(f"  {ip}: {len(users)} users - {', '.join(sorted(users))}")

    print()
    print("=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"Total users scanned: {len(users)}")
    print(f"Confirmed compromised: {len(compromised_users)}")
    print(f"Suspicious activity: {len(suspicious_users)}")
    print(f"Unique attacker IPs seen: {len(all_attacker_ips)}")


if __name__ == '__main__':
    main()
