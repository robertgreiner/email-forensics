#!/usr/bin/env python3
"""
Check the 7 suspicious users from the scan to determine if legitimate.
Focus on the IPs that triggered alerts to verify if mobile/VPN.
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

# Suspicious users from the scan
SUSPICIOUS_USERS = [
    'aracely@mossutilities.com',
    'dglass@mossutilities.com',
    'julie@mossutilities.com',
    'karla@mossutilities.com',
    'mvargas@mossutilities.com',
    'roxanne@mossutilities.com',
    'wdavis@mossutilities.com',
]


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


def get_login_events(credentials, user_email, days=30):
    """Get login events for a user."""
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
        pass

    return events


def analyze_ip(ip):
    """Categorize IP address."""
    if ip.startswith('2600:') or ip.startswith('2607:'):
        return 'Mobile (AT&T/Verizon IPv6)'
    elif ip.startswith('172.'):
        # 172.16-31.x.x is private, but 172.32+ is often AT&T
        second_octet = int(ip.split('.')[1])
        if second_octet >= 16 and second_octet <= 31:
            return 'Private network'
        else:
            return 'AT&T Mobile (CGNAT)'
    elif ip.startswith('138.199.114.'):
        return 'Office IP'
    elif ip.startswith('45.') or ip.startswith('46.') or ip.startswith('38.') or ip.startswith('142.') or ip.startswith('156.'):
        return 'SUSPICIOUS - Datacenter'
    else:
        return 'Unknown - needs verification'


def main():
    print("=" * 80)
    print("SUSPICIOUS USER VERIFICATION")
    print("=" * 80)
    print()

    credentials = get_credentials()

    for email in SUSPICIOUS_USERS:
        print(f"\n{'='*60}")
        print(f"User: {email}")
        print(f"{'='*60}")

        events = get_login_events(credentials, email)

        if not events:
            print("  No login events found")
            continue

        # Collect unique IPs and categorize
        ip_summary = {}
        for event in events:
            ip = event.get('ipAddress', 'Unknown')
            event_name = event.get('events', [{}])[0].get('name', 'unknown')
            timestamp = event.get('id', {}).get('time', '')[:10]

            if ip not in ip_summary:
                ip_summary[ip] = {
                    'category': analyze_ip(ip),
                    'events': [],
                    'dates': set(),
                }
            ip_summary[ip]['events'].append(event_name)
            ip_summary[ip]['dates'].add(timestamp)

        print(f"\n  IP Summary ({len(ip_summary)} unique IPs):")
        for ip, data in sorted(ip_summary.items(), key=lambda x: len(x[1]['dates']), reverse=True):
            success_count = data['events'].count('login_success')
            failure_count = sum(1 for e in data['events'] if 'failure' in e)
            date_range = f"{min(data['dates'])} to {max(data['dates'])}" if len(data['dates']) > 1 else list(data['dates'])[0]

            flag = "⚠️" if 'SUSPICIOUS' in data['category'] else "✓"
            print(f"    {flag} {ip}")
            print(f"       Category: {data['category']}")
            print(f"       Dates: {date_range}")
            print(f"       Successes: {success_count}, Failures: {failure_count}")

    print("\n")
    print("=" * 80)
    print("LEGEND")
    print("=" * 80)
    print("✓ = Likely legitimate (mobile, office, etc.)")
    print("⚠️ = Needs further investigation")
    print()
    print("Common legitimate IP patterns:")
    print("  - 2600:xxxx (AT&T mobile IPv6)")
    print("  - 2607:xxxx (Verizon mobile IPv6)")
    print("  - 172.56-172.255.x.x (AT&T CGNAT)")
    print("  - 138.199.114.x (Office)")


if __name__ == '__main__':
    main()
