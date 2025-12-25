#!/usr/bin/env python3
"""
Categorize the "missing" emails to understand why they're not in SENT folder.
"""

import os
import csv
from dotenv import load_dotenv
import google.auth
from google.auth import iam
from google.auth.transport import requests as auth_requests
from google.oauth2 import service_account
from googleapiclient.discovery import build
from collections import defaultdict

load_dotenv()

SERVICE_ACCOUNT_EMAIL = os.getenv('SERVICE_ACCOUNT_EMAIL')
TARGET_USER = 'lori.maynard@askmoss.com'
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']


def get_credentials(target_user):
    source_credentials, project = google.auth.default(scopes=['https://www.googleapis.com/auth/cloud-platform'])
    request = auth_requests.Request()
    signer = iam.Signer(request=request, credentials=source_credentials, service_account_email=SERVICE_ACCOUNT_EMAIL)
    return service_account.Credentials(
        signer=signer, service_account_email=SERVICE_ACCOUNT_EMAIL,
        token_uri='https://oauth2.googleapis.com/token', scopes=SCOPES, subject=target_user
    )


def get_gmail_message_ids(service):
    """Get all Message-IDs from Gmail SENT folder for Dec 1-17."""
    query = 'in:sent after:2025/12/01 before:2025/12/18'
    all_messages = []
    page_token = None
    while True:
        results = service.users().messages().list(
            userId='me', q=query, pageToken=page_token, maxResults=500
        ).execute()
        all_messages.extend(results.get('messages', []))
        page_token = results.get('nextPageToken')
        if not page_token:
            break

    msg_ids = set()
    for msg in all_messages:
        full_msg = service.users().messages().get(
            userId='me', id=msg['id'], format='metadata',
            metadataHeaders=['Message-ID']
        ).execute()
        headers = {h['name'].lower(): h['value'] for h in full_msg.get('payload', {}).get('headers', [])}
        mid = headers.get('message-id', '')
        if mid:
            msg_ids.add(mid)
    return msg_ids


def main():
    # Get Gmail Message-IDs
    creds = get_credentials(TARGET_USER)
    service = build('gmail', 'v1', credentials=creds)
    gmail_ids = get_gmail_message_ids(service)

    # Read admin log and categorize missing
    categories = defaultdict(list)
    suspicious = []

    with open('/home/robert/Downloads/lori-send.csv', 'r') as f:
        reader = csv.DictReader(f)
        seen = set()
        for row in reader:
            msg_id = row.get('Message ID', '')
            if msg_id and msg_id not in seen and msg_id not in gmail_ids:
                seen.add(msg_id)
                subject = row.get('Subject', '')
                to_addr = row.get('To (Envelope)', '')
                date = row.get('Date', '')[:10]
                ip = row.get('IP address', '')

                # Categorize
                if subject.startswith('Accepted:') or subject.startswith('Declined:') or subject.startswith('Tentative:'):
                    categories['calendar_responses'].append({'date': date, 'subject': subject, 'to': to_addr})
                elif 'ssdhvca.com' in to_addr.lower() or 'aksmoss.com' in to_addr.lower():
                    categories['attacker_domains'].append({'date': date, 'subject': subject, 'to': to_addr, 'ip': ip})
                elif to_addr.endswith('@askmoss.com'):
                    categories['internal_askmoss'].append({'date': date, 'subject': subject, 'to': to_addr})
                elif to_addr.endswith('@mossutilities.com'):
                    categories['internal_mossutil'].append({'date': date, 'subject': subject, 'to': to_addr})
                else:
                    categories['external'].append({'date': date, 'subject': subject, 'to': to_addr, 'ip': ip})

    print("CATEGORIZATION OF 200 MISSING EMAILS")
    print("=" * 70)
    print()

    total = 0
    for cat, items in sorted(categories.items()):
        count = len(items)
        total += count
        print(f"{cat}: {count}")

    print(f"\nTotal categorized: {total}")

    # Show attacker domain details
    if categories['attacker_domains']:
        print()
        print("=" * 70)
        print("CRITICAL: EMAILS TO ATTACKER DOMAINS")
        print("=" * 70)
        for item in categories['attacker_domains']:
            print(f"  [{item['date']}] To: {item['to']}")
            print(f"    Subject: {item['subject']}")
            print(f"    IP: {item['ip']}")
            print()

    # Show external emails (potential concern)
    if categories['external']:
        print()
        print("=" * 70)
        print("EXTERNAL EMAILS NOT IN SENT FOLDER (sample):")
        print("=" * 70)
        for item in categories['external'][:15]:
            domain = item['to'].split('@')[1] if '@' in item['to'] else 'unknown'
            print(f"  [{item['date']}] {domain}: {item['subject'][:50]}")


if __name__ == '__main__':
    main()
