#!/usr/bin/env python3
"""
Compare Message-IDs between Admin Log (259) and Gmail SENT folder (62).
Find the "missing" emails.
"""

import os
import csv
from dotenv import load_dotenv
import google.auth
from google.auth import iam
from google.auth.transport import requests as auth_requests
from google.oauth2 import service_account
from googleapiclient.discovery import build

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


def get_admin_log_message_ids(filepath):
    """Get all Message-IDs from Admin Email Log CSV."""
    msg_ids = {}
    with open(filepath, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            msg_id = row.get('Message ID', '')
            if msg_id and msg_id not in msg_ids:
                msg_ids[msg_id] = {
                    'date': row.get('Date', '')[:10],
                    'subject': row.get('Subject', ''),
                    'to': row.get('To (Envelope)', ''),
                    'ip': row.get('IP address', '')
                }
    return msg_ids


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

    msg_ids = {}
    for msg in all_messages:
        full_msg = service.users().messages().get(
            userId='me', id=msg['id'], format='metadata',
            metadataHeaders=['Message-ID', 'Subject', 'To', 'Date']
        ).execute()
        headers = {h['name'].lower(): h['value'] for h in full_msg.get('payload', {}).get('headers', [])}
        mid = headers.get('message-id', '')
        if mid:
            msg_ids[mid] = {
                'subject': headers.get('subject', ''),
                'to': headers.get('to', ''),
                'date': headers.get('date', '')
            }
    return msg_ids


def main():
    # Get Admin Log Message-IDs
    admin_ids = get_admin_log_message_ids('/home/robert/Downloads/lori-send.csv')
    print(f"Admin Email Log: {len(admin_ids)} unique Message-IDs")

    # Get Gmail Message-IDs
    creds = get_credentials(TARGET_USER)
    service = build('gmail', 'v1', credentials=creds)
    gmail_ids = get_gmail_message_ids(service)
    print(f"Gmail SENT folder: {len(gmail_ids)} unique Message-IDs")

    # Find differences
    admin_set = set(admin_ids.keys())
    gmail_set = set(gmail_ids.keys())

    in_both = admin_set & gmail_set
    only_in_admin = admin_set - gmail_set
    only_in_gmail = gmail_set - admin_set

    print()
    print(f"In BOTH:            {len(in_both)}")
    print(f"Only in Admin Log:  {len(only_in_admin)} <-- MISSING FROM MAILBOX")
    print(f"Only in Gmail:      {len(only_in_gmail)} <-- Not in admin log?")

    if only_in_admin:
        print()
        print("=" * 70)
        print("MISSING FROM MAILBOX (in Admin Log but not in Gmail SENT):")
        print("=" * 70)

        # Group by date and show sample
        by_date = {}
        for mid in only_in_admin:
            info = admin_ids[mid]
            date = info['date']
            if date not in by_date:
                by_date[date] = []
            by_date[date].append(info)

        for date in sorted(by_date.keys()):
            print(f"\n{date}: {len(by_date[date])} missing emails")
            for info in by_date[date][:5]:  # Show first 5
                print(f"  To: {info['to'][:40]:<40} Subj: {info['subject'][:35]}")

    # Check if missing emails went to attacker domains
    print()
    print("=" * 70)
    print("MISSING EMAILS TO ATTACKER DOMAINS:")
    print("=" * 70)
    suspicious = ['ssdhvca.com', 'aksmoss.com', 'sshdvac.com']
    for mid in only_in_admin:
        info = admin_ids[mid]
        to_domain = info['to'].split('@')[1] if '@' in info['to'] else ''
        if to_domain.lower() in suspicious:
            print(f"  [{info['date']}] To: {info['to']} Subj: {info['subject']}")


if __name__ == '__main__':
    main()
