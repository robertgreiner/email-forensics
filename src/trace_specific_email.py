#!/usr/bin/env python3
"""
Trace a specific "missing" email to understand what happened to it.
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
ADMIN_USER = os.getenv('ADMIN_USER')
TARGET_USER = 'lori.maynard@askmoss.com'


def get_credentials(admin_email, scopes):
    source_credentials, project = google.auth.default(scopes=['https://www.googleapis.com/auth/cloud-platform'])
    request = auth_requests.Request()
    signer = iam.Signer(request=request, credentials=source_credentials, service_account_email=SERVICE_ACCOUNT_EMAIL)
    return service_account.Credentials(
        signer=signer, service_account_email=SERVICE_ACCOUNT_EMAIL,
        token_uri='https://oauth2.googleapis.com/token', scopes=scopes, subject=admin_email
    )


def main():
    # Find a missing email (from admin log but not in Gmail)
    # Let's pick one from the attacker domain list
    target_subject = "Re: Cintas Invoices/Payments"
    target_to = "lori.maynard@aksmoss.com"

    print(f"Tracing email:")
    print(f"  Subject: {target_subject}")
    print(f"  To: {target_to}")
    print()

    # Find in admin log CSV
    print("Admin Email Log entry:")
    print("-" * 60)
    with open('/home/robert/Downloads/lori-send.csv', 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            if target_to in row.get('To (Envelope)', ''):
                print(f"  Date: {row.get('Date')}")
                print(f"  Message-ID: {row.get('Message ID')[:60]}...")
                print(f"  Subject: {row.get('Subject')}")
                print(f"  From (Header): {row.get('From (Header address)')}")
                print(f"  From (Envelope): {row.get('From (Envelope)')}")
                print(f"  To: {row.get('To (Envelope)')}")
                print(f"  IP: {row.get('IP address')}")
                print(f"  Traffic source: {row.get('Traffic source')}")
                break

    # Search Gmail for this Message-ID
    print()
    print("Gmail search:")
    print("-" * 60)

    # Try Gmail search
    gmail_creds = get_credentials(TARGET_USER, ['https://www.googleapis.com/auth/gmail.readonly'])
    gmail_service = build('gmail', 'v1', credentials=gmail_creds)

    # Search by subject
    query = f'subject:"{target_subject}"'
    results = gmail_service.users().messages().list(
        userId='me', q=query, maxResults=10
    ).execute()

    if results.get('messages'):
        print(f"  Found {len(results['messages'])} messages matching subject")
        for msg in results['messages'][:3]:
            full_msg = gmail_service.users().messages().get(
                userId='me', id=msg['id'], format='metadata'
            ).execute()
            labels = full_msg.get('labelIds', [])
            print(f"    ID: {msg['id']}, Labels: {labels}")
    else:
        print("  No messages found with this subject!")

    # Also check Gmail audit logs for this email
    print()
    print("Gmail audit logs (Reports API):")
    print("-" * 60)

    admin_creds = get_credentials(ADMIN_USER, ['https://www.googleapis.com/auth/admin.reports.audit.readonly'])
    admin_service = build('admin', 'reports_v1', credentials=admin_creds)

    # Search for gmail events around Dec 15
    results = admin_service.activities().list(
        userKey=TARGET_USER,
        applicationName='gmail',
        startTime='2025-12-15T00:00:00.000Z',
        endTime='2025-12-16T00:00:00.000Z',
        maxResults=50
    ).execute()

    events = results.get('items', [])
    print(f"  Found {len(events)} Gmail events on Dec 15")

    # Look for any related to aksmoss
    for event in events:
        for e in event.get('events', []):
            params = {p['name']: p.get('value', '') for p in e.get('parameters', [])}
            if 'aksmoss' in str(params).lower() or 'cintas' in str(params).lower():
                print(f"  Related event: {e.get('name')} - {params}")


if __name__ == '__main__':
    main()
