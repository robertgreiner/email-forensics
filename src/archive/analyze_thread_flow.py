#!/usr/bin/env python3
"""
Analyze the thread flow to determine who initiated contact with the fraudulent domain.
"""

import google.auth
from google.auth import iam
from google.auth.transport import requests as auth_requests
from google.oauth2 import service_account
from googleapiclient.discovery import build
from datetime import datetime

SERVICE_ACCOUNT_EMAIL = 'moss-service-account@hvac-labs.iam.gserviceaccount.com'
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
DELEGATED_USER = 'lori.maynard@askmoss.com'

def get_service():
    source_credentials, project = google.auth.default(scopes=['https://www.googleapis.com/auth/cloud-platform'])
    request = auth_requests.Request()
    signer = iam.Signer(request=request, credentials=source_credentials, service_account_email=SERVICE_ACCOUNT_EMAIL)
    delegated_credentials = service_account.Credentials(
        signer=signer,
        service_account_email=SERVICE_ACCOUNT_EMAIL,
        token_uri='https://oauth2.googleapis.com/token',
        scopes=SCOPES,
        subject=DELEGATED_USER
    )
    return build('gmail', 'v1', credentials=delegated_credentials)

def main():
    service = get_service()

    print("="*80)
    print("THREAD FLOW ANALYSIS - WHO INITIATED CONTACT?")
    print("="*80)

    # Get ALL emails involving ssdhvca.com (fraudulent domain)
    queries = [
        ('FROM fraudulent domain', 'from:ssdhvca.com'),
        ('TO fraudulent domain', 'to:ssdhvca.com'),
    ]

    all_emails = []

    for label, query in queries:
        print(f"\n{label}: {query}")
        results = service.users().messages().list(userId='me', q=query, maxResults=100).execute()
        messages = results.get('messages', [])
        print(f"  Found: {len(messages)} messages")

        for msg in messages:
            full = service.users().messages().get(userId='me', id=msg['id'], format='full').execute()
            headers = {h['name']: h['value'] for h in full['payload']['headers']}

            all_emails.append({
                'gmail_id': msg['id'],
                'date': headers.get('Date', ''),
                'from': headers.get('From', ''),
                'to': headers.get('To', ''),
                'subject': headers.get('Subject', ''),
                'message_id': headers.get('Message-ID', headers.get('Message-Id', '')),
                'in_reply_to': headers.get('In-Reply-To', ''),
                'references': headers.get('References', ''),
                'direction': 'INBOUND' if 'ssdhvca.com' in headers.get('From', '').lower() else 'OUTBOUND'
            })

    # Sort by date
    from email.utils import parsedate_to_datetime
    def parse_date(email):
        try:
            return parsedate_to_datetime(email['date'])
        except:
            return datetime.min

    all_emails.sort(key=parse_date)

    # Deduplicate by message_id
    seen = set()
    unique_emails = []
    for e in all_emails:
        if e['message_id'] not in seen:
            seen.add(e['message_id'])
            unique_emails.append(e)

    print("\n" + "="*80)
    print("CHRONOLOGICAL EMAIL FLOW WITH FRAUDULENT DOMAIN (ssdhvca.com)")
    print("="*80)

    for i, email in enumerate(unique_emails, 1):
        print(f"\n--- Email #{i} [{email['direction']}] ---")
        print(f"Date: {email['date']}")
        print(f"From: {email['from']}")
        print(f"To: {email['to'][:80]}..." if len(email['to']) > 80 else f"To: {email['to']}")
        print(f"Subject: {email['subject'][:60]}...")
        print(f"Message-ID: {email['message_id'][:60]}...")

        if email['in_reply_to']:
            print(f"In-Reply-To: {email['in_reply_to'][:60]}...")
            # Identify what they're replying to
            if 'BYAPR13MB2743' in email['in_reply_to']:
                print("  ^-- REPLYING TO: Fraudulent email (attacker's M365 tenant)")
            elif 'BLAPR19MB4417' in email['in_reply_to']:
                print("  ^-- REPLYING TO: Legitimate Standard Supply email")
            elif 'mail.gmail.com' in email['in_reply_to']:
                print("  ^-- REPLYING TO: Gmail message (Moss employee)")
        else:
            print("In-Reply-To: NOT PRESENT (could be thread initiator)")

    # Analysis
    print("\n" + "="*80)
    print("ANALYSIS: WHO INITIATED?")
    print("="*80)

    inbound = [e for e in unique_emails if e['direction'] == 'INBOUND']
    outbound = [e for e in unique_emails if e['direction'] == 'OUTBOUND']

    print(f"\nInbound (FROM ssdhvca.com): {len(inbound)}")
    print(f"Outbound (TO ssdhvca.com): {len(outbound)}")

    if inbound and outbound:
        first_inbound = inbound[0]
        first_outbound = outbound[0]

        print(f"\nFirst INBOUND (from attacker):")
        print(f"  Date: {first_inbound['date']}")
        print(f"  Subject: {first_inbound['subject'][:50]}")
        print(f"  In-Reply-To: {first_inbound['in_reply_to'][:50] if first_inbound['in_reply_to'] else 'NOT PRESENT'}")

        print(f"\nFirst OUTBOUND (Lori to attacker):")
        print(f"  Date: {first_outbound['date']}")
        print(f"  Subject: {first_outbound['subject'][:50]}")
        print(f"  In-Reply-To: {first_outbound['in_reply_to'][:50] if first_outbound['in_reply_to'] else 'NOT PRESENT'}")

        # Check if Lori's first outbound is replying to attacker
        if first_outbound['in_reply_to']:
            if 'BYAPR13MB2743' in first_outbound['in_reply_to']:
                print("\n  ==> Lori's first email TO ssdhvca.com is a REPLY to a fraudulent email")
                print("      The attacker initiated contact, Lori replied.")
            else:
                print(f"\n  ==> Lori's first email references: {first_outbound['in_reply_to']}")
                print("      Need to trace this Message-ID to understand the flow")
        else:
            print("\n  [!] Lori's first email has NO In-Reply-To header")
            print("      This could mean SHE initiated contact (suspicious!)")

    # Check if we're missing emails - look at References to find missing messages
    print("\n" + "="*80)
    print("CHECKING FOR MISSING EMAILS IN THREAD")
    print("="*80)

    all_message_ids = set(e['message_id'] for e in unique_emails)
    referenced_ids = set()

    for e in unique_emails:
        if e['in_reply_to']:
            referenced_ids.add(e['in_reply_to'].strip())
        if e['references']:
            for ref in e['references'].split():
                referenced_ids.add(ref.strip())

    missing = referenced_ids - all_message_ids
    missing = [m for m in missing if m]  # Remove empty

    if missing:
        print(f"\nFound {len(missing)} referenced Message-IDs not in our dataset:")
        for mid in missing[:10]:  # Show first 10
            print(f"  - {mid[:70]}...")
            if 'BYAPR13MB2743' in mid:
                print("    ^-- This is from the ATTACKER'S M365 tenant (ssdhvca.com)")
            elif 'BLAPR19MB4417' in mid:
                print("    ^-- This is from Standard Supply's LEGITIMATE tenant (ssdhvac.com)")
            elif 'mail.gmail.com' in mid:
                print("    ^-- This is from Gmail (Moss)")
    else:
        print("\nNo missing Message-IDs detected")

    # Check TRASH for fraudulent emails
    print("\n" + "="*80)
    print("CHECKING TRASH FOR FRAUDULENT EMAILS")
    print("="*80)

    trash_results = service.users().messages().list(userId='me', q='in:trash from:ssdhvca.com', maxResults=50).execute()
    trash_messages = trash_results.get('messages', [])

    print(f"\nFraudulent emails in TRASH: {len(trash_messages)}")

    if trash_messages:
        print("\nTRASHED fraudulent emails:")
        for msg in trash_messages:
            full = service.users().messages().get(userId='me', id=msg['id'], format='full').execute()
            headers = {h['name']: h['value'] for h in full['payload']['headers']}
            print(f"\n  Date: {headers.get('Date', '')}")
            print(f"  From: {headers.get('From', '')}")
            print(f"  Subject: {headers.get('Subject', '')[:50]}")
            print(f"  Message-ID: {headers.get('Message-ID', headers.get('Message-Id', ''))[:50]}")

if __name__ == '__main__':
    main()
