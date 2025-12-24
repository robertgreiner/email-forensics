#!/usr/bin/env python3
"""Analyze Madelin Martinez's emails for Reply-To poisoning or different attack patterns."""

import os
import google.auth
from google.auth import iam
from google.auth.transport import requests as auth_requests
from google.oauth2 import service_account
from googleapiclient.discovery import build

SERVICE_ACCOUNT_EMAIL = 'moss-service-account@hvac-labs.iam.gserviceaccount.com'
DELEGATED_USER = 'madelin.martinez@askmoss.com'
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

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
    print("="*80)
    print(f"ANALYZING MADELIN MARTINEZ'S MAILBOX")
    print(f"User: {DELEGATED_USER}")
    print("="*80)

    service = get_service()

    # Search queries
    queries = [
        ('From ssdhvac.com (legitimate)', 'from:ssdhvac.com'),
        ('From ssdhvca.com (fraudulent)', 'from:ssdhvca.com'),
        ('Sent to ssdhvac.com', 'in:sent to:ssdhvac.com'),
        ('Sent to ssdhvca.com', 'in:sent to:ssdhvca.com'),
    ]

    all_legit = []
    all_fraud = []

    for label, query in queries:
        print(f"\n{'='*60}")
        print(f"{label}")
        print(f"Query: {query}")
        print(f"{'='*60}")

        try:
            results = service.users().messages().list(userId='me', q=query, maxResults=50).execute()
            messages = results.get('messages', [])
        except Exception as e:
            print(f"  ERROR: {e}")
            continue

        if not messages:
            print("  No messages found")
            continue

        print(f"  Found {len(messages)} messages\n")

        for msg in messages:
            full = service.users().messages().get(userId='me', id=msg['id'], format='full').execute()
            headers = {h['name']: h['value'] for h in full['payload']['headers']}

            date = headers.get('Date', 'UNKNOWN')
            from_addr = headers.get('From', 'UNKNOWN')
            to = headers.get('To', 'UNKNOWN')
            subject = headers.get('Subject', 'UNKNOWN')[:50]
            reply_to = headers.get('Reply-To', 'NOT PRESENT')
            message_id = headers.get('Message-ID', headers.get('Message-Id', 'UNKNOWN'))
            in_reply_to = headers.get('In-Reply-To', 'NOT PRESENT')

            # Get DKIM domain
            dkim_sig = headers.get('DKIM-Signature', '')
            dkim_domain = 'UNKNOWN'
            if dkim_sig:
                if 'd=' in dkim_sig:
                    dkim_domain = dkim_sig.split('d=')[1].split(';')[0].strip()

            email_data = {
                'date': date,
                'from': from_addr,
                'to': to,
                'subject': subject,
                'reply_to': reply_to,
                'message_id': message_id,
                'in_reply_to': in_reply_to,
                'dkim_domain': dkim_domain
            }

            if 'ssdhvac.com' in str(from_addr).lower():
                all_legit.append(email_data)
            elif 'ssdhvca.com' in str(from_addr).lower():
                all_fraud.append(email_data)

            print(f"  Date: {date}")
            print(f"  From: {from_addr}")
            to_short = to[:70] + "..." if len(str(to)) > 70 else to
            print(f"  To: {to_short}")
            print(f"  Subject: {subject}...")
            print(f"  Reply-To: {reply_to}")
            print(f"  DKIM Domain: {dkim_domain}")

            # Flag suspicious Reply-To
            if reply_to != 'NOT PRESENT':
                from_domain = from_addr.split('@')[-1].replace('>', '') if '@' in from_addr else ''
                reply_domain = reply_to.split('@')[-1].replace('>', '') if '@' in reply_to else ''
                if from_domain.lower() != reply_domain.lower():
                    print(f"  >>> WARNING: Reply-To domain ({reply_domain}) differs from From domain ({from_domain})!")
                    if 'ssdhvca' in reply_domain.lower():
                        print(f"  >>> !!! SMOKING GUN: Reply-To points to FRAUDULENT domain !!!")

            # Flag if legitimate email with fraudulent DKIM
            if 'ssdhvac.com' in str(from_addr).lower() and 'warehouseathletics' in dkim_domain.lower():
                print(f"  >>> WARNING: Legitimate domain but fraudulent DKIM!")

            print()

    # Summary
    print("\n" + "="*80)
    print("SUMMARY FOR MADELIN MARTINEZ")
    print("="*80)

    print(f"\nLegitimate emails from ssdhvac.com: {len(all_legit)}")
    print(f"Fraudulent emails from ssdhvca.com: {len(all_fraud)}")

    # Check for Reply-To poisoning in legitimate emails
    print("\n" + "-"*40)
    print("REPLY-TO POISONING CHECK:")
    print("-"*40)

    poisoned = [e for e in all_legit if e['reply_to'] != 'NOT PRESENT']
    if poisoned:
        print(f"\n[!] Found {len(poisoned)} legitimate emails WITH Reply-To header:")
        for e in poisoned:
            print(f"\n  Date: {e['date']}")
            print(f"  From: {e['from']}")
            print(f"  Reply-To: {e['reply_to']}")
            if 'ssdhvca' in str(e['reply_to']).lower():
                print(f"  >>> !!! SMOKING GUN - REPLY-TO POINTS TO FRAUDULENT DOMAIN !!!")
    else:
        print("\n  No Reply-To headers found in legitimate emails from ssdhvac.com")
        print("  CONCLUSION: No Reply-To poisoning detected for Madelin")

if __name__ == '__main__':
    main()
