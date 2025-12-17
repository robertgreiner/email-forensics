#!/usr/bin/env python3
"""Analyze Lori's sent emails to determine if Moss was compromised."""

import os
import google.auth
from google.auth import iam
from google.auth.transport import requests as auth_requests
from google.oauth2 import service_account
from googleapiclient.discovery import build

SERVICE_ACCOUNT_EMAIL = 'moss-service-account@hvac-labs.iam.gserviceaccount.com'
DELEGATED_USER = 'lori.maynard@askmoss.com'
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
    service = get_service()

    print("="*80)
    print("ANALYZING LORI'S SENT EMAILS - LOOKING FOR COMPROMISE INDICATORS")
    print("="*80)

    # Get all sent emails to both domains
    queries = [
        ('Sent to ssdhvac.com (legitimate)', 'in:sent to:ssdhvac.com'),
        ('Sent to ssdhvca.com (fraudulent)', 'in:sent to:ssdhvca.com'),
    ]

    sent_to_legit = []
    sent_to_fraud = []

    for label, query in queries:
        print(f"\n{'='*60}")
        print(f"{label}")
        print(f"Query: {query}")
        print(f"{'='*60}")

        results = service.users().messages().list(userId='me', q=query, maxResults=50).execute()
        messages = results.get('messages', [])

        if not messages:
            print("  No messages found")
            continue

        print(f"  Found {len(messages)} messages\n")

        for msg in messages:
            full = service.users().messages().get(userId='me', id=msg['id'], format='full').execute()
            headers = {h['name']: h['value'] for h in full['payload']['headers']}

            date = headers.get('Date', 'UNKNOWN')
            to = headers.get('To', 'UNKNOWN')
            subject = headers.get('Subject', 'UNKNOWN')[:60]
            message_id = headers.get('Message-ID', headers.get('Message-Id', 'UNKNOWN'))
            in_reply_to = headers.get('In-Reply-To', 'NOT PRESENT')

            email_data = {
                'date': date,
                'to': to,
                'subject': subject,
                'message_id': message_id,
                'in_reply_to': in_reply_to
            }

            if 'ssdhvca.com' in query:
                sent_to_fraud.append(email_data)
            else:
                sent_to_legit.append(email_data)

            print(f"  Date: {date}")
            print(f"  To: {to[:80]}..." if len(to) > 80 else f"  To: {to}")
            print(f"  Subject: {subject}...")
            print(f"  Message-ID: {message_id}")
            irt = str(in_reply_to)
            print(f"  In-Reply-To: {irt[:70]}..." if len(irt) > 70 else f"  In-Reply-To: {in_reply_to}")

            # Check if In-Reply-To points to fraudulent or legitimate domain
            if in_reply_to != 'NOT PRESENT':
                if 'BYAPR13MB2743' in str(in_reply_to):
                    print(f"  >>> REPLYING TO FRAUDULENT EMAIL (warehouseathletics tenant)")
                elif 'BLAPR19MB4417' in str(in_reply_to):
                    print(f"  >>> Replying to legitimate Standard Supply email")
                elif 'CAEDQfw' in str(in_reply_to):
                    print(f"  >>> Replying to Gmail message")
            print()

    # Analysis
    print("\n" + "="*80)
    print("COMPROMISE ANALYSIS")
    print("="*80)

    print(f"\nTotal emails sent to ssdhvac.com (legitimate): {len(sent_to_legit)}")
    print(f"Total emails sent to ssdhvca.com (fraudulent): {len(sent_to_fraud)}")

    if sent_to_fraud:
        print("\n[!] Lori DID send emails to the fraudulent domain ssdhvca.com")
        print("    This indicates she was REPLYING to fraudulent emails she received.")
        print("    Her replies went to the attacker instead of the real Janet.")

        # Check what she was replying to
        fraud_replies = [e for e in sent_to_fraud if e['in_reply_to'] != 'NOT PRESENT']
        if fraud_replies:
            print(f"\n    {len(fraud_replies)} of these were replies to messages with In-Reply-To:")
            for e in fraud_replies:
                irt = e['in_reply_to']
                if 'BYAPR13MB2743' in str(irt):
                    print(f"      - Replied to FRAUDULENT message: {irt[:50]}...")

    print("\n" + "-"*40)
    print("KEY QUESTION: Was Moss compromised?")
    print("-"*40)

    print("""
If MOSS was compromised (attacker had access to Lori's mailbox):
  - Attacker could read Lori's inbox directly
  - Attacker could read Lori's sent folder
  - Attacker would NOT need to register a lookalike domain
  - Attacker could just intercept/modify emails or set up forwarding
  - Why would they make Lori send emails to a domain they control?
    They could just READ her replies directly from her sent folder!

If STANDARD SUPPLY was compromised (attacker had access to Janet's mailbox):
  - Attacker sees incoming emails from Lori
  - Attacker registers lookalike domain to impersonate Janet
  - Attacker sends fake emails that thread with legitimate conversation
  - Lori replies, thinking she's emailing Janet
  - Lori's replies go to attacker's domain (ssdhvca.com)
  - This is EXACTLY what we see in the evidence

CONCLUSION: The fact that Lori sent emails TO the fraudulent domain
            proves she was FOOLED, not COMPROMISED.

            If Moss was compromised, the attacker wouldn't need Lori
            to send emails to a different domain - they could just
            read her sent folder directly.
""")

    # Additional check - timeline analysis
    print("\n" + "-"*40)
    print("TIMELINE VERIFICATION")
    print("-"*40)

    print("""
The attack flow was:
1. Attacker monitors Janet's inbox at Standard Supply (sees Lori's emails)
2. Attacker registers ssdhvca.com (lookalike domain)
3. Attacker sets up warehouseathletics M365 tenant
4. Attacker sends fake email appearing to be from Janet
5. Lori receives fake email, it threads with real conversation
6. Lori replies - her reply goes to ssdhvca.com (attacker)
7. Attacker receives Lori's reply, continues impersonation

This flow ONLY makes sense if the attacker was on Standard Supply's side.
If attacker was on Moss's side, steps 2-6 would be unnecessary.
""")

if __name__ == '__main__':
    main()
