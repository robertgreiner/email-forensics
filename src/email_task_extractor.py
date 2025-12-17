#!/usr/bin/env python3
"""
Email Task Extractor - POC
Analyzes recent emails to extract action items:
1. Things the user is on the hook to complete
2. Things owed to the user

Uses Gmail API with domain-wide delegation.
"""

import os
import re
import base64
import google.auth
from google.auth import iam
from google.auth.transport import requests as auth_requests
from google.oauth2 import service_account
from googleapiclient.discovery import build
from datetime import datetime

SERVICE_ACCOUNT_EMAIL = 'moss-service-account@hvac-labs.iam.gserviceaccount.com'
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

# User to analyze
TARGET_USER = 'lori.maynard@askmoss.com'

# Number of recent emails to analyze
NUM_EMAILS = 10

def get_service(delegated_user):
    """Create Gmail API service with domain-wide delegation."""
    source_credentials, project = google.auth.default(scopes=['https://www.googleapis.com/auth/cloud-platform'])
    request = auth_requests.Request()
    signer = iam.Signer(request=request, credentials=source_credentials, service_account_email=SERVICE_ACCOUNT_EMAIL)
    delegated_credentials = service_account.Credentials(
        signer=signer,
        service_account_email=SERVICE_ACCOUNT_EMAIL,
        token_uri='https://oauth2.googleapis.com/token',
        scopes=SCOPES,
        subject=delegated_user
    )
    return build('gmail', 'v1', credentials=delegated_credentials)

def get_body_text(payload):
    """Extract plain text body from email payload."""
    body_text = ""

    if 'body' in payload and payload['body'].get('data'):
        try:
            body_text = base64.urlsafe_b64decode(payload['body']['data']).decode('utf-8', errors='replace')
        except:
            pass

    if 'parts' in payload:
        for part in payload['parts']:
            mime_type = part.get('mimeType', '')
            if mime_type == 'text/plain':
                if part.get('body', {}).get('data'):
                    try:
                        body_text += base64.urlsafe_b64decode(part['body']['data']).decode('utf-8', errors='replace')
                    except:
                        pass
            elif 'parts' in part:
                body_text += get_body_text(part)

    return body_text

def extract_action_items(body, subject, from_addr, to_addr, user_email):
    """
    Extract action items from email body.
    Returns (items_for_user, items_owed_to_user)
    """
    items_for_user = []
    items_owed_to_user = []

    # Normalize the body text
    body_lower = body.lower()
    lines = body.split('\n')

    # Patterns that indicate action items FOR the recipient
    action_patterns_for_user = [
        r'can you\s+(.+?)[\?\.]',
        r'could you\s+(.+?)[\?\.]',
        r'please\s+(.+?)[\.\n]',
        r'need you to\s+(.+?)[\.\n]',
        r'would you\s+(.+?)[\?\.]',
        r'let me know\s+(.+?)[\.\n]',
        r'send (?:me|us)\s+(.+?)[\.\n]',
        r'get (?:me|us)\s+(.+?)[\.\n]',
        r'provide\s+(.+?)[\.\n]',
        r'confirm\s+(.+?)[\.\n]',
        r'review\s+(.+?)[\.\n]',
        r'update\s+(.+?)[\.\n]',
    ]

    # Patterns that indicate things OWED to the user
    action_patterns_owed = [
        r'i will\s+(.+?)[\.\n]',
        r"i'll\s+(.+?)[\.\n]",
        r'we will\s+(.+?)[\.\n]',
        r"we'll\s+(.+?)[\.\n]",
        r'i can\s+(.+?)[\.\n]',
        r'expect\s+(.+?)[\.\n]',
        r'will send\s+(.+?)[\.\n]',
        r'will provide\s+(.+?)[\.\n]',
        r'will get\s+(.+?)[\.\n]',
        r'will have\s+(.+?)[\.\n]',
    ]

    user_is_recipient = user_email.lower() in to_addr.lower()
    user_is_sender = user_email.lower() in from_addr.lower()

    # If user received this email, look for action items assigned to them
    if user_is_recipient:
        for pattern in action_patterns_for_user:
            matches = re.findall(pattern, body_lower, re.IGNORECASE)
            for match in matches:
                item = match.strip()[:100]  # Limit length
                if len(item) > 10:  # Filter out very short matches
                    items_for_user.append(item)

        # Also look for promises made TO the user
        for pattern in action_patterns_owed:
            matches = re.findall(pattern, body_lower, re.IGNORECASE)
            for match in matches:
                item = match.strip()[:100]
                if len(item) > 10:
                    items_owed_to_user.append(item)

    # If user sent this email, their commitments become items for them
    if user_is_sender:
        for pattern in action_patterns_owed:
            matches = re.findall(pattern, body_lower, re.IGNORECASE)
            for match in matches:
                item = match.strip()[:100]
                if len(item) > 10:
                    items_for_user.append(item)

        # Things they requested become items owed to them
        for pattern in action_patterns_for_user:
            matches = re.findall(pattern, body_lower, re.IGNORECASE)
            for match in matches:
                item = match.strip()[:100]
                if len(item) > 10:
                    items_owed_to_user.append(item)

    return items_for_user, items_owed_to_user

def analyze_emails(user_email, num_emails=10):
    """Analyze recent emails for a user and extract action items."""

    print(f"{'='*60}")
    print(f"EMAIL TASK EXTRACTOR - POC")
    print(f"{'='*60}")
    print(f"User: {user_email}")
    print(f"Analyzing last {num_emails} emails...")
    print(f"{'='*60}\n")

    service = get_service(user_email)

    # Get recent emails from inbox
    results = service.users().messages().list(
        userId='me',
        maxResults=num_emails,
        labelIds=['INBOX']
    ).execute()

    messages = results.get('messages', [])

    if not messages:
        print("No messages found.")
        return

    all_items_for_user = []
    all_items_owed_to_user = []

    for i, msg in enumerate(messages):
        msg_id = msg['id']

        # Get full message
        full_msg = service.users().messages().get(userId='me', id=msg_id, format='full').execute()
        headers = {h['name']: h['value'] for h in full_msg['payload']['headers']}

        from_addr = headers.get('From', '')
        to_addr = headers.get('To', '')
        subject = headers.get('Subject', '(no subject)')
        date = headers.get('Date', '')

        # Get body
        body = get_body_text(full_msg['payload'])

        # Extract action items
        items_for, items_owed = extract_action_items(body, subject, from_addr, to_addr, user_email)

        # Print email summary
        print(f"[Email {i+1}] {subject[:50]}...")
        print(f"   From: {from_addr[:40]}")
        print(f"   Date: {date}")

        if items_for:
            print(f"   → Action items for {user_email.split('@')[0]}:")
            for item in items_for[:3]:  # Limit to 3 per email
                print(f"      • {item}")
                all_items_for_user.append({
                    'item': item,
                    'source': subject[:40],
                    'from': from_addr.split('<')[0].strip() if '<' in from_addr else from_addr[:30],
                    'date': date
                })

        if items_owed:
            print(f"   → Items owed to {user_email.split('@')[0]}:")
            for item in items_owed[:3]:
                print(f"      • {item}")
                all_items_owed_to_user.append({
                    'item': item,
                    'source': subject[:40],
                    'from': from_addr.split('<')[0].strip() if '<' in from_addr else from_addr[:30],
                    'date': date
                })

        if not items_for and not items_owed:
            print(f"   (no action items detected)")

        print()

    # Print summary
    print(f"\n{'='*60}")
    print(f"TASK SUMMARY FOR {user_email.split('@')[0].upper()}")
    print(f"{'='*60}\n")

    print(f"📋 THINGS YOU NEED TO DO ({len(all_items_for_user)} items)")
    print("-" * 40)
    if all_items_for_user:
        seen = set()
        for item in all_items_for_user:
            if item['item'] not in seen:
                seen.add(item['item'])
                print(f"  □ {item['item']}")
                print(f"    └─ From: {item['from']} | Re: {item['source']}")
    else:
        print("  (none detected)")

    print(f"\n📥 THINGS OWED TO YOU ({len(all_items_owed_to_user)} items)")
    print("-" * 40)
    if all_items_owed_to_user:
        seen = set()
        for item in all_items_owed_to_user:
            if item['item'] not in seen:
                seen.add(item['item'])
                print(f"  ○ {item['item']}")
                print(f"    └─ From: {item['from']} | Re: {item['source']}")
    else:
        print("  (none detected)")

    print(f"\n{'='*60}")
    print("NOTE: This is a POC using pattern matching.")
    print("For production, consider integrating with an LLM for better accuracy.")
    print(f"{'='*60}")

def main():
    analyze_emails(TARGET_USER, NUM_EMAILS)

if __name__ == '__main__':
    main()
