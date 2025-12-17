#!/usr/bin/env python3
"""
Gmail API Email Header Retrieval Script
Uses domain-wide delegation via ADC impersonation to access a user's mailbox.

Usage:
    # First, set up impersonation:
    gcloud auth application-default login --impersonate-service-account=SERVICE_ACCOUNT_EMAIL

    # Then run:
    python get_email_headers.py

Prerequisites:
    pip install google-auth google-api-python-client python-dotenv
"""

import os
import base64
from datetime import datetime
from dotenv import load_dotenv
import google.auth
from google.oauth2 import service_account
from googleapiclient.discovery import build

# Load environment variables from .env file
load_dotenv()

# Configuration
SERVICE_ACCOUNT_EMAIL = os.getenv('SERVICE_ACCOUNT_EMAIL', 'moss-service-account@hvac-labs.iam.gserviceaccount.com')
DELEGATED_USER = os.getenv('DELEGATED_USER', 'lori.maynard@askmoss.com')

# Gmail API scopes needed for reading emails
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

# Email search parameters - BEC Investigation
TARGET_FROM = os.getenv('TARGET_FROM', 'jhalstead-wiggins@ssdhvca.com')
TARGET_FROM_DOMAIN = 'ssdhvca.com'  # Note: vca not vac
TARGET_SUBJECT = os.getenv('TARGET_SUBJECT', 'Re: 125604 Moss Mechanical LLC & 128659 Moss Mechanical LLC- Heritage')
TARGET_DATE = '2025/12/04'  # Dec 4, 2025


def get_gmail_service():
    """Create Gmail API service with domain-wide delegation via ADC impersonation."""
    from google.auth import iam
    from google.auth.transport import requests as auth_requests

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
        subject=DELEGATED_USER
    )

    # Build the Gmail API service
    service = build('gmail', 'v1', credentials=delegated_credentials)
    return service


def search_emails_by_query(service, query):
    """Search for emails using a specific query."""
    try:
        results = service.users().messages().list(
            userId='me',
            q=query,
            maxResults=50
        ).execute()
        return results.get('messages', [])
    except Exception as e:
        print(f"[-] Search failed for query '{query}': {e}")
        return []


def search_all_relevant_emails(service):
    """Search for all emails related to the BEC investigation."""

    all_messages = {}

    # Search queries for the investigation
    queries = [
        # Legitimate domain emails (ssdhvac.com - note: vac)
        ('ssdhvac.com - All', 'from:ssdhvac.com'),
        ('ssdhvac.com - Nov 21', 'from:ssdhvac.com after:2025/11/20 before:2025/11/22'),
        ('ssdhvac.com - Dec 3', 'from:ssdhvac.com after:2025/12/02 before:2025/12/04'),

        # Fraudulent domain emails (ssdhvca.com - note: vca)
        ('ssdhvca.com - All', 'from:ssdhvca.com'),
        ('ssdhvca.com - Trash', 'in:trash from:ssdhvca.com'),

        # Also check sent folder for replies
        ('Sent to ssdhvac', 'in:sent to:ssdhvac.com'),
        ('Sent to ssdhvca', 'in:sent to:ssdhvca.com'),
    ]

    for label, query in queries:
        print(f"\n[*] Searching: {label}")
        print(f"    Query: {query}")
        messages = search_emails_by_query(service, query)
        if messages:
            print(f"    [+] Found {len(messages)} message(s)")
            for msg in messages:
                all_messages[msg['id']] = msg
        else:
            print(f"    [-] No messages found")

    return list(all_messages.values())


def get_full_headers(service, message_id):
    """Retrieve full email headers for a specific message."""

    # Get the message in 'full' format to access headers
    message = service.users().messages().get(
        userId='me',
        id=message_id,
        format='full'
    ).execute()

    return message


def get_raw_message(service, message_id):
    """Retrieve raw email (RFC 2822 format) for complete headers."""

    message = service.users().messages().get(
        userId='me',
        id=message_id,
        format='raw'
    ).execute()

    # Decode the raw message
    raw_data = message.get('raw', '')
    if raw_data:
        decoded = base64.urlsafe_b64decode(raw_data).decode('utf-8', errors='replace')
        return decoded
    return None


def extract_headers(message):
    """Extract headers from message payload."""
    headers = {}
    payload = message.get('payload', {})
    header_list = payload.get('headers', [])

    for header in header_list:
        name = header.get('name', '')
        value = header.get('value', '')
        # Store all headers, handle duplicates by making a list
        if name in headers:
            if isinstance(headers[name], list):
                headers[name].append(value)
            else:
                headers[name] = [headers[name], value]
        else:
            headers[name] = value

    return headers


def print_forensic_headers(headers, raw_headers=None):
    """Print headers relevant to email forensics/reply analysis."""

    print("\n" + "="*80)
    print("FORENSIC EMAIL HEADER ANALYSIS")
    print("="*80)

    # Critical headers for reply-to investigation
    critical_headers = [
        'From',
        'Reply-To',
        'Return-Path',
        'Sender',
        'X-Original-Sender',
        'X-Original-From',
    ]

    print("\n[CRITICAL - Reply Destination Headers]")
    print("-"*40)
    for h in critical_headers:
        value = headers.get(h, 'NOT PRESENT')
        flag = ""
        # Flag if Reply-To differs from From
        if h == 'Reply-To' and value != 'NOT PRESENT':
            from_addr = headers.get('From', '')
            if value.lower() != from_addr.lower():
                flag = " ⚠️  DIFFERS FROM 'From' HEADER!"
        print(f"{h}: {value}{flag}")

    # Message routing headers
    routing_headers = [
        'To',
        'Cc',
        'Bcc',
        'Delivered-To',
        'X-Forwarded-To',
        'X-Forwarded-For',
    ]

    print("\n[Message Routing]")
    print("-"*40)
    for h in routing_headers:
        value = headers.get(h, 'NOT PRESENT')
        if value != 'NOT PRESENT':
            print(f"{h}: {value}")

    # Message identification
    id_headers = [
        'Message-ID',
        'Message-Id',
        'In-Reply-To',
        'References',
        'Thread-Index',
    ]

    print("\n[Message Identification]")
    print("-"*40)
    for h in id_headers:
        value = headers.get(h, 'NOT PRESENT')
        if value != 'NOT PRESENT':
            print(f"{h}: {value}")

    # Authentication headers (SPF, DKIM, DMARC)
    auth_headers = [
        'Authentication-Results',
        'ARC-Authentication-Results',
        'Received-SPF',
        'DKIM-Signature',
        'X-Google-DKIM-Signature',
    ]

    print("\n[Authentication Results]")
    print("-"*40)
    for h in auth_headers:
        value = headers.get(h, 'NOT PRESENT')
        if value != 'NOT PRESENT':
            # Truncate long values for readability
            if len(str(value)) > 200:
                print(f"{h}: {str(value)[:200]}...")
            else:
                print(f"{h}: {value}")

    # Date/time headers
    date_headers = ['Date', 'X-MS-Exchange-Organization-SCL', 'X-MS-Exchange-Organization-AuthSource']

    print("\n[Timestamp & Exchange Headers]")
    print("-"*40)
    for h in date_headers:
        value = headers.get(h, 'NOT PRESENT')
        if value != 'NOT PRESENT':
            print(f"{h}: {value}")

    # Print Received headers (mail path) - these can reveal the actual origin
    print("\n[Mail Path - Received Headers (newest first)]")
    print("-"*40)
    received = headers.get('Received', [])
    if isinstance(received, str):
        received = [received]
    for i, r in enumerate(received):
        print(f"\n[Hop {i+1}]")
        print(f"{r[:500]}..." if len(r) > 500 else r)

    # Print all headers for completeness
    print("\n" + "="*80)
    print("ALL HEADERS")
    print("="*80)
    for name, value in sorted(headers.items()):
        if isinstance(value, list):
            for v in value:
                print(f"{name}: {v[:200]}..." if len(str(v)) > 200 else f"{name}: {v}")
        else:
            print(f"{name}: {value[:200]}..." if len(str(value)) > 200 else f"{name}: {value}")


def get_full_email_details(headers):
    """Extract all forensic details from headers."""

    from_addr = headers.get('From', 'UNKNOWN')
    reply_to = headers.get('Reply-To', 'NOT PRESENT')
    return_path = headers.get('Return-Path', 'NOT PRESENT')
    date = headers.get('Date', 'UNKNOWN')
    subject = headers.get('Subject', 'UNKNOWN')
    message_id = headers.get('Message-ID', headers.get('Message-Id', 'UNKNOWN'))
    in_reply_to = headers.get('In-Reply-To', 'NOT PRESENT')
    references = headers.get('References', 'NOT PRESENT')
    to = headers.get('To', 'UNKNOWN')
    cc = headers.get('Cc', headers.get('CC', 'NOT PRESENT'))

    # Get DKIM domain
    dkim_sig = headers.get('DKIM-Signature', '')
    dkim_domain = 'UNKNOWN'
    if dkim_sig:
        if isinstance(dkim_sig, list):
            dkim_sig = dkim_sig[0]
        if 'd=' in dkim_sig:
            dkim_domain = dkim_sig.split('d=')[1].split(';')[0].strip()

    # Get authentication results
    auth_results = headers.get('Authentication-Results', '')
    if isinstance(auth_results, list):
        auth_results = auth_results[0] if auth_results else ''

    # Parse SPF/DKIM/DMARC from auth results
    spf_result = 'UNKNOWN'
    dkim_result = 'UNKNOWN'
    dmarc_result = 'UNKNOWN'
    if auth_results:
        if 'spf=pass' in auth_results.lower():
            spf_result = 'PASS'
        elif 'spf=fail' in auth_results.lower():
            spf_result = 'FAIL'
        elif 'spf=softfail' in auth_results.lower():
            spf_result = 'SOFTFAIL'
        elif 'spf=none' in auth_results.lower():
            spf_result = 'NONE'

        if 'dkim=pass' in auth_results.lower():
            dkim_result = 'PASS'
        elif 'dkim=fail' in auth_results.lower():
            dkim_result = 'FAIL'
        elif 'dkim=none' in auth_results.lower():
            dkim_result = 'NONE'

        if 'dmarc=pass' in auth_results.lower():
            dmarc_result = 'PASS'
        elif 'dmarc=fail' in auth_results.lower():
            dmarc_result = 'FAIL'
        elif 'dmarc=none' in auth_results.lower():
            dmarc_result = 'NONE'

    # Get Received headers (mail path)
    received = headers.get('Received', [])
    if isinstance(received, str):
        received = [received]

    # Get X-Originating-IP if present
    x_originating_ip = headers.get('X-Originating-IP', headers.get('x-originating-ip', 'NOT PRESENT'))

    # Get MS Exchange headers
    x_ms_tenant_id = headers.get('X-MS-Exchange-CrossTenant-id', 'NOT PRESENT')
    x_originatororg = headers.get('X-OriginatorOrg', headers.get('x-originatororg', 'NOT PRESENT'))

    return {
        'from': from_addr,
        'to': to,
        'cc': cc,
        'reply_to': reply_to,
        'return_path': return_path,
        'date': date,
        'subject': subject,
        'message_id': message_id,
        'in_reply_to': in_reply_to,
        'references': references,
        'dkim_domain': dkim_domain,
        'spf': spf_result,
        'dkim': dkim_result,
        'dmarc': dmarc_result,
        'received': received,
        'x_originating_ip': x_originating_ip,
        'x_ms_tenant_id': x_ms_tenant_id,
        'x_originatororg': x_originatororg,
        'auth_results': auth_results,
    }


def print_forensic_summary(headers, email_num):
    """Print concise forensic summary for BEC investigation."""

    from_addr = headers.get('From', 'UNKNOWN')
    reply_to = headers.get('Reply-To', 'NOT PRESENT')
    return_path = headers.get('Return-Path', 'NOT PRESENT')
    date = headers.get('Date', 'UNKNOWN')
    subject = headers.get('Subject', 'UNKNOWN')
    message_id = headers.get('Message-ID', headers.get('Message-Id', 'UNKNOWN'))
    in_reply_to = headers.get('In-Reply-To', 'NOT PRESENT')
    references = headers.get('References', 'NOT PRESENT')

    # Get authentication results
    auth_results = headers.get('Authentication-Results', '')
    if isinstance(auth_results, list):
        auth_results = auth_results[0] if auth_results else ''

    # Get DKIM domain
    dkim_sig = headers.get('DKIM-Signature', '')
    dkim_domain = 'UNKNOWN'
    if dkim_sig:
        if isinstance(dkim_sig, list):
            dkim_sig = dkim_sig[0]
        if 'd=' in dkim_sig:
            dkim_domain = dkim_sig.split('d=')[1].split(';')[0].strip()

    # Determine if suspicious
    suspicious = False
    reasons = []

    # Check for Reply-To poisoning
    if reply_to != 'NOT PRESENT':
        from_domain = from_addr.split('@')[-1].replace('>', '') if '@' in from_addr else ''
        reply_domain = reply_to.split('@')[-1].replace('>', '') if '@' in reply_to else ''
        if from_domain and reply_domain and from_domain.lower() != reply_domain.lower():
            suspicious = True
            reasons.append(f"REPLY-TO MISMATCH: From={from_domain}, Reply-To={reply_domain}")

    # Check for DKIM domain mismatch
    from_domain = from_addr.split('@')[-1].replace('>', '') if '@' in from_addr else ''
    if dkim_domain != 'UNKNOWN' and from_domain:
        # Allow onmicrosoft.com as valid for Microsoft 365
        if from_domain.lower() not in dkim_domain.lower() and 'onmicrosoft.com' not in dkim_domain.lower():
            pass  # Normal case
        elif from_domain.lower() not in dkim_domain.lower():
            # Check if it's a different tenant
            if 'ssdhvac' not in dkim_domain.lower() and 'ssdhvca' in from_domain.lower():
                suspicious = True
                reasons.append(f"DKIM DOMAIN MISMATCH: From={from_domain}, DKIM={dkim_domain}")
            elif 'warehouseathletics' in dkim_domain.lower():
                suspicious = True
                reasons.append(f"FRAUDULENT TENANT: DKIM signed by {dkim_domain}")

    # Check for ssdhvca.com (fraudulent domain)
    if 'ssdhvca.com' in from_addr.lower():
        suspicious = True
        reasons.append("FROM FRAUDULENT DOMAIN: ssdhvca.com (lookalike)")

    print(f"\n{'='*80}")
    print(f"EMAIL #{email_num}")
    print(f"{'='*80}")
    print(f"Date/Time:      {date}")
    print(f"From:           {from_addr}")
    print(f"Subject:        {subject[:60]}..." if len(str(subject)) > 60 else f"Subject:        {subject}")
    print(f"Reply-To:       {reply_to}")
    print(f"Return-Path:    {return_path}")
    print(f"Message-ID:     {message_id}")
    print(f"In-Reply-To:    {in_reply_to}")
    print(f"References:     {references[:80]}..." if len(str(references)) > 80 else f"References:     {references}")
    print(f"DKIM Domain:    {dkim_domain}")
    print(f"")
    print(f"SUSPICIOUS:     {'YES' if suspicious else 'NO'}")
    if reasons:
        for r in reasons:
            print(f"  >>> {r}")

    return {
        'date': date,
        'from': from_addr,
        'reply_to': reply_to,
        'message_id': message_id,
        'in_reply_to': in_reply_to,
        'references': references,
        'dkim_domain': dkim_domain,
        'suspicious': suspicious,
        'reasons': reasons
    }


def main():
    print("="*80)
    print("BEC FORENSIC INVESTIGATION - EMAIL HEADER ANALYSIS")
    print("="*80)
    print(f"\nTarget User: {DELEGATED_USER}")
    print(f"Legitimate Domain: ssdhvac.com")
    print(f"Fraudulent Domain: ssdhvca.com")

    try:
        print("\n[*] Authenticating with service account...")
        service = get_gmail_service()
        print("[+] Authentication successful")

        print("\n[*] Searching for all relevant emails...")
        messages = search_all_relevant_emails(service)

        if not messages:
            print("\n[-] No matching emails found.")
            return

        print(f"\n[+] Found {len(messages)} unique messages to analyze")

        # Collect all email data for detailed analysis
        all_emails = []
        legit_emails = []
        fraud_emails = []

        # Process each message
        for i, msg in enumerate(messages, 1):
            gmail_id = msg['id']

            # Get full message with headers
            full_message = get_full_headers(service, gmail_id)
            headers = extract_headers(full_message)

            # Get detailed forensic data
            email_data = get_full_email_details(headers)
            email_data['gmail_id'] = gmail_id
            email_data['email_num'] = i

            # Categorize
            if 'ssdhvca.com' in str(email_data['from']).lower():
                email_data['category'] = 'FRAUDULENT'
                fraud_emails.append(email_data)
            elif 'ssdhvac.com' in str(email_data['from']).lower():
                email_data['category'] = 'LEGITIMATE'
                legit_emails.append(email_data)
            elif 'askmoss.com' in str(email_data['from']).lower():
                email_data['category'] = 'SENT_BY_VICTIM'
            else:
                email_data['category'] = 'OTHER'

            all_emails.append(email_data)

        # Sort by date
        from datetime import datetime
        import email.utils

        def parse_date(d):
            try:
                parsed = email.utils.parsedate_to_datetime(d)
                return parsed
            except:
                return datetime.min

        all_emails.sort(key=lambda x: parse_date(x['date']))
        legit_emails.sort(key=lambda x: parse_date(x['date']))
        fraud_emails.sort(key=lambda x: parse_date(x['date']))

        # Print detailed analysis
        print("\n" + "="*80)
        print("LEGITIMATE EMAILS FROM ssdhvac.com (Standard Supply)")
        print("="*80)

        for e in legit_emails:
            print(f"\n--- Email from {e['date']} ---")
            print(f"From:        {e['from']}")
            print(f"To:          {e['to']}")
            print(f"Subject:     {e['subject'][:70]}..." if len(str(e['subject'])) > 70 else f"Subject:     {e['subject']}")
            print(f"Reply-To:    {e['reply_to']}")
            print(f"Return-Path: {e['return_path']}")
            print(f"Message-ID:  {e['message_id']}")
            print(f"In-Reply-To: {e['in_reply_to']}")
            print(f"DKIM Domain: {e['dkim_domain']}")
            print(f"SPF/DKIM/DMARC: {e['spf']}/{e['dkim']}/{e['dmarc']}")
            print(f"X-OriginatorOrg: {e['x_originatororg']}")

        print("\n" + "="*80)
        print("FRAUDULENT EMAILS FROM ssdhvca.com (Attacker)")
        print("="*80)

        for e in fraud_emails:
            print(f"\n--- Email from {e['date']} ---")
            print(f"From:        {e['from']}")
            print(f"To:          {e['to']}")
            print(f"Subject:     {e['subject'][:70]}..." if len(str(e['subject'])) > 70 else f"Subject:     {e['subject']}")
            print(f"Reply-To:    {e['reply_to']}")
            print(f"Return-Path: {e['return_path']}")
            print(f"Message-ID:  {e['message_id']}")
            print(f"In-Reply-To: {e['in_reply_to']}")
            print(f"References:  {e['references'][:100]}..." if len(str(e['references'])) > 100 else f"References:  {e['references']}")
            print(f"DKIM Domain: {e['dkim_domain']}")
            print(f"SPF/DKIM/DMARC: {e['spf']}/{e['dkim']}/{e['dmarc']}")
            print(f"X-OriginatorOrg: {e['x_originatororg']}")
            print(f"X-MS-Tenant-ID: {e['x_ms_tenant_id']}")

        # Build Message-ID chain analysis
        print("\n" + "="*80)
        print("MESSAGE-ID CHAIN ANALYSIS")
        print("="*80)

        # Collect all Message-IDs
        all_message_ids = {}
        for e in all_emails:
            mid = e['message_id']
            if mid and mid != 'UNKNOWN':
                all_message_ids[mid] = e

        # Analyze References chains
        print("\nFirst fraudulent email analysis:")
        if fraud_emails:
            first_fraud = fraud_emails[0]
            print(f"\nDate: {first_fraud['date']}")
            print(f"Message-ID: {first_fraud['message_id']}")
            print(f"In-Reply-To: {first_fraud['in_reply_to']}")
            print(f"\nReferences chain:")
            refs = first_fraud['references']
            if refs and refs != 'NOT PRESENT':
                ref_list = refs.replace('\n', ' ').replace('\t', ' ').split()
                ref_list = [r.strip() for r in ref_list if r.strip().startswith('<')]
                for i, ref in enumerate(ref_list):
                    source = "UNKNOWN"
                    if ref in all_message_ids:
                        source = f"Found: {all_message_ids[ref]['from']}"
                    elif 'CAEDQfw' in ref:
                        source = "Gmail (likely Lori Maynard)"
                    elif 'BYAPR13MB2743' in ref:
                        source = "FRAUDULENT (warehouseathletics tenant)"
                    elif 'BLAPR19MB4417' in ref:
                        source = "Standard Supply (ssdhvac.com)"
                    print(f"  [{i+1}] {ref}")
                    print(f"      -> {source}")

        # Summary statistics
        print("\n" + "="*80)
        print("SUMMARY STATISTICS")
        print("="*80)
        print(f"\nTotal emails analyzed: {len(all_emails)}")
        print(f"Legitimate emails (ssdhvac.com): {len(legit_emails)}")
        print(f"Fraudulent emails (ssdhvca.com): {len(fraud_emails)}")

        # Check for Reply-To poisoning
        print("\n" + "-"*40)
        print("REPLY-TO POISONING CHECK:")
        print("-"*40)
        poisoned = [e for e in legit_emails if e['reply_to'] != 'NOT PRESENT']
        if poisoned:
            print("[!] Legitimate emails with Reply-To header:")
            for e in poisoned:
                print(f"  Date: {e['date']}")
                print(f"  From: {e['from']}")
                print(f"  Reply-To: {e['reply_to']}")
                if 'ssdhvca' in str(e['reply_to']).lower():
                    print("  >>> SMOKING GUN: Reply-To points to fraudulent domain!")
        else:
            print("  No Reply-To headers found in legitimate emails")
            print("  CONCLUSION: No Reply-To poisoning attack detected")

        # Return data for report generation
        return {
            'all_emails': all_emails,
            'legit_emails': legit_emails,
            'fraud_emails': fraud_emails,
            'all_message_ids': all_message_ids
        }

    except Exception as e:
        print(f"\n[-] ERROR: {e}")
        import traceback
        traceback.print_exc()
        return None


if __name__ == '__main__':
    main()
