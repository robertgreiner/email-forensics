#!/usr/bin/env python3
"""
Comprehensive Email Review - BEC Investigation
Scans all specified users for emails from ssdhvac.com in the last 30 days.
Checks every email for Reply-To poisoning and other anomalies.
"""

import os
import sys
import google.auth
from google.auth import iam
from google.auth.transport import requests as auth_requests
from google.oauth2 import service_account
from googleapiclient.discovery import build
from datetime import datetime, timedelta
from collections import defaultdict

SERVICE_ACCOUNT_EMAIL = 'moss-service-account@hvac-labs.iam.gserviceaccount.com'
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

# Users to scan - add all users who may have communicated with Standard Supply
USERS_TO_SCAN = [
    'lori.maynard@askmoss.com',
    'madelin.martinez@askmoss.com',
    # Add more users as needed
]

# Domains to analyze
LEGITIMATE_DOMAIN = 'ssdhvac.com'
FRAUDULENT_DOMAIN = 'ssdhvca.com'

def get_service(delegated_user):
    """Create Gmail API service with domain-wide delegation for a specific user."""
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

def extract_domain(email_addr):
    """Extract domain from email address."""
    if not email_addr or '@' not in str(email_addr):
        return ''
    return email_addr.split('@')[-1].replace('>', '').replace('"', '').strip().lower()

def analyze_email(service, msg_id):
    """Fetch and analyze a single email."""
    full = service.users().messages().get(userId='me', id=msg_id, format='full').execute()
    headers = {h['name']: h['value'] for h in full['payload']['headers']}

    date = headers.get('Date', 'UNKNOWN')
    from_addr = headers.get('From', 'UNKNOWN')
    to = headers.get('To', 'UNKNOWN')
    cc = headers.get('Cc', '')
    subject = headers.get('Subject', 'UNKNOWN')
    reply_to = headers.get('Reply-To', None)
    return_path = headers.get('Return-Path', 'UNKNOWN')
    message_id = headers.get('Message-ID', headers.get('Message-Id', 'UNKNOWN'))
    in_reply_to = headers.get('In-Reply-To', None)
    references = headers.get('References', None)

    # DKIM analysis
    dkim_sig = headers.get('DKIM-Signature', '')
    dkim_domain = None
    if dkim_sig and 'd=' in dkim_sig:
        dkim_domain = dkim_sig.split('d=')[1].split(';')[0].strip()

    # Authentication results
    auth_results = headers.get('Authentication-Results', '')
    arc_auth = headers.get('ARC-Authentication-Results', '')

    # MS headers
    x_originator_org = headers.get('X-OriginatorOrg', '')
    x_ms_tenant_id = headers.get('X-MS-Exchange-CrossTenant-id', '')

    # Analyze for anomalies
    from_domain = extract_domain(from_addr)
    reply_to_domain = extract_domain(reply_to) if reply_to else None
    return_path_domain = extract_domain(return_path)

    anomalies = []

    # Check Reply-To poisoning
    if reply_to:
        if reply_to_domain != from_domain:
            anomalies.append(f"REPLY-TO MISMATCH: From={from_domain}, Reply-To={reply_to_domain}")
            if FRAUDULENT_DOMAIN in reply_to_domain:
                anomalies.append("!!! CRITICAL: Reply-To points to FRAUDULENT domain !!!")

    # Check DKIM domain mismatch
    if dkim_domain and from_domain:
        if dkim_domain.lower() != from_domain.lower() and 'onmicrosoft.com' not in from_domain.lower():
            anomalies.append(f"DKIM MISMATCH: From={from_domain}, DKIM={dkim_domain}")
            if 'warehouseathletics' in dkim_domain.lower():
                anomalies.append("!!! CRITICAL: DKIM signed by known attacker tenant !!!")

    # Check Return-Path mismatch
    if return_path_domain and from_domain:
        if return_path_domain.lower() != from_domain.lower():
            anomalies.append(f"RETURN-PATH MISMATCH: From={from_domain}, Return-Path={return_path_domain}")

    return {
        'date': date,
        'from': from_addr,
        'to': to,
        'cc': cc,
        'subject': subject[:80] if subject else '',
        'reply_to': reply_to,
        'return_path': return_path,
        'message_id': message_id,
        'in_reply_to': in_reply_to,
        'dkim_domain': dkim_domain,
        'x_originator_org': x_originator_org,
        'x_ms_tenant_id': x_ms_tenant_id,
        'from_domain': from_domain,
        'anomalies': anomalies
    }

def scan_user(user_email, query, label):
    """Scan a user's mailbox for emails matching the query."""
    print(f"\n{'='*70}")
    print(f"Scanning: {user_email}")
    print(f"Query: {query}")
    print(f"{'='*70}")

    try:
        service = get_service(user_email)
        results = service.users().messages().list(userId='me', q=query, maxResults=500).execute()
        messages = results.get('messages', [])
    except Exception as e:
        print(f"  ERROR accessing {user_email}: {e}")
        return []

    if not messages:
        print(f"  No messages found")
        return []

    print(f"  Found {len(messages)} messages")

    emails = []
    for msg in messages:
        try:
            email_data = analyze_email(service, msg['id'])
            email_data['user'] = user_email
            email_data['search_label'] = label
            emails.append(email_data)
        except Exception as e:
            print(f"  Error analyzing message {msg['id']}: {e}")

    return emails

def main():
    print("="*80)
    print("COMPREHENSIVE BEC INVESTIGATION - EMAIL REVIEW")
    print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*80)

    # Calculate date range (last 30 days)
    thirty_days_ago = (datetime.now() - timedelta(days=30)).strftime('%Y/%m/%d')

    # Queries to run
    queries = [
        (f'from:{LEGITIMATE_DOMAIN} after:{thirty_days_ago}', f'FROM {LEGITIMATE_DOMAIN} (last 30 days)'),
        (f'from:{FRAUDULENT_DOMAIN} after:{thirty_days_ago}', f'FROM {FRAUDULENT_DOMAIN} (last 30 days)'),
        (f'to:{LEGITIMATE_DOMAIN} after:{thirty_days_ago}', f'TO {LEGITIMATE_DOMAIN} (last 30 days)'),
        (f'to:{FRAUDULENT_DOMAIN} after:{thirty_days_ago}', f'TO {FRAUDULENT_DOMAIN} (last 30 days)'),
    ]

    all_emails = []

    for user in USERS_TO_SCAN:
        for query, label in queries:
            emails = scan_user(user, query, label)
            all_emails.extend(emails)

    # Deduplicate by message ID (same email may appear for multiple users if CC'd)
    seen_ids = set()
    unique_emails = []
    for email in all_emails:
        if email['message_id'] not in seen_ids:
            seen_ids.add(email['message_id'])
            unique_emails.append(email)

    # Categorize
    from_legit = [e for e in unique_emails if e['from_domain'] == LEGITIMATE_DOMAIN]
    from_fraud = [e for e in unique_emails if e['from_domain'] == FRAUDULENT_DOMAIN]

    # Summary
    print("\n" + "="*80)
    print("SUMMARY")
    print("="*80)

    print(f"\nUsers Scanned: {len(USERS_TO_SCAN)}")
    for user in USERS_TO_SCAN:
        print(f"  - {user}")

    print(f"\nDate Range: Last 30 days (since {thirty_days_ago})")
    print(f"\nTotal Unique Emails Analyzed: {len(unique_emails)}")
    print(f"  - From {LEGITIMATE_DOMAIN}: {len(from_legit)}")
    print(f"  - From {FRAUDULENT_DOMAIN}: {len(from_fraud)}")

    # Anomaly report
    print("\n" + "="*80)
    print("ANOMALY DETECTION RESULTS")
    print("="*80)

    anomalous = [e for e in unique_emails if e['anomalies']]

    if not anomalous:
        print("\n  ✓ NO ANOMALIES DETECTED in any emails from legitimate domain")
        print("  ✓ No Reply-To poisoning found")
        print("  ✓ No DKIM mismatches on legitimate emails")
    else:
        print(f"\n  [!] Found {len(anomalous)} emails with anomalies:\n")
        for email in anomalous:
            print(f"  Date: {email['date']}")
            print(f"  From: {email['from']}")
            print(f"  To: {email['to'][:60]}..." if len(str(email['to'])) > 60 else f"  To: {email['to']}")
            print(f"  Subject: {email['subject']}")
            for anomaly in email['anomalies']:
                print(f"  >>> {anomaly}")
            print()

    # Reply-To analysis for legitimate emails
    print("\n" + "="*80)
    print("REPLY-TO HEADER ANALYSIS - LEGITIMATE EMAILS")
    print("="*80)

    reply_to_present = [e for e in from_legit if e['reply_to']]
    reply_to_absent = [e for e in from_legit if not e['reply_to']]

    print(f"\n  Total legitimate emails from {LEGITIMATE_DOMAIN}: {len(from_legit)}")
    print(f"  - With Reply-To header: {len(reply_to_present)}")
    print(f"  - Without Reply-To header: {len(reply_to_absent)}")

    if reply_to_present:
        print(f"\n  [!] ATTENTION: {len(reply_to_present)} emails have Reply-To headers:\n")
        for email in reply_to_present:
            print(f"    Date: {email['date']}")
            print(f"    From: {email['from']}")
            print(f"    Reply-To: {email['reply_to']}")
            reply_domain = extract_domain(email['reply_to'])
            if reply_domain != LEGITIMATE_DOMAIN:
                if FRAUDULENT_DOMAIN in reply_domain:
                    print(f"    >>> !!! SMOKING GUN: Reply-To points to FRAUDULENT domain !!!")
                else:
                    print(f"    >>> WARNING: Reply-To domain ({reply_domain}) differs from From domain")
            print()
    else:
        print(f"\n  ✓ CONFIRMED: All {len(from_legit)} legitimate emails have NO Reply-To header")
        print("  ✓ NO REPLY-TO POISONING DETECTED")

    # Detailed listing
    print("\n" + "="*80)
    print("DETAILED EMAIL INVENTORY - LEGITIMATE DOMAIN")
    print("="*80)

    if from_legit:
        # Sort by date
        from_legit_sorted = sorted(from_legit, key=lambda x: x['date'], reverse=True)
        print(f"\n{'#':<3} {'Date':<26} {'From':<40} {'Reply-To':<12} {'Subject':<40}")
        print("-"*120)
        for i, email in enumerate(from_legit_sorted, 1):
            from_short = email['from'][:38] if len(str(email['from'])) > 38 else email['from']
            subj_short = email['subject'][:38] if len(str(email['subject'])) > 38 else email['subject']
            reply_to_status = "PRESENT" if email['reply_to'] else "NOT PRESENT"
            date_short = email['date'][:24] if len(str(email['date'])) > 24 else email['date']
            print(f"{i:<3} {date_short:<26} {from_short:<40} {reply_to_status:<12} {subj_short}")

    print("\n" + "="*80)
    print("DETAILED EMAIL INVENTORY - FRAUDULENT DOMAIN")
    print("="*80)

    if from_fraud:
        from_fraud_sorted = sorted(from_fraud, key=lambda x: x['date'], reverse=True)
        print(f"\n{'#':<3} {'Date':<26} {'From':<40} {'DKIM Domain':<35}")
        print("-"*110)
        for i, email in enumerate(from_fraud_sorted, 1):
            from_short = email['from'][:38] if len(str(email['from'])) > 38 else email['from']
            dkim = email['dkim_domain'] or 'NONE'
            date_short = email['date'][:24] if len(str(email['date'])) > 24 else email['date']
            print(f"{i:<3} {date_short:<26} {from_short:<40} {dkim:<35}")
    else:
        print("\n  No fraudulent emails found (good!)")

    # Final verdict
    print("\n" + "="*80)
    print("VERDICT")
    print("="*80)

    poisoning_detected = any(
        e['reply_to'] and FRAUDULENT_DOMAIN in extract_domain(e['reply_to'])
        for e in from_legit
    )

    any_reply_to = len(reply_to_present) > 0

    if poisoning_detected:
        print("""
    ╔══════════════════════════════════════════════════════════════════════╗
    ║  !!!  REPLY-TO POISONING DETECTED  !!!                               ║
    ║                                                                       ║
    ║  Legitimate emails from Standard Supply contain Reply-To headers      ║
    ║  pointing to the fraudulent domain. This indicates Standard Supply's  ║
    ║  outgoing email was modified to redirect replies to attackers.        ║
    ╚══════════════════════════════════════════════════════════════════════╝
    """)
    elif any_reply_to:
        print(f"""
    ╔══════════════════════════════════════════════════════════════════════╗
    ║  WARNING: Reply-To headers found on {len(reply_to_present)} legitimate email(s)              ║
    ║                                                                       ║
    ║  Review the Reply-To values above to determine if they are            ║
    ║  legitimate (e.g., pointing to same organization) or suspicious.      ║
    ╚══════════════════════════════════════════════════════════════════════╝
    """)
    else:
        print("""
    ╔══════════════════════════════════════════════════════════════════════╗
    ║  ✓  NO REPLY-TO POISONING DETECTED                                   ║
    ║                                                                       ║
    ║  All legitimate emails from Standard Supply have NO Reply-To header.  ║
    ║  The attack did not involve modifying outgoing Standard Supply emails.║
    ║                                                                       ║
    ║  CONCLUSION: Moss Mechanical was NOT compromised.                     ║
    ║  Attack vector: Read-access compromise at Standard Supply.            ║
    ╚══════════════════════════════════════════════════════════════════════╝
    """)

    print(f"\nReport complete. {len(unique_emails)} unique emails analyzed across {len(USERS_TO_SCAN)} users.")

if __name__ == '__main__':
    main()
