#!/usr/bin/env python3
"""
Check Gmail settings for compromise indicators.

Inspects:
- Email forwarding rules
- Email filters (auto-delete, forward, label rules)
- Delegates (who has access to the mailbox)
- SendAs addresses
- Auto-reply settings

Usage:
    # First, set up impersonation:
    gcloud auth application-default login --impersonate-service-account=SERVICE_ACCOUNT_EMAIL

    # Then run:
    python check_gmail_settings.py --user lori.maynard@domain.com
    python check_gmail_settings.py  # Uses DELEGATED_USER from .env
"""

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv
import google.auth
from google.auth import iam
from google.auth.transport import requests as auth_requests
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# Load environment
load_dotenv()

SERVICE_ACCOUNT_EMAIL = os.getenv('SERVICE_ACCOUNT_EMAIL', 'moss-service-account@hvac-labs.iam.gserviceaccount.com')
DEFAULT_USER = os.getenv('DELEGATED_USER')

# Scopes for Gmail settings
SCOPES = [
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/gmail.settings.basic',
]


def get_credentials(user_email: str):
    """Get credentials with domain-wide delegation via ADC impersonation."""
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
        subject=user_email
    )

    return delegated_credentials


def check_forwarding(service, user_email: str) -> dict:
    """Check auto-forwarding settings."""
    print(f"\n{'='*80}")
    print("EMAIL FORWARDING SETTINGS")
    print('='*80)

    result = {'enabled': False, 'address': None, 'disposition': None}

    try:
        settings = service.users().settings().getAutoForwarding(userId='me').execute()

        enabled = settings.get('enabled', False)
        forward_to = settings.get('emailAddress', '')
        disposition = settings.get('disposition', '')

        result = {
            'enabled': enabled,
            'address': forward_to,
            'disposition': disposition
        }

        if enabled:
            print(f"\n*** WARNING: AUTO-FORWARDING IS ENABLED ***")
            print(f"    Forwarding to: {forward_to}")
            print(f"    Disposition:   {disposition}")
            print("\n    This is a common persistence mechanism for attackers!")
        else:
            print("\n[OK] Auto-forwarding is NOT enabled")

    except HttpError as e:
        print(f"Error checking forwarding: {e}")

    return result


def check_filters(service, user_email: str) -> list:
    """Check email filters for suspicious rules."""
    print(f"\n{'='*80}")
    print("EMAIL FILTERS")
    print('='*80)

    filters = []
    suspicious = []

    try:
        result = service.users().settings().filters().list(userId='me').execute()
        filters = result.get('filter', [])

        if not filters:
            print("\n[OK] No email filters configured")
            return filters

        print(f"\nFound {len(filters)} filters:\n")

        for f in filters:
            filter_id = f.get('id', 'unknown')
            criteria = f.get('criteria', {})
            action = f.get('action', {})

            # Check for suspicious patterns
            is_suspicious = False
            reasons = []

            # Forward action
            if action.get('forward'):
                is_suspicious = True
                reasons.append(f"FORWARDS TO: {action['forward']}")

            # Delete/trash action
            if action.get('removeLabelIds') and 'INBOX' in action.get('removeLabelIds', []):
                if not action.get('addLabelIds'):
                    is_suspicious = True
                    reasons.append("SKIPS INBOX (hides emails)")

            if action.get('addLabelIds') and 'TRASH' in action.get('addLabelIds', []):
                is_suspicious = True
                reasons.append("MOVES TO TRASH")

            # Mark as read (hiding)
            if action.get('removeLabelIds') and 'UNREAD' in action.get('removeLabelIds', []):
                reasons.append("Marks as read automatically")

            # Build criteria description
            criteria_parts = []
            if criteria.get('from'):
                criteria_parts.append(f"From: {criteria['from']}")
            if criteria.get('to'):
                criteria_parts.append(f"To: {criteria['to']}")
            if criteria.get('subject'):
                criteria_parts.append(f"Subject: {criteria['subject']}")
            if criteria.get('query'):
                criteria_parts.append(f"Query: {criteria['query']}")
            if criteria.get('hasAttachment'):
                criteria_parts.append("Has attachment")

            criteria_str = ' AND '.join(criteria_parts) if criteria_parts else 'All emails'

            # Build action description
            action_parts = []
            if action.get('addLabelIds'):
                action_parts.append(f"Add labels: {action['addLabelIds']}")
            if action.get('removeLabelIds'):
                action_parts.append(f"Remove labels: {action['removeLabelIds']}")
            if action.get('forward'):
                action_parts.append(f"Forward to: {action['forward']}")

            action_str = ', '.join(action_parts) if action_parts else 'No action'

            if is_suspicious:
                suspicious.append(f)
                print(f"*** SUSPICIOUS FILTER ***")
                print(f"    ID: {filter_id}")
                print(f"    Criteria: {criteria_str}")
                print(f"    Action: {action_str}")
                for r in reasons:
                    print(f"    >>> {r}")
                print()
            else:
                print(f"  [{filter_id}] {criteria_str}")
                print(f"    -> {action_str}")
                if reasons:
                    for r in reasons:
                        print(f"       Note: {r}")
                print()

        if suspicious:
            print(f"\n*** {len(suspicious)} SUSPICIOUS FILTERS FOUND ***")

    except HttpError as e:
        print(f"Error checking filters: {e}")

    return filters


def check_delegates(service, user_email: str) -> list:
    """Check who has delegate access to the mailbox."""
    print(f"\n{'='*80}")
    print("MAILBOX DELEGATES")
    print('='*80)

    delegates = []

    try:
        result = service.users().settings().delegates().list(userId='me').execute()
        delegates = result.get('delegates', [])

        if not delegates:
            print("\n[OK] No delegates configured (no one else has mailbox access)")
            return delegates

        print(f"\n*** {len(delegates)} DELEGATES HAVE ACCESS TO THIS MAILBOX ***\n")

        for d in delegates:
            delegate_email = d.get('delegateEmail', 'unknown')
            status = d.get('verificationStatus', 'unknown')
            print(f"  - {delegate_email}")
            print(f"    Status: {status}")
            print()

        print("NOTE: Verify each delegate is legitimate and expected!")

    except HttpError as e:
        if '403' in str(e):
            print("\n[INFO] Cannot check delegates (may require additional permissions)")
        else:
            print(f"Error checking delegates: {e}")

    return delegates


def check_send_as(service, user_email: str) -> list:
    """Check SendAs addresses (who can send as this user)."""
    print(f"\n{'='*80}")
    print("SEND-AS ADDRESSES")
    print('='*80)

    send_as = []

    try:
        result = service.users().settings().sendAs().list(userId='me').execute()
        send_as = result.get('sendAs', [])

        print(f"\nConfigured send-as addresses:\n")

        for s in send_as:
            email = s.get('sendAsEmail', 'unknown')
            display_name = s.get('displayName', '')
            is_primary = s.get('isPrimary', False)
            is_default = s.get('isDefault', False)
            verification = s.get('verificationStatus', 'unknown')
            reply_to = s.get('replyToAddress', '')

            status = []
            if is_primary:
                status.append('PRIMARY')
            if is_default:
                status.append('DEFAULT')

            status_str = f" [{', '.join(status)}]" if status else ""

            print(f"  - {email}{status_str}")
            if display_name:
                print(f"    Display name: {display_name}")
            if reply_to and reply_to != email:
                print(f"    *** Reply-To: {reply_to} (DIFFERENT FROM SEND ADDRESS)")
            print(f"    Verified: {verification}")
            print()

        # Flag non-primary verified addresses
        non_primary = [s for s in send_as if not s.get('isPrimary') and s.get('verificationStatus') == 'accepted']
        if non_primary:
            print(f"*** NOTE: {len(non_primary)} additional verified send-as addresses ***")
            print("   Review these to ensure they're legitimate.")

    except HttpError as e:
        print(f"Error checking send-as: {e}")

    return send_as


def check_vacation_responder(service, user_email: str) -> dict:
    """Check vacation/auto-reply settings."""
    print(f"\n{'='*80}")
    print("VACATION AUTO-RESPONDER")
    print('='*80)

    vacation = {}

    try:
        result = service.users().settings().getVacation(userId='me').execute()

        enabled = result.get('enableAutoReply', False)
        subject = result.get('responseSubject', '')
        body = result.get('responseBodyPlainText', '')[:200]

        vacation = {
            'enabled': enabled,
            'subject': subject,
            'body_preview': body
        }

        if enabled:
            print(f"\n[INFO] Vacation auto-responder is ON")
            print(f"    Subject: {subject}")
            print(f"    Body preview: {body}...")
            print("\n    (May be legitimate, but verify it wasn't set maliciously)")
        else:
            print("\n[OK] Vacation auto-responder is OFF")

    except HttpError as e:
        print(f"Error checking vacation settings: {e}")

    return vacation


def check_imap_pop(service, user_email: str) -> dict:
    """Check IMAP/POP settings."""
    print(f"\n{'='*80}")
    print("IMAP/POP ACCESS SETTINGS")
    print('='*80)

    settings = {}

    try:
        imap = service.users().settings().getImap(userId='me').execute()
        pop = service.users().settings().getPop(userId='me').execute()

        settings = {
            'imap_enabled': imap.get('enabled', False),
            'pop_enabled': pop.get('accessWindow') != 'disabled'
        }

        if imap.get('enabled'):
            print(f"\n[INFO] IMAP is ENABLED")
            print("    External email clients can sync this mailbox")
        else:
            print("\n[OK] IMAP is disabled")

        if pop.get('accessWindow') != 'disabled':
            print(f"\n[INFO] POP is ENABLED")
            print(f"    Access window: {pop.get('accessWindow')}")
            print(f"    Disposition: {pop.get('disposition')}")
            print("    External clients can download mail via POP")
        else:
            print("\n[OK] POP is disabled")

    except HttpError as e:
        print(f"Error checking IMAP/POP: {e}")

    return settings


def save_results(results: dict, user_email: str):
    """Save results to JSON."""
    output_dir = Path('output')
    output_dir.mkdir(exist_ok=True)

    username = user_email.split('@')[0]
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filepath = output_dir / f"{username}_gmail_settings_{timestamp}.json"

    with open(filepath, 'w') as f:
        json.dump(results, f, indent=2, default=str)

    print(f"\n[+] Results saved to {filepath}")


def main():
    parser = argparse.ArgumentParser(description='Check Gmail settings for compromise indicators')
    parser.add_argument('--user', '-u', help='User email to check (or set DELEGATED_USER in .env)')

    args = parser.parse_args()

    user_email = args.user or DEFAULT_USER
    if not user_email:
        print("ERROR: Must specify user via --user or DELEGATED_USER env var")
        sys.exit(1)

    print(f"Checking Gmail settings for: {user_email}")
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Build service
    try:
        credentials = get_credentials(user_email)
        service = build('gmail', 'v1', credentials=credentials)
    except Exception as e:
        print(f"ERROR: Failed to authenticate: {e}")
        print("\nMake sure you have:")
        print("1. Service account key file in place")
        print("2. Domain-wide delegation configured with scopes:")
        print("   - https://www.googleapis.com/auth/gmail.readonly")
        print("   - https://www.googleapis.com/auth/gmail.settings.basic")
        sys.exit(1)

    results = {
        'user': user_email,
        'checked_at': datetime.now().isoformat(),
        'forwarding': {},
        'filters': [],
        'delegates': [],
        'send_as': [],
        'vacation': {},
        'imap_pop': {}
    }

    # Run all checks
    results['forwarding'] = check_forwarding(service, user_email)
    results['filters'] = check_filters(service, user_email)
    results['delegates'] = check_delegates(service, user_email)
    results['send_as'] = check_send_as(service, user_email)
    results['vacation'] = check_vacation_responder(service, user_email)
    results['imap_pop'] = check_imap_pop(service, user_email)

    # Summary
    print("\n" + "="*80)
    print("SUMMARY")
    print("="*80)

    issues = []

    if results['forwarding'].get('enabled'):
        issues.append("Auto-forwarding is ENABLED")

    suspicious_filters = [f for f in results['filters']
                        if f.get('action', {}).get('forward')
                        or ('INBOX' in f.get('action', {}).get('removeLabelIds', [])
                            and not f.get('action', {}).get('addLabelIds'))
                        or 'TRASH' in f.get('action', {}).get('addLabelIds', [])]
    if suspicious_filters:
        issues.append(f"{len(suspicious_filters)} suspicious email filters")

    if results['delegates']:
        issues.append(f"{len(results['delegates'])} delegates have mailbox access")

    if issues:
        print("\n*** ISSUES REQUIRING REVIEW ***")
        for issue in issues:
            print(f"  - {issue}")
    else:
        print("\n[OK] No obvious compromise indicators found in Gmail settings")

    save_results(results, user_email)


if __name__ == '__main__':
    main()
