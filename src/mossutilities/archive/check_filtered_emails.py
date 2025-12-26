#!/usr/bin/env python3
"""
Check what emails from christian@ and alamara@ were sent to Vaughn
around the attack window, and delete the suspicious filter.
"""

import os
from datetime import datetime
from dotenv import load_dotenv
import google.auth
from google.auth.transport import requests as auth_requests
from googleapiclient.discovery import build

load_dotenv('/home/robert/Work/_archive/email-forensics/.env.mossutilities')

SERVICE_ACCOUNT_EMAIL = os.getenv('SERVICE_ACCOUNT_EMAIL')
ADMIN_USER = os.getenv('ADMIN_USER')

TARGET_USER = 'vaughn@mossutilities.com'


def get_vaughn_gmail_creds():
    """Get credentials impersonating Vaughn."""
    from google.auth import iam
    from google.oauth2 import service_account

    source_credentials, project = google.auth.default(scopes=['https://www.googleapis.com/auth/cloud-platform'])
    request = auth_requests.Request()

    signer = iam.Signer(
        request=request,
        credentials=source_credentials,
        service_account_email=SERVICE_ACCOUNT_EMAIL
    )

    return service_account.Credentials(
        signer=signer,
        service_account_email=SERVICE_ACCOUNT_EMAIL,
        token_uri='https://oauth2.googleapis.com/token',
        scopes=[
            'https://www.googleapis.com/auth/gmail.settings.basic',
            'https://www.googleapis.com/auth/gmail.readonly',
            'https://www.googleapis.com/auth/gmail.modify',
        ],
        subject=TARGET_USER
    )


def check_emails_from_filtered_senders():
    """Check emails from christian@ and alamara@ around attack window."""
    print("=" * 80)
    print("EMAILS FROM FILTERED SENDERS (Nov 25 - Dec 15)")
    print("=" * 80)

    creds = get_vaughn_gmail_creds()
    gmail = build('gmail', 'v1', credentials=creds)

    # Search for emails from the filtered senders around attack window
    query = "(from:christian@mossutilities.com OR from:alamara@mossutilities.com) after:2025/11/25 before:2025/12/15"

    try:
        results = gmail.users().messages().list(userId='me', q=query, maxResults=50).execute()
        messages = results.get('messages', [])

        print(f"\nFound {len(messages)} emails from christian@ or alamara@\n")

        for msg in messages:
            # Get message details
            msg_data = gmail.users().messages().get(userId='me', id=msg['id'], format='metadata',
                                                     metadataHeaders=['From', 'Subject', 'Date']).execute()

            headers = {h['name']: h['value'] for h in msg_data.get('payload', {}).get('headers', [])}
            labels = msg_data.get('labelIds', [])

            # Check if it was in inbox or archived
            in_inbox = 'INBOX' in labels
            is_read = 'UNREAD' not in labels

            status = ""
            if not in_inbox:
                status = "⚠️ SKIPPED INBOX"
            if not is_read:
                status += " (UNREAD)"

            print(f"  Date: {headers.get('Date', 'Unknown')}")
            print(f"  From: {headers.get('From', 'Unknown')}")
            print(f"  Subject: {headers.get('Subject', 'No subject')}")
            print(f"  Status: {status if status else '✓ Normal'}")
            print()

    except Exception as e:
        print(f"Error searching emails: {e}")


def delete_suspicious_filter():
    """Find and delete the suspicious filter."""
    print("=" * 80)
    print("DELETING SUSPICIOUS FILTER")
    print("=" * 80)

    creds = get_vaughn_gmail_creds()
    gmail = build('gmail', 'v1', credentials=creds)

    try:
        # List all filters
        filters = gmail.users().settings().filters().list(userId='me').execute()

        for f in filters.get('filter', []):
            criteria = f.get('criteria', {})
            action = f.get('action', {})
            filter_id = f.get('id')

            # Check if this is the suspicious filter
            from_criteria = criteria.get('from', '')
            removes_inbox = 'INBOX' in action.get('removeLabelIds', [])

            if 'christian@mossutilities.com' in from_criteria or 'alamara@mossutilities.com' in from_criteria:
                print(f"\nFound suspicious filter:")
                print(f"  Filter ID: {filter_id}")
                print(f"  From: {from_criteria}")
                print(f"  Action: Skip inbox = {removes_inbox}")

                # Delete it
                print(f"\n  Deleting filter {filter_id}...")
                gmail.users().settings().filters().delete(userId='me', id=filter_id).execute()
                print(f"  ✅ Filter deleted successfully!")
                return True

        print("  Filter not found (may have already been deleted)")
        return False

    except Exception as e:
        print(f"Error deleting filter: {e}")
        return False


def verify_filter_deleted():
    """Verify the filter is gone."""
    print("\n" + "=" * 80)
    print("VERIFYING FILTER DELETION")
    print("=" * 80)

    creds = get_vaughn_gmail_creds()
    gmail = build('gmail', 'v1', credentials=creds)

    try:
        filters = gmail.users().settings().filters().list(userId='me').execute()
        filter_list = filters.get('filter', [])

        print(f"\nRemaining filters: {len(filter_list)}")

        for f in filter_list:
            criteria = f.get('criteria', {})
            action = f.get('action', {})
            print(f"  - From: {criteria.get('from', 'N/A')}, Subject: {criteria.get('subject', 'N/A')}")
            print(f"    Actions: {action}")

        if not filter_list:
            print("  ✅ No filters remaining")

    except Exception as e:
        print(f"Error verifying: {e}")


def main():
    check_emails_from_filtered_senders()
    print()
    delete_suspicious_filter()
    verify_filter_deleted()


if __name__ == '__main__':
    main()
