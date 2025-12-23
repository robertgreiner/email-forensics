#!/usr/bin/env python3
"""
List all users in Google Workspace domain.

Usage:
    python list_users.py
"""

import os
from dotenv import load_dotenv
import google.auth
from google.auth import iam
from google.auth.transport import requests as auth_requests
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

load_dotenv()

SERVICE_ACCOUNT_EMAIL = os.getenv('SERVICE_ACCOUNT_EMAIL', 'moss-service-account@hvac-labs.iam.gserviceaccount.com')
ADMIN_USER = os.getenv('ADMIN_USER')

SCOPES = [
    'https://www.googleapis.com/auth/admin.directory.user.readonly',
]


def get_credentials(admin_email: str):
    """Get credentials with domain-wide delegation via ADC impersonation."""
    source_credentials, project = google.auth.default(scopes=['https://www.googleapis.com/auth/cloud-platform'])
    request = auth_requests.Request()

    signer = iam.Signer(
        request=request,
        credentials=source_credentials,
        service_account_email=SERVICE_ACCOUNT_EMAIL
    )

    delegated_credentials = service_account.Credentials(
        signer=signer,
        service_account_email=SERVICE_ACCOUNT_EMAIL,
        token_uri='https://oauth2.googleapis.com/token',
        scopes=SCOPES,
        subject=admin_email
    )

    return delegated_credentials


def list_users():
    """List all users in the domain."""
    credentials = get_credentials(ADMIN_USER)
    service = build('admin', 'directory_v1', credentials=credentials)

    users = []
    page_token = None

    while True:
        try:
            results = service.users().list(
                customer='my_customer',
                maxResults=500,
                pageToken=page_token,
                orderBy='email'
            ).execute()

            users.extend(results.get('users', []))
            page_token = results.get('nextPageToken')

            if not page_token:
                break

        except HttpError as e:
            print(f"Error: {e}")
            break

    return users


def main():
    print("Fetching all users from Google Workspace...\n")

    users = list_users()

    print(f"{'Email':<45} {'Name':<30} {'Suspended':<10} {'2SV':<10}")
    print("-" * 95)

    for user in users:
        email = user.get('primaryEmail', 'Unknown')
        name = user.get('name', {}).get('fullName', 'Unknown')
        suspended = 'Yes' if user.get('suspended', False) else 'No'
        enrolled_2sv = 'Yes' if user.get('isEnrolledIn2Sv', False) else 'No'

        print(f"{email:<45} {name:<30} {suspended:<10} {enrolled_2sv:<10}")

    print(f"\nTotal users: {len(users)}")

    # Summary
    active_users = [u for u in users if not u.get('suspended', False)]
    users_with_2sv = [u for u in active_users if u.get('isEnrolledIn2Sv', False)]
    users_without_2sv = [u for u in active_users if not u.get('isEnrolledIn2Sv', False)]

    print(f"\nActive users: {len(active_users)}")
    print(f"With 2FA: {len(users_with_2sv)}")
    print(f"WITHOUT 2FA: {len(users_without_2sv)}")

    if users_without_2sv:
        print("\n*** USERS WITHOUT 2FA ***")
        for u in users_without_2sv:
            print(f"  - {u.get('primaryEmail')}")

    return users


if __name__ == '__main__':
    main()
