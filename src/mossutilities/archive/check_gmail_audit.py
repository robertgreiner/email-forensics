#!/usr/bin/env python3
"""
Check Gmail audit logs for Vaughn around the attack window.
This uses the Admin Reports API which we have access to.
"""

import os
from datetime import datetime, timedelta
from dotenv import load_dotenv
import google.auth
from google.auth.transport import requests as auth_requests
from googleapiclient.discovery import build

load_dotenv('/home/robert/Work/_archive/email-forensics/.env.mossutilities')

SERVICE_ACCOUNT_EMAIL = os.getenv('SERVICE_ACCOUNT_EMAIL')
ADMIN_USER = os.getenv('ADMIN_USER')

TARGET_USER = 'vaughn@mossutilities.com'

ATTACKER_IPS = {'45.159.127.16', '156.229.254.40', '45.192.39.3', '38.69.8.106', '142.111.254.241'}


def get_credentials():
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
        scopes=['https://www.googleapis.com/auth/admin.reports.audit.readonly'],
        subject=ADMIN_USER
    )


def main():
    print("=" * 80)
    print("GMAIL AUDIT LOGS - VAUGHN (Dec 2-10)")
    print("=" * 80)

    credentials = get_credentials()
    service = build('admin', 'reports_v1', credentials=credentials)

    start_date = datetime(2025, 12, 2, 0, 0, 0)
    end_date = datetime(2025, 12, 10, 23, 59, 59)

    try:
        results = service.activities().list(
            userKey=TARGET_USER,
            applicationName='gmail',
            startTime=start_date.strftime('%Y-%m-%dT%H:%M:%SZ'),
            endTime=end_date.strftime('%Y-%m-%dT%H:%M:%SZ'),
            maxResults=500
        ).execute()

        events = results.get('items', [])
        print(f"\nFound {len(events)} Gmail events\n")

        # Sort by time
        events.sort(key=lambda x: x.get('id', {}).get('time', ''))

        for event in events:
            ip = event.get('ipAddress', 'Unknown')
            timestamp = event.get('id', {}).get('time', '')[:19]

            flag = "🚨 ATTACKER" if ip in ATTACKER_IPS else ""

            for evt in event.get('events', []):
                event_name = evt.get('name', 'unknown')
                params = {}
                for param in evt.get('parameters', []):
                    name = param.get('name')
                    value = param.get('value') or param.get('intValue') or param.get('boolValue')
                    if value:
                        params[name] = value

                print(f"[{timestamp}] {event_name} from {ip} {flag}")
                if params:
                    for k, v in params.items():
                        # Truncate long values
                        v_str = str(v)[:100] + "..." if len(str(v)) > 100 else str(v)
                        print(f"    {k}: {v_str}")
                print()

    except Exception as e:
        print(f"Error: {e}")
        print("\nNote: Gmail audit logs may not be available for all Workspace editions.")
        print("The Gmail application in Admin Reports requires Enterprise or higher.")


if __name__ == '__main__':
    main()
