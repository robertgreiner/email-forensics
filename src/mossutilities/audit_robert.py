#!/usr/bin/env python3
"""
Quick audit of robert@mossutilities.com logins.
Check the datacenter IP login.
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


def get_credentials():
    from google.auth import iam
    from google.oauth2 import service_account

    SCOPES = ['https://www.googleapis.com/auth/admin.reports.audit.readonly']

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
        scopes=SCOPES,
        subject=ADMIN_USER
    )


def main():
    credentials = get_credentials()
    service = build('admin', 'reports_v1', credentials=credentials)

    end_time = datetime.utcnow()
    start_time = end_time - timedelta(days=30)

    results = service.activities().list(
        userKey='robert@mossutilities.com',
        applicationName='login',
        startTime=start_time.strftime('%Y-%m-%dT%H:%M:%SZ'),
        endTime=end_time.strftime('%Y-%m-%dT%H:%M:%SZ'),
        maxResults=500
    ).execute()

    events = results.get('items', [])

    print("=" * 80)
    print("ROBERT@MOSSUTILITIES.COM LOGIN AUDIT")
    print("=" * 80)

    for event in sorted(events, key=lambda x: x.get('id', {}).get('time', '')):
        ip = event.get('ipAddress', 'Unknown')
        timestamp = event.get('id', {}).get('time', '')[:19]
        event_name = event.get('events', [{}])[0].get('name', 'unknown')

        # Flag datacenter IPs
        flag = ""
        if ip.startswith('142.111.'):
            flag = "⚠️ ACE DATACENTER"
        elif ip.startswith('138.199.114.'):
            flag = "Office"
        elif ip.startswith('2600:') or ip.startswith('172.'):
            flag = "Mobile"

        print(f"  [{timestamp}] {event_name} from {ip} {flag}")


if __name__ == '__main__':
    main()
