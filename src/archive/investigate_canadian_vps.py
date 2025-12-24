#!/usr/bin/env python3
"""
Deep investigation of the Canadian VPS IP (158.51.123.14) activity.
"""

import os
import csv
from dotenv import load_dotenv
import google.auth
from google.auth import iam
from google.auth.transport import requests as auth_requests
from google.oauth2 import service_account
from googleapiclient.discovery import build

load_dotenv()

SERVICE_ACCOUNT_EMAIL = os.getenv('SERVICE_ACCOUNT_EMAIL')
ADMIN_USER = os.getenv('ADMIN_USER')
TARGET_USER = 'lori.maynard@askmoss.com'
SUSPICIOUS_IP = '158.51.123.14'


def get_credentials(admin_email, scopes):
    source_credentials, project = google.auth.default(scopes=['https://www.googleapis.com/auth/cloud-platform'])
    request = auth_requests.Request()
    signer = iam.Signer(request=request, credentials=source_credentials, service_account_email=SERVICE_ACCOUNT_EMAIL)
    return service_account.Credentials(
        signer=signer, service_account_email=SERVICE_ACCOUNT_EMAIL,
        token_uri='https://oauth2.googleapis.com/token', scopes=scopes, subject=admin_email
    )


def main():
    print(f"Deep investigation of IP: {SUSPICIOUS_IP}")
    print("=" * 70)

    # Get full details from admin log
    print("\n1. Full Admin Email Log entries for this IP:")
    print("-" * 70)

    with open('/home/robert/Downloads/lori-send.csv', 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get('IP address') == SUSPICIOUS_IP:
                print(f"\nDate: {row.get('Date')}")
                print(f"Message-ID: {row.get('Message ID')}")
                print(f"Subject: {row.get('Subject')}")
                print(f"From (Header): {row.get('From (Header address)')}")
                print(f"From (Envelope): {row.get('From (Envelope)')}")
                print(f"To (Envelope): {row.get('To (Envelope)')}")
                print(f"Traffic source: {row.get('Traffic source')}")
                print(f"SPF domain: {row.get('SPF domain')}")
                print(f"DKIM domain: {row.get('DKIM domain')}")
                print(f"Client Type: {row.get('Client Type')}")

    # Check login audit logs for this IP
    print("\n\n2. Login events from this IP:")
    print("-" * 70)

    creds = get_credentials(ADMIN_USER, ['https://www.googleapis.com/auth/admin.reports.audit.readonly'])
    service = build('admin', 'reports_v1', credentials=creds)

    # Search login events
    results = service.activities().list(
        userKey=TARGET_USER,
        applicationName='login',
        maxResults=500
    ).execute()

    found_login = False
    for event in results.get('items', []):
        ip = event.get('ipAddress', '')
        if ip == SUSPICIOUS_IP:
            found_login = True
            print(f"\nTime: {event.get('id', {}).get('time')}")
            for e in event.get('events', []):
                print(f"  Event: {e.get('name')}")
                for p in e.get('parameters', []):
                    print(f"    {p.get('name')}: {p.get('value')}")

    if not found_login:
        print("  No login events found from this IP!")

    # Check token/OAuth events for this IP
    print("\n\n3. OAuth/Token events from this IP:")
    print("-" * 70)

    results = service.activities().list(
        userKey=TARGET_USER,
        applicationName='token',
        maxResults=500
    ).execute()

    found_token = False
    for event in results.get('items', []):
        ip = event.get('ipAddress', '')
        if ip == SUSPICIOUS_IP:
            found_token = True
            print(f"\nTime: {event.get('id', {}).get('time')}")
            for e in event.get('events', []):
                print(f"  Event: {e.get('name')}")
                for p in e.get('parameters', []):
                    print(f"    {p.get('name')}: {p.get('value')}")

    if not found_token:
        print("  No OAuth/token events found from this IP!")

    # Check Gmail activity from this IP
    print("\n\n4. Gmail activity events from this IP:")
    print("-" * 70)

    results = service.activities().list(
        userKey=TARGET_USER,
        applicationName='gmail',
        maxResults=1000
    ).execute()

    found_gmail = False
    for event in results.get('items', []):
        ip = event.get('ipAddress', '')
        if ip == SUSPICIOUS_IP:
            found_gmail = True
            print(f"\nTime: {event.get('id', {}).get('time')}")
            for e in event.get('events', []):
                print(f"  Event: {e.get('name')}")

    if not found_gmail:
        print("  No Gmail activity events found from this IP in audit logs!")


if __name__ == '__main__':
    main()
