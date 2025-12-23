#!/usr/bin/env python3
"""
Google Workspace Audit Log Retrieval for Incident Response.

Pulls:
- Login audit logs (suspicious sign-ins)
- Gmail audit logs (email activity)
- Token/OAuth audit logs (third-party app access)

Requires Admin SDK scopes added to domain-wide delegation:
  https://www.googleapis.com/auth/admin.reports.audit.readonly

Must impersonate an admin user (not regular user) for Reports API.

Usage:
    # First, set up impersonation:
    gcloud auth application-default login --impersonate-service-account=SERVICE_ACCOUNT_EMAIL

    # Then run:
    python audit_logs.py --user lori.maynard@domain.com --days 30
    python audit_logs.py --user lori.maynard@domain.com --start 2024-12-01 --end 2024-12-15
"""

import argparse
import json
import os
import sys
from datetime import datetime, timedelta
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
ADMIN_USER = os.getenv('ADMIN_USER')  # Must be a Workspace admin for Reports API

# Scopes needed for audit logs
SCOPES = [
    'https://www.googleapis.com/auth/admin.reports.audit.readonly',
]


def get_credentials(admin_email: str):
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
        subject=admin_email
    )

    return delegated_credentials


def format_timestamp(ts_str: str) -> str:
    """Format Google's timestamp to readable format."""
    if not ts_str:
        return "N/A"
    try:
        dt = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
        return dt.strftime('%Y-%m-%d %H:%M:%S UTC')
    except:
        return ts_str


def get_login_events(service, user_email: str, start_time: str, end_time: str):
    """Fetch login audit events for a user."""
    print(f"\n{'='*80}")
    print(f"LOGIN AUDIT EVENTS FOR: {user_email}")
    print(f"Period: {start_time} to {end_time}")
    print('='*80)

    events = []
    try:
        request = service.activities().list(
            userKey=user_email,
            applicationName='login',
            startTime=start_time,
            endTime=end_time,
            maxResults=1000
        )

        while request:
            response = request.execute()
            items = response.get('items', [])
            events.extend(items)
            request = service.activities().list_next(request, response)

    except HttpError as e:
        print(f"Error fetching login events: {e}")
        return events

    if not events:
        print("\nNo login events found for this period.")
        return events

    print(f"\nFound {len(events)} login events:\n")

    # Categorize events
    suspicious = []
    normal = []

    for event in events:
        event_time = format_timestamp(event.get('id', {}).get('time', ''))
        ip_address = event.get('ipAddress', 'Unknown IP')

        for e in event.get('events', []):
            event_type = e.get('type', 'unknown')
            event_name = e.get('name', 'unknown')

            # Extract parameters
            params = {p.get('name'): p.get('value') for p in e.get('parameters', [])}

            login_type = params.get('login_type', 'unknown')
            is_suspicious = params.get('is_suspicious', 'false')
            login_challenge_method = params.get('login_challenge_method', '')

            event_data = {
                'time': event_time,
                'ip': ip_address,
                'type': event_type,
                'name': event_name,
                'login_type': login_type,
                'is_suspicious': is_suspicious,
                'challenge_method': login_challenge_method,
                'params': params
            }

            if is_suspicious == 'true' or event_name in ['login_failure', 'login_challenge', 'suspicious_login']:
                suspicious.append(event_data)
            else:
                normal.append(event_data)

    # Print suspicious first
    if suspicious:
        print("*** SUSPICIOUS/FAILED LOGINS ***")
        print("-"*60)
        for e in suspicious:
            print(f"  [{e['time']}] {e['name']}")
            print(f"    IP: {e['ip']}")
            print(f"    Type: {e['login_type']}")
            if e['challenge_method']:
                print(f"    Challenge: {e['challenge_method']}")
            print()

    # Print normal logins
    print("\n[Normal Login Activity]")
    print("-"*60)
    for e in normal[:50]:  # Limit output
        print(f"  [{e['time']}] {e['name']} from {e['ip']} ({e['login_type']})")

    if len(normal) > 50:
        print(f"  ... and {len(normal) - 50} more events")

    return events


def get_gmail_events(service, user_email: str, start_time: str, end_time: str):
    """Fetch Gmail audit events (requires enterprise/E5)."""
    print(f"\n{'='*80}")
    print(f"GMAIL AUDIT EVENTS FOR: {user_email}")
    print(f"Period: {start_time} to {end_time}")
    print('='*80)

    events = []
    try:
        # Note: Gmail audit logs may require Gmail Enterprise
        request = service.activities().list(
            userKey=user_email,
            applicationName='gmail',
            startTime=start_time,
            endTime=end_time,
            maxResults=1000
        )

        while request:
            response = request.execute()
            items = response.get('items', [])
            events.extend(items)
            request = service.activities().list_next(request, response)

    except HttpError as e:
        if 'not enabled' in str(e).lower() or '400' in str(e):
            print("\nGmail audit logs may not be available (requires Enterprise license)")
        else:
            print(f"Error fetching Gmail events: {e}")
        return events

    if not events:
        print("\nNo Gmail events found (or not available on your license).")
        return events

    print(f"\nFound {len(events)} Gmail events:\n")

    for event in events[:100]:
        event_time = format_timestamp(event.get('id', {}).get('time', ''))
        ip_address = event.get('ipAddress', 'Unknown')

        for e in event.get('events', []):
            event_name = e.get('name', 'unknown')
            params = {p.get('name'): p.get('value') for p in e.get('parameters', [])}

            print(f"  [{event_time}] {event_name}")
            print(f"    IP: {ip_address}")
            if params:
                for k, v in list(params.items())[:5]:
                    print(f"    {k}: {v}")
            print()

    return events


def get_token_events(service, user_email: str, start_time: str, end_time: str):
    """Fetch OAuth token/app authorization events."""
    print(f"\n{'='*80}")
    print(f"OAUTH/TOKEN EVENTS FOR: {user_email}")
    print(f"Period: {start_time} to {end_time}")
    print('='*80)

    events = []
    try:
        request = service.activities().list(
            userKey=user_email,
            applicationName='token',
            startTime=start_time,
            endTime=end_time,
            maxResults=1000
        )

        while request:
            response = request.execute()
            items = response.get('items', [])
            events.extend(items)
            request = service.activities().list_next(request, response)

    except HttpError as e:
        print(f"Error fetching token events: {e}")
        return events

    if not events:
        print("\nNo OAuth/token events found for this period.")
        return events

    print(f"\nFound {len(events)} OAuth/token events:\n")
    print("*** These show third-party apps granted access to the account ***\n")

    for event in events:
        event_time = format_timestamp(event.get('id', {}).get('time', ''))
        ip_address = event.get('ipAddress', 'Unknown')

        for e in event.get('events', []):
            event_name = e.get('name', 'unknown')
            params = {p.get('name'): p.get('value') for p in e.get('parameters', [])}

            app_name = params.get('app_name', 'Unknown App')
            client_id = params.get('client_id', '')
            scopes = params.get('scope', '')

            print(f"  [{event_time}] {event_name}")
            print(f"    App: {app_name}")
            print(f"    Client ID: {client_id}")
            print(f"    IP: {ip_address}")
            if scopes:
                print(f"    Scopes: {scopes}")
            print()

    return events


def get_user_settings_events(service, user_email: str, start_time: str, end_time: str):
    """Fetch user settings changes (filters, forwarding, etc.)."""
    print(f"\n{'='*80}")
    print(f"USER/ADMIN SETTINGS CHANGES FOR: {user_email}")
    print(f"Period: {start_time} to {end_time}")
    print('='*80)

    events = []
    try:
        # Check admin audit log for changes to this user
        request = service.activities().list(
            userKey='all',
            applicationName='admin',
            startTime=start_time,
            endTime=end_time,
            filters=f'USER_EMAIL=={user_email}',
            maxResults=1000
        )

        while request:
            response = request.execute()
            items = response.get('items', [])
            events.extend(items)
            request = service.activities().list_next(request, response)

    except HttpError as e:
        print(f"Error fetching admin events: {e}")
        return events

    if not events:
        print("\nNo admin changes found for this user.")
        return events

    print(f"\nFound {len(events)} admin events affecting this user:\n")

    for event in events:
        event_time = format_timestamp(event.get('id', {}).get('time', ''))
        actor = event.get('actor', {}).get('email', 'Unknown')
        ip_address = event.get('ipAddress', 'Unknown')

        for e in event.get('events', []):
            event_name = e.get('name', 'unknown')
            params = {p.get('name'): p.get('value') for p in e.get('parameters', [])}

            print(f"  [{event_time}] {event_name}")
            print(f"    Actor: {actor}")
            print(f"    IP: {ip_address}")
            if params:
                for k, v in list(params.items())[:10]:
                    print(f"    {k}: {v}")
            print()

    return events


def save_events(events: list, filename: str):
    """Save events to JSON file."""
    output_dir = Path('output')
    output_dir.mkdir(exist_ok=True)

    filepath = output_dir / filename
    with open(filepath, 'w') as f:
        json.dump(events, f, indent=2, default=str)

    print(f"\n[+] Saved {len(events)} events to {filepath}")


def main():
    parser = argparse.ArgumentParser(description='Fetch Google Workspace audit logs')
    parser.add_argument('--user', '-u', required=True, help='User email to investigate')
    parser.add_argument('--admin', '-a', help='Admin email for API access (or set ADMIN_USER env var)')
    parser.add_argument('--days', '-d', type=int, default=30, help='Number of days back (default: 30)')
    parser.add_argument('--start', '-s', help='Start date (YYYY-MM-DD)')
    parser.add_argument('--end', '-e', help='End date (YYYY-MM-DD)')
    parser.add_argument('--output', '-o', help='Output JSON file prefix')

    args = parser.parse_args()

    # Determine time range
    if args.start and args.end:
        start_time = f"{args.start}T00:00:00Z"
        end_time = f"{args.end}T23:59:59Z"
    else:
        end_dt = datetime.utcnow()
        start_dt = end_dt - timedelta(days=args.days)
        start_time = start_dt.strftime('%Y-%m-%dT%H:%M:%SZ')
        end_time = end_dt.strftime('%Y-%m-%dT%H:%M:%SZ')

    # Get admin user
    admin_email = args.admin or ADMIN_USER
    if not admin_email:
        print("ERROR: Must specify admin user via --admin or ADMIN_USER env var")
        print("The Reports API requires impersonating a Workspace admin.")
        sys.exit(1)

    print(f"Fetching audit logs for: {args.user}")
    print(f"Using admin account: {admin_email}")
    print(f"Time range: {start_time} to {end_time}")

    # Build service
    try:
        credentials = get_credentials(admin_email)
        service = build('admin', 'reports_v1', credentials=credentials)
    except Exception as e:
        print(f"ERROR: Failed to authenticate: {e}")
        print("\nMake sure you have:")
        print("1. Service account key file in place")
        print("2. Domain-wide delegation configured with scope:")
        print("   https://www.googleapis.com/auth/admin.reports.audit.readonly")
        print("3. An admin user email set")
        sys.exit(1)

    all_events = {}

    # Fetch all audit types
    all_events['login'] = get_login_events(service, args.user, start_time, end_time)
    all_events['gmail'] = get_gmail_events(service, args.user, start_time, end_time)
    all_events['token'] = get_token_events(service, args.user, start_time, end_time)
    all_events['admin'] = get_user_settings_events(service, args.user, start_time, end_time)

    # Save to files
    if args.output or True:  # Always save
        prefix = args.output or args.user.split('@')[0]
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        save_events(all_events, f"{prefix}_audit_{timestamp}.json")

    # Summary
    print("\n" + "="*80)
    print("SUMMARY")
    print("="*80)
    print(f"Login events:  {len(all_events['login'])}")
    print(f"Gmail events:  {len(all_events['gmail'])}")
    print(f"OAuth events:  {len(all_events['token'])}")
    print(f"Admin events:  {len(all_events['admin'])}")

    # Quick risk assessment
    suspicious_logins = sum(1 for e in all_events['login']
                          for ev in e.get('events', [])
                          for p in ev.get('parameters', [])
                          if p.get('name') == 'is_suspicious' and p.get('value') == 'true')

    if suspicious_logins:
        print(f"\n*** WARNING: {suspicious_logins} suspicious login events detected! ***")

    oauth_grants = len(all_events['token'])
    if oauth_grants:
        print(f"\n*** REVIEW: {oauth_grants} OAuth app authorizations found ***")


if __name__ == '__main__':
    main()
