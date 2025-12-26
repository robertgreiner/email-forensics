#!/usr/bin/env python3
"""
Analyze comprehensive utilities-all.csv export for security issues.
~1.5M rows of email activity data.
"""

import csv
from datetime import datetime, timezone
from collections import defaultdict
import re

CSV_PATH = '/home/robert/Downloads/utilities-all.csv'

# Known attacker IPs from both incidents
ATTACKER_IPS_UTILITIES = {
    '45.159.127.16',
    '156.229.254.40',
    '45.192.39.3',
    '38.69.8.106',
    '142.111.254.241',
}

ATTACKER_IPS_HVAC = {
    '172.120.137.37',
    '45.87.125.150',
    '46.232.34.229',
    '147.124.205.9',
    '158.51.123.14',
}

ALL_ATTACKER_IPS = ATTACKER_IPS_UTILITIES | ATTACKER_IPS_HVAC

# Attack window
ATTACK_START = datetime(2025, 12, 1, 0, 0, 0, tzinfo=timezone.utc)
ATTACK_END = datetime(2025, 12, 20, 0, 0, 0, tzinfo=timezone.utc)

# Suspicious patterns
SUSPICIOUS_DOMAINS = {
    'protonmail.com', 'protonmail.ch', 'tutanota.com', 'guerrillamail.com',
    'tempmail.com', 'mailinator.com', '10minutemail.com', 'yopmail.com',
}

def parse_date(date_str):
    """Parse date string from CSV."""
    if not date_str:
        return None
    try:
        dt = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        return dt.astimezone(timezone.utc)
    except:
        return None


def is_external_domain(email, internal_domains={'mossutilities.com', 'askmoss.com'}):
    """Check if email is external."""
    if not email:
        return False
    match = re.search(r'@([\w.-]+)', email.lower())
    if match:
        domain = match.group(1)
        return domain not in internal_domains
    return False


def main():
    print("=" * 80)
    print("COMPREHENSIVE UTILITIES EXPORT ANALYSIS")
    print("=" * 80)

    # Counters
    total_rows = 0
    attacker_events = []
    external_sends = []
    suspicious_sends = []
    events_by_type = defaultdict(int)
    events_by_user = defaultdict(int)
    events_by_ip = defaultdict(int)
    attack_window_events = []

    # Track unique external recipients
    external_recipients = defaultdict(set)

    # Track potential data exfiltration (large attachments sent externally)
    large_external_attachments = []

    print("\nReading CSV (this may take a moment for 1.5M rows)...")

    with open(CSV_PATH, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)

        for row in reader:
            total_rows += 1

            if total_rows % 200000 == 0:
                print(f"  Processed {total_rows:,} rows...")

            ip = row.get('IP address', '')
            event = row.get('Event', '')
            owner = row.get('Owner', '')
            date_str = row.get('Date', '')
            to_env = row.get('To (Envelope)', '')
            from_header = row.get('From (Header address)', '')
            subject = row.get('Subject', '')
            attachment = row.get('Attachment name', '')
            geo = row.get('Geo location', '')
            link_domain = row.get('Link domain', '')

            date = parse_date(date_str)

            events_by_type[event] += 1
            if owner:
                events_by_user[owner] += 1
            if ip:
                events_by_ip[ip] += 1

            # Check for attacker IP activity
            if ip in ALL_ATTACKER_IPS:
                attacker_events.append({
                    'date': date_str,
                    'event': event,
                    'owner': owner,
                    'ip': ip,
                    'subject': subject[:80] if subject else '',
                    'to': to_env,
                    'from': from_header,
                    'geo': geo,
                })

            # Check attack window activity
            if date and ATTACK_START <= date <= ATTACK_END:
                # Track sends to external addresses
                if event == 'Send' and is_external_domain(to_env):
                    external_sends.append({
                        'date': date_str,
                        'owner': owner,
                        'to': to_env,
                        'subject': subject[:80] if subject else '',
                        'ip': ip,
                        'attachment': attachment,
                    })

                    # Extract domain
                    match = re.search(r'@([\w.-]+)', to_env.lower())
                    if match:
                        external_recipients[owner].add(match.group(1))

                    # Check for suspicious domains
                    if any(susp in to_env.lower() for susp in SUSPICIOUS_DOMAINS):
                        suspicious_sends.append({
                            'date': date_str,
                            'owner': owner,
                            'to': to_env,
                            'subject': subject[:80] if subject else '',
                            'ip': ip,
                        })

                    # Large attachments
                    if attachment and ip in ALL_ATTACKER_IPS:
                        large_external_attachments.append({
                            'date': date_str,
                            'owner': owner,
                            'to': to_env,
                            'attachment': attachment,
                            'ip': ip,
                        })

    print(f"\nTotal rows processed: {total_rows:,}")

    # ================================================================
    # ATTACKER IP ACTIVITY
    # ================================================================
    print("\n" + "=" * 80)
    print("🚨 ACTIVITY FROM ATTACKER IPs")
    print("=" * 80)

    if attacker_events:
        print(f"\nFound {len(attacker_events)} events from attacker IPs:\n")

        # Group by user
        by_user = defaultdict(list)
        for evt in attacker_events:
            by_user[evt['owner']].append(evt)

        for user, events in sorted(by_user.items()):
            print(f"\n  {user}: {len(events)} events")
            for evt in events[:10]:  # Limit per user
                print(f"    [{evt['date'][:19]}] {evt['event']}")
                if evt['subject']:
                    print(f"        Subject: {evt['subject']}")
                if evt['to']:
                    print(f"        To: {evt['to']}")
            if len(events) > 10:
                print(f"    ... and {len(events) - 10} more events")
    else:
        print("\n  ✅ No email activity from attacker IPs found in this export")

    # ================================================================
    # SUSPICIOUS EXTERNAL SENDS
    # ================================================================
    print("\n" + "=" * 80)
    print("⚠️ SENDS TO SUSPICIOUS DOMAINS (during attack window)")
    print("=" * 80)

    if suspicious_sends:
        print(f"\nFound {len(suspicious_sends)} sends to suspicious domains:\n")
        for evt in suspicious_sends[:20]:
            print(f"  [{evt['date'][:19]}] {evt['owner']}")
            print(f"      To: {evt['to']}")
            print(f"      Subject: {evt['subject']}")
    else:
        print("\n  ✅ No sends to known suspicious domains")

    # ================================================================
    # EXTERNAL SEND PATTERNS
    # ================================================================
    print("\n" + "=" * 80)
    print("📧 EXTERNAL SEND PATTERNS (during attack window)")
    print("=" * 80)

    print(f"\nTotal external sends: {len(external_sends)}")

    # Top external senders
    sender_counts = defaultdict(int)
    for evt in external_sends:
        sender_counts[evt['owner']] += 1

    print("\nTop 10 external senders:")
    for sender, count in sorted(sender_counts.items(), key=lambda x: -x[1])[:10]:
        domains = external_recipients.get(sender, set())
        print(f"  {sender}: {count} sends to {len(domains)} unique domains")

    # Check for unusual patterns from compromised users
    print("\n--- Compromised User External Sends ---")
    compromised = ['vaughn@mossutilities.com']
    for user in compromised:
        user_sends = [e for e in external_sends if e['owner'] == user]
        if user_sends:
            print(f"\n  {user}: {len(user_sends)} external sends")
            for evt in user_sends[:15]:
                flag = "🚨" if evt['ip'] in ALL_ATTACKER_IPS else ""
                print(f"    {flag} [{evt['date'][:16]}] To: {evt['to']}")
                if evt['subject']:
                    print(f"        Subject: {evt['subject'][:60]}")
        else:
            print(f"\n  {user}: No external sends in attack window")

    # ================================================================
    # TOP IPs
    # ================================================================
    print("\n" + "=" * 80)
    print("🌐 TOP IPs BY ACTIVITY")
    print("=" * 80)

    print("\nTop 20 IPs by event count:")
    for ip, count in sorted(events_by_ip.items(), key=lambda x: -x[1])[:20]:
        flag = "🚨 ATTACKER" if ip in ALL_ATTACKER_IPS else ""
        print(f"  {ip}: {count:,} events {flag}")

    # ================================================================
    # EVENT TYPE SUMMARY
    # ================================================================
    print("\n" + "=" * 80)
    print("📊 EVENT TYPE SUMMARY")
    print("=" * 80)

    for event, count in sorted(events_by_type.items(), key=lambda x: -x[1]):
        print(f"  {event}: {count:,}")

    # ================================================================
    # DATA EXFILTRATION CHECK
    # ================================================================
    print("\n" + "=" * 80)
    print("📤 ATTACHMENTS SENT FROM ATTACKER IPs")
    print("=" * 80)

    if large_external_attachments:
        print(f"\nFound {len(large_external_attachments)} attachments sent externally from attacker IPs:\n")
        for evt in large_external_attachments:
            print(f"  [{evt['date'][:19]}] {evt['owner']}")
            print(f"      To: {evt['to']}")
            print(f"      Attachment: {evt['attachment']}")
    else:
        print("\n  ✅ No attachments sent externally from attacker IPs")

    # ================================================================
    # SUMMARY
    # ================================================================
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)

    print(f"\n  Total events analyzed: {total_rows:,}")
    print(f"  Events from attacker IPs: {len(attacker_events)}")
    print(f"  External sends during attack window: {len(external_sends)}")
    print(f"  Sends to suspicious domains: {len(suspicious_sends)}")
    print(f"  Attachments from attacker IPs: {len(large_external_attachments)}")

    if attacker_events:
        print(f"\n  ⚠️ Found {len(attacker_events)} events from attacker IPs - review above")
    else:
        print("\n  ✅ No attacker IP activity in email logs")


if __name__ == '__main__':
    main()
