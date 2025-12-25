#!/usr/bin/env python3
"""
Analyze Vaughn's email activity export for attacker activity.
"""

import csv
from datetime import datetime, timezone
from collections import defaultdict

CSV_PATH = '/home/robert/Downloads/vaughn-all.csv'

ATTACKER_IPS = {
    '45.159.127.16',
    '156.229.254.40',
    '45.192.39.3',
    '38.69.8.106',
    '142.111.254.241',
}

# Attack window: Dec 2-10, 2025
ATTACK_START = datetime(2025, 12, 2, 0, 0, 0, tzinfo=timezone.utc)
ATTACK_END = datetime(2025, 12, 10, 23, 59, 59, tzinfo=timezone.utc)


def parse_date(date_str):
    """Parse the date string from the CSV and convert to UTC."""
    try:
        # Format: 2025-12-25T16:19:36-06:00
        dt = datetime.fromisoformat(date_str)
        # Convert to UTC for comparison
        return dt.astimezone(timezone.utc)
    except:
        return None


def main():
    print("=" * 80)
    print("VAUGHN EMAIL ACTIVITY ANALYSIS")
    print("=" * 80)

    attacker_events = []
    attack_window_events = []
    sent_emails = []
    event_types = defaultdict(int)

    with open(CSV_PATH, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)

        for row in reader:
            ip = row.get('IP address', '')
            date_str = row.get('Date', '')
            event = row.get('Event', '')
            subject = row.get('Subject', '')
            from_addr = row.get('From (Header address)', '')
            to_addr = row.get('To (Envelope)', '')
            geo = row.get('Geo location', '')

            event_types[event] += 1

            date = parse_date(date_str)

            # Check for attacker IPs
            if ip in ATTACKER_IPS:
                attacker_events.append({
                    'date': date_str,
                    'event': event,
                    'subject': subject[:80] if subject else '',
                    'from': from_addr,
                    'to': to_addr,
                    'ip': ip,
                    'geo': geo,
                })

            # Check for activity in attack window
            if date and ATTACK_START <= date <= ATTACK_END:
                attack_window_events.append({
                    'date': date_str,
                    'event': event,
                    'subject': subject[:80] if subject else '',
                    'from': from_addr,
                    'to': to_addr,
                    'ip': ip,
                    'geo': geo,
                })

                # Track sent emails
                if event == 'Send':
                    sent_emails.append({
                        'date': date_str,
                        'subject': subject,
                        'to': to_addr,
                        'ip': ip,
                        'geo': geo,
                    })

    # Report
    print(f"\nTotal events in export: {sum(event_types.values())}")
    print(f"\nEvent types:")
    for event, count in sorted(event_types.items(), key=lambda x: -x[1]):
        print(f"  {event}: {count}")

    print("\n" + "=" * 80)
    print("🚨 ACTIVITY FROM ATTACKER IPs")
    print("=" * 80)

    if attacker_events:
        print(f"\nFound {len(attacker_events)} events from attacker IPs:\n")
        for evt in attacker_events:
            print(f"  [{evt['date']}] {evt['event']}")
            print(f"      IP: {evt['ip']} ({evt['geo']})")
            if evt['subject']:
                print(f"      Subject: {evt['subject']}")
            if evt['to']:
                print(f"      To: {evt['to']}")
            print()
    else:
        print("\n  ✓ No email activity from attacker IPs found")

    print("\n" + "=" * 80)
    print("📧 SENT EMAILS DURING ATTACK WINDOW (Dec 2-10)")
    print("=" * 80)

    if sent_emails:
        print(f"\nFound {len(sent_emails)} sent emails:\n")
        for email in sent_emails[:50]:  # Limit output
            print(f"  [{email['date']}]")
            print(f"      To: {email['to']}")
            print(f"      Subject: {email['subject'][:100] if email['subject'] else '(no subject)'}")
            print(f"      IP: {email['ip']} ({email['geo']})")

            # Flag if from attacker IP
            if email['ip'] in ATTACKER_IPS:
                print(f"      🚨 SENT FROM ATTACKER IP!")
            print()

        if len(sent_emails) > 50:
            print(f"  ... and {len(sent_emails) - 50} more sent emails")
    else:
        print("\n  No sent emails in attack window")

    print("\n" + "=" * 80)
    print("📊 ATTACK WINDOW SUMMARY")
    print("=" * 80)

    # Summarize attack window by event type
    window_events_by_type = defaultdict(int)
    window_events_by_ip = defaultdict(int)

    for evt in attack_window_events:
        window_events_by_type[evt['event']] += 1
        if evt['ip']:
            window_events_by_ip[evt['ip']] += 1

    print(f"\nTotal events in attack window: {len(attack_window_events)}")
    print(f"\nBy event type:")
    for event, count in sorted(window_events_by_type.items(), key=lambda x: -x[1]):
        print(f"  {event}: {count}")

    print(f"\nTop IPs in attack window:")
    for ip, count in sorted(window_events_by_ip.items(), key=lambda x: -x[1])[:15]:
        flag = "🚨 ATTACKER" if ip in ATTACKER_IPS else ""
        print(f"  {ip}: {count} events {flag}")


if __name__ == '__main__':
    main()
