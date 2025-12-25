#!/usr/bin/env python3
"""
Deep dive into suspicious IP activity.
"""

import csv
from collections import defaultdict, Counter
from datetime import datetime

SUSPICIOUS_IP = '158.51.123.14'
SECOND_IP = '138.199.114.2'

def analyze_ip(filepath, target_ip):
    print(f"\n{'='*80}")
    print(f"DEEP DIVE: {target_ip}")
    print(f"{'='*80}")

    events_by_type = Counter()
    events_by_date = Counter()
    send_events = []
    delete_events = []
    trash_events = []
    all_events = []

    with open(filepath, 'r', errors='replace') as f:
        reader = csv.DictReader(f)
        for row in reader:
            ip = row.get('IP address', '')
            if ip != target_ip:
                continue

            event = row.get('Event', '')
            date = row.get('Date', '')
            subject = row.get('Subject', '')
            to_addr = row.get('To (Envelope)', '')
            from_addr = row.get('From (Envelope)', '')

            events_by_type[event] += 1
            if date:
                events_by_date[date[:10]] += 1

            all_events.append({
                'date': date,
                'event': event,
                'subject': subject,
                'from': from_addr,
                'to': to_addr
            })

            if event == 'Send':
                send_events.append({
                    'date': date,
                    'subject': subject,
                    'from': from_addr,
                    'to': to_addr
                })
            elif event == 'Delete':
                delete_events.append({
                    'date': date,
                    'subject': subject,
                    'from': from_addr,
                    'to': to_addr
                })
            elif 'Trash' in event:
                trash_events.append({
                    'date': date,
                    'event': event,
                    'subject': subject,
                    'to': to_addr
                })

    print(f"\nTotal events: {sum(events_by_type.values())}")

    print("\nEvents by type:")
    for evt, count in events_by_type.most_common():
        print(f"  {evt}: {count}")

    print("\nEvents by date:")
    for date in sorted(events_by_date.keys()):
        print(f"  {date}: {events_by_date[date]}")

    print(f"\n{'='*80}")
    print("ALL SEND EVENTS:")
    for evt in send_events:
        print(f"\n  Date: {evt['date']}")
        print(f"  To: {evt['to']}")
        print(f"  Subject: {evt['subject']}")

    print(f"\n{'='*80}")
    print(f"DELETE EVENTS: {len(delete_events)}")
    for evt in delete_events[:20]:
        print(f"\n  Date: {evt['date']}")
        print(f"  Subject: {evt['subject'][:60]}")

    print(f"\n{'='*80}")
    print(f"TRASH EVENTS (sample): {len(trash_events)}")
    for evt in trash_events[:10]:
        print(f"\n  Date: {evt['date']}")
        print(f"  Event: {evt['event']}")
        print(f"  Subject: {evt['subject'][:60]}")

    return all_events


def main():
    filepath = '/home/robert/Downloads/lori-all.csv'

    # Analyze suspicious IP
    events1 = analyze_ip(filepath, SUSPICIOUS_IP)

    # Check second IP
    print(f"\n\n{'#'*80}")
    print("Checking second highest IP...")

    # Quick lookup of second IP
    import subprocess
    result = subprocess.run(['whois', SECOND_IP], capture_output=True, text=True)
    for line in result.stdout.split('\n'):
        if any(x in line.lower() for x in ['orgname', 'netname', 'organization', 'descr']):
            print(line)
            break

    analyze_ip(filepath, SECOND_IP)


if __name__ == '__main__':
    main()
