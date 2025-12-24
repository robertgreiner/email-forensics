#!/usr/bin/env python3
"""
Deep investigation of IP 147.124.205.9 - potential second attacker IP.
"""

import csv
from collections import Counter

TARGET_IP = '147.124.205.9'

def main():
    filepath = '/home/robert/Downloads/lori-all.csv'

    print("=" * 80)
    print(f"INVESTIGATION: {TARGET_IP}")
    print("=" * 80)

    events = []

    with open(filepath, 'r', errors='replace') as f:
        reader = csv.DictReader(f)
        for row in reader:
            ip = row.get('IP address', '')
            if ip != TARGET_IP:
                continue

            events.append({
                'date': row.get('Date', ''),
                'event': row.get('Event', ''),
                'subject': row.get('Subject', ''),
                'to': row.get('To (Envelope)', '').lower(),
                'from': row.get('From (Envelope)', '').lower()
            })

    print(f"\nTotal events: {len(events)}")

    # Date range
    dates = sorted(set(e['date'][:10] for e in events if e['date']))
    print(f"Active dates: {dates}")

    # Event types
    event_types = Counter(e['event'] for e in events)
    print(f"\nEvent breakdown:")
    for evt, count in event_types.most_common():
        print(f"  {evt}: {count}")

    # All events in chronological order
    print("\n" + "=" * 80)
    print("FULL CHRONOLOGICAL EVENT LOG:")
    print("=" * 80)

    for e in sorted(events, key=lambda x: x['date']):
        to_flag = ""
        if 'ssdhvca' in e['to'] or 'aksmoss' in e['to'] or 'sshdvac' in e['to']:
            to_flag = " *** ATTACKER DOMAIN ***"
        print(f"\n  {e['date']}")
        print(f"  Event: {e['event']}")
        if e['to']:
            print(f"  To: {e['to']}{to_flag}")
        print(f"  Subject: {e['subject'][:70]}")


if __name__ == '__main__':
    main()
