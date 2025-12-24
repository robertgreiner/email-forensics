#!/usr/bin/env python3
"""
Comprehensive analysis of lori-all.csv - all Gmail events.
"""

import csv
from collections import defaultdict, Counter
from datetime import datetime

SUSPICIOUS_IP = '158.51.123.14'
ATTACKER_IPS = {'172.120.137.37', '45.87.125.150', '46.232.34.229'}
ATTACKER_DOMAINS = {'ssdhvca.com', 'aksmoss.com', 'sshdvac.com'}
OFFICE_IP = '199.200.88.186'

def analyze_csv(filepath):
    print(f"Analyzing {filepath}...")
    print("=" * 80)

    # Counters and collectors
    event_types = Counter()
    ips = Counter()
    dates = Counter()

    suspicious_ip_events = []
    attacker_ip_events = []
    attacker_domain_events = []

    row_count = 0

    with open(filepath, 'r', errors='replace') as f:
        reader = csv.DictReader(f)

        for row in reader:
            row_count += 1

            event = row.get('Event', '')
            ip = row.get('IP address', '')
            date = row.get('Date', '')[:10] if row.get('Date') else ''
            to_addr = row.get('To (Envelope)', '').lower()
            from_addr = row.get('From (Envelope)', '').lower()
            subject = row.get('Subject', '')

            # Count basics
            event_types[event] += 1
            if ip:
                ips[ip] += 1
            if date:
                dates[date] += 1

            # Check for suspicious IP
            if ip == SUSPICIOUS_IP:
                suspicious_ip_events.append({
                    'date': row.get('Date', ''),
                    'event': event,
                    'subject': subject,
                    'from': from_addr,
                    'to': to_addr,
                    'ip': ip
                })

            # Check for attacker IPs
            if ip in ATTACKER_IPS:
                attacker_ip_events.append({
                    'date': row.get('Date', ''),
                    'event': event,
                    'subject': subject,
                    'from': from_addr,
                    'to': to_addr,
                    'ip': ip
                })

            # Check for attacker domains
            for domain in ATTACKER_DOMAINS:
                if domain in to_addr or domain in from_addr:
                    attacker_domain_events.append({
                        'date': row.get('Date', ''),
                        'event': event,
                        'subject': subject,
                        'from': from_addr,
                        'to': to_addr,
                        'ip': ip
                    })
                    break

    print(f"\nTotal rows: {row_count:,}")

    # Event types
    print("\n" + "=" * 80)
    print("EVENT TYPES:")
    for evt, count in event_types.most_common():
        print(f"  {evt}: {count:,}")

    # Date range
    print("\n" + "=" * 80)
    print("DATE RANGE:")
    sorted_dates = sorted(dates.keys())
    if sorted_dates:
        print(f"  From: {sorted_dates[0]} to {sorted_dates[-1]}")

    # Top IPs
    print("\n" + "=" * 80)
    print("TOP 15 IPs:")
    for ip, count in ips.most_common(15):
        label = ""
        if ip == OFFICE_IP:
            label = " [OFFICE]"
        elif ip == SUSPICIOUS_IP:
            label = " [SUSPICIOUS - Canadian VPS]"
        elif ip in ATTACKER_IPS:
            label = " [ATTACKER LOGIN IP]"
        print(f"  {ip}: {count:,}{label}")

    # Suspicious IP events
    print("\n" + "=" * 80)
    print(f"EVENTS FROM SUSPICIOUS IP ({SUSPICIOUS_IP}):")
    if suspicious_ip_events:
        for evt in suspicious_ip_events:
            print(f"\n  Date: {evt['date']}")
            print(f"  Event: {evt['event']}")
            print(f"  From: {evt['from']}")
            print(f"  To: {evt['to']}")
            print(f"  Subject: {evt['subject'][:60]}")
    else:
        print("  None found!")

    # Attacker IP events
    print("\n" + "=" * 80)
    print("EVENTS FROM ATTACKER LOGIN IPs:")
    if attacker_ip_events:
        for evt in attacker_ip_events[:20]:
            print(f"\n  Date: {evt['date']}")
            print(f"  Event: {evt['event']}")
            print(f"  IP: {evt['ip']}")
            print(f"  From: {evt['from']}")
            print(f"  To: {evt['to']}")
    else:
        print("  None found!")

    # Attacker domain events
    print("\n" + "=" * 80)
    print(f"EVENTS INVOLVING ATTACKER DOMAINS ({ATTACKER_DOMAINS}):")
    print(f"Total: {len(attacker_domain_events)}")
    if attacker_domain_events:
        # Group by event type
        by_event = defaultdict(list)
        for evt in attacker_domain_events:
            by_event[evt['event']].append(evt)

        for event_type, evts in by_event.items():
            print(f"\n  {event_type}: {len(evts)} events")
            for evt in evts[:5]:
                print(f"    [{evt['date'][:10]}] {evt['from']} -> {evt['to']}")
                if evt['subject']:
                    print(f"      Subject: {evt['subject'][:50]}")
                print(f"      IP: {evt['ip']}")


if __name__ == '__main__':
    analyze_csv('/home/robert/Downloads/lori-all.csv')
