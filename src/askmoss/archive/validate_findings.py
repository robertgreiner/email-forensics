#!/usr/bin/env python3
"""
Validate our findings:
1. Are there any IPs we missed?
2. What exactly did the attacker do beyond read/delete/exfiltrate?
"""

import csv
from collections import defaultdict, Counter

# Known legitimate
OFFICE_IP = '199.200.88.186'
KNOWN_LEGIT = {
    '199.200.88.186',  # Office
    '138.199.114.2',   # Confirmed legit (Aug-Oct)
}

# Known attacker
KNOWN_ATTACKER = {
    '172.120.137.37',  # Login
    '45.87.125.150',   # Login
    '46.232.34.229',   # Login
    '147.124.205.9',   # Operations
    '158.51.123.14',   # Operations
}

# AWS IPs (Abnormal Security)
AWS_PREFIXES = ('44.', '52.', '35.', '50.17.', '13.59.', '3.132.', '3.231.', '34.', '100.', '107.23.')

# Google IPs
GOOGLE_PREFIXES = ('209.85.',)

def is_known_service(ip):
    """Check if IP is a known service (AWS, Google, etc.)"""
    for prefix in AWS_PREFIXES + GOOGLE_PREFIXES:
        if ip.startswith(prefix):
            return True
    return False

def main():
    filepath = '/home/robert/Downloads/lori-all.csv'

    print("=" * 80)
    print("VALIDATION: Did we miss anything?")
    print("=" * 80)

    # Track all IPs with their events
    ip_data = defaultdict(lambda: {
        'events': Counter(),
        'dates': set(),
        'sends': [],
        'replies': [],
        'forwards': [],
        'drafts': [],
        'deletes': [],
    })

    with open(filepath, 'r', errors='replace') as f:
        reader = csv.DictReader(f)
        for row in reader:
            ip = row.get('IP address', '')
            if not ip:
                continue

            event = row.get('Event', '')
            date = row.get('Date', '')[:10] if row.get('Date') else ''
            subject = row.get('Subject', '')
            to_addr = row.get('To (Envelope)', '').lower()
            full_date = row.get('Date', '')

            ip_data[ip]['events'][event] += 1
            if date:
                ip_data[ip]['dates'].add(date)

            # Track specific event types
            if event == 'Send':
                ip_data[ip]['sends'].append({'date': full_date, 'to': to_addr, 'subject': subject})
            elif event == 'Reply':
                ip_data[ip]['replies'].append({'date': full_date, 'to': to_addr, 'subject': subject})
            elif 'Forward' in event:
                ip_data[ip]['forwards'].append({'date': full_date, 'to': to_addr, 'subject': subject})
            elif event == 'Draft':
                ip_data[ip]['drafts'].append({'date': full_date, 'to': to_addr, 'subject': subject})
            elif event == 'Delete':
                ip_data[ip]['deletes'].append({'date': full_date, 'subject': subject})

    # ================================================================
    # Question 1: Any unknown IPs with December activity + suspicious events?
    # ================================================================
    print("\n" + "=" * 80)
    print("UNKNOWN IPs WITH DECEMBER ACTIVITY (not office, not known attacker, not AWS/Google)")
    print("=" * 80)

    suspicious_unknown = []
    for ip, data in ip_data.items():
        # Skip known
        if ip in KNOWN_LEGIT or ip in KNOWN_ATTACKER:
            continue
        if ip.startswith('199.200.'):  # Office range
            continue
        if ':' in ip:  # IPv6 (mobile)
            continue
        if is_known_service(ip):
            continue

        # Check for December activity
        dec_dates = [d for d in data['dates'] if d.startswith('2025-12')]
        if not dec_dates:
            continue

        # Check for suspicious events (not just Receive)
        non_receive = {k: v for k, v in data['events'].items() if k != 'Receive'}
        if non_receive:
            suspicious_unknown.append({
                'ip': ip,
                'dec_dates': sorted(dec_dates),
                'events': dict(data['events']),
                'sends': data['sends'],
                'replies': data['replies'],
                'deletes': data['deletes'],
            })

    if suspicious_unknown:
        for s in sorted(suspicious_unknown, key=lambda x: sum(x['events'].values()), reverse=True):
            print(f"\n  {s['ip']}")
            print(f"    December dates: {s['dec_dates'][0]} to {s['dec_dates'][-1]} ({len(s['dec_dates'])} days)")
            print(f"    Events: {s['events']}")
            if s['sends']:
                print(f"    SENDS: {len(s['sends'])}")
                for send in s['sends'][:3]:
                    print(f"      -> {send['to']}: {send['subject'][:40]}")
            if s['replies']:
                print(f"    REPLIES: {len(s['replies'])}")
                for r in s['replies'][:3]:
                    print(f"      -> {r['to']}: {r['subject'][:40]}")
            if s['deletes']:
                print(f"    DELETES: {len(s['deletes'])}")
    else:
        print("\n  None found - all suspicious IPs accounted for")

    # ================================================================
    # Question 2: What did the known attacker IPs actually do?
    # ================================================================
    print("\n" + "=" * 80)
    print("COMPLETE ACTIVITY FROM KNOWN ATTACKER IPs")
    print("=" * 80)

    for ip in ['147.124.205.9', '158.51.123.14']:
        data = ip_data[ip]
        print(f"\n{ip}:")
        print(f"  Active dates: {sorted(data['dates'])}")
        print(f"  Event breakdown:")
        for evt, count in data['events'].most_common():
            print(f"    {evt}: {count}")

        if data['replies']:
            print(f"\n  *** REPLY EVENTS ({len(data['replies'])}) ***")
            for r in data['replies']:
                print(f"    Date: {r['date']}")
                print(f"    To: {r['to']}")
                print(f"    Subject: {r['subject'][:60]}")

        if data['forwards']:
            print(f"\n  *** FORWARD EVENTS ({len(data['forwards'])}) ***")
            for f in data['forwards']:
                print(f"    To: {f['to']}: {f['subject'][:50]}")

    # ================================================================
    # Summary
    # ================================================================
    print("\n" + "=" * 80)
    print("SUMMARY: What did the attacker actually do?")
    print("=" * 80)

    total_events = sum(ip_data['147.124.205.9']['events'].values()) + sum(ip_data['158.51.123.14']['events'].values())
    print(f"\nTotal events from attacker IPs: {total_events}")

    combined = Counter()
    for ip in ['147.124.205.9', '158.51.123.14']:
        combined.update(ip_data[ip]['events'])

    print("\nCombined event breakdown:")
    for evt, count in combined.most_common():
        pct = count / total_events * 100
        print(f"  {evt}: {count} ({pct:.1f}%)")


if __name__ == '__main__':
    main()
