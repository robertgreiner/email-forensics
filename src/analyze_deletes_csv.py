#!/usr/bin/env python3
"""
Analyze domain-wide DELETE events from Admin Email Log Search export.
Looking for suspicious patterns across all users.
"""

import csv
from collections import defaultdict, Counter
from datetime import datetime

# Known attacker IPs
KNOWN_ATTACKER_IPS = {
    '172.120.137.37',
    '45.87.125.150',
    '46.232.34.229',
    '147.124.205.9',
    '158.51.123.14',
}

# Known legitimate IP patterns
OFFICE_PATTERNS = ('199.200.',)
AWS_PATTERNS = ('44.', '52.', '35.', '54.', '3.', '107.23.', '50.17.', '13.59.', '13.111.')
GOOGLE_PATTERNS = ('209.85.',)
MOBILE_IPV6 = ('2600:', '2607:')


def is_datacenter_ip(ip):
    """Heuristic to detect datacenter/VPS IPs."""
    if not ip:
        return False

    # Known attacker
    if ip in KNOWN_ATTACKER_IPS:
        return True

    # Skip known legitimate
    for pattern in OFFICE_PATTERNS + AWS_PATTERNS + GOOGLE_PATTERNS:
        if ip.startswith(pattern):
            return False

    # Skip IPv6 mobile
    if ':' in ip:
        return False

    # Remaining IPs could be suspicious - return True for further analysis
    return True


def main():
    filepath = '/home/robert/Downloads/deletes.csv'

    print("=" * 80)
    print("DOMAIN-WIDE DELETE EVENT ANALYSIS")
    print("=" * 80)

    # Parse CSV
    events = []
    with open(filepath, 'r', errors='replace') as f:
        reader = csv.DictReader(f)
        for row in reader:
            events.append(row)

    print(f"\nTotal delete events: {len(events):,}")

    # ================================================================
    # CHECK 1: Deletes from known attacker IPs
    # ================================================================
    print("\n" + "=" * 80)
    print("CHECK 1: Deletes from KNOWN ATTACKER IPs")
    print("=" * 80)

    attacker_deletes = []
    for event in events:
        ip = event.get('IP address', '')
        if ip in KNOWN_ATTACKER_IPS:
            attacker_deletes.append(event)

    if attacker_deletes:
        print(f"\n  🚨 FOUND {len(attacker_deletes)} deletes from known attacker IPs:\n")

        # Group by user
        by_user = defaultdict(list)
        for e in attacker_deletes:
            by_user[e.get('Owner', 'Unknown')].append(e)

        for user, user_events in sorted(by_user.items()):
            print(f"  {user}: {len(user_events)} deletes")
            for e in user_events[:5]:  # Show first 5
                print(f"    {e.get('Date', '')[:19]} | {e.get('IP address', '')} | {e.get('Subject', '')[:50]}")
            if len(user_events) > 5:
                print(f"    ... and {len(user_events) - 5} more")
    else:
        print("\n  ✅ No deletes from known attacker IPs")

    # ================================================================
    # CHECK 2: Deletes by user
    # ================================================================
    print("\n" + "=" * 80)
    print("CHECK 2: Delete counts by user")
    print("=" * 80)

    by_user = Counter()
    for event in events:
        by_user[event.get('Owner', 'Unknown')] += 1

    print(f"\n  Top 20 users by delete count:\n")
    for user, count in by_user.most_common(20):
        print(f"    {user:<45} {count:>6} deletes")

    # ================================================================
    # CHECK 3: Deletes from suspicious/datacenter IPs
    # ================================================================
    print("\n" + "=" * 80)
    print("CHECK 3: Deletes from suspicious/datacenter IPs")
    print("=" * 80)

    suspicious_deletes = []
    suspicious_ips = defaultdict(lambda: {'count': 0, 'users': set(), 'dates': set()})

    for event in events:
        ip = event.get('IP address', '')
        if is_datacenter_ip(ip) and ip not in KNOWN_ATTACKER_IPS:
            suspicious_deletes.append(event)
            suspicious_ips[ip]['count'] += 1
            suspicious_ips[ip]['users'].add(event.get('Owner', ''))
            date_str = event.get('Date', '')[:10]
            if date_str:
                suspicious_ips[ip]['dates'].add(date_str)

    if suspicious_ips:
        # Sort by count
        sorted_ips = sorted(suspicious_ips.items(), key=lambda x: -x[1]['count'])

        print(f"\n  Found {len(suspicious_ips)} potentially suspicious IPs:\n")

        for ip, data in sorted_ips[:30]:  # Top 30
            users = list(data['users'])[:3]
            users_str = ', '.join(users)
            if len(data['users']) > 3:
                users_str += f" (+{len(data['users'])-3})"
            print(f"    {ip:<20} | {data['count']:>5} deletes | {len(data['users']):>2} users | {users_str}")
    else:
        print("\n  ✅ No suspicious datacenter IPs detected")

    # ================================================================
    # CHECK 4: Users with deletes from suspicious IPs
    # ================================================================
    print("\n" + "=" * 80)
    print("CHECK 4: Users with deletes from suspicious IPs")
    print("=" * 80)

    user_suspicious = defaultdict(lambda: {'count': 0, 'ips': set()})
    for event in suspicious_deletes:
        user = event.get('Owner', '')
        ip = event.get('IP address', '')
        user_suspicious[user]['count'] += 1
        user_suspicious[user]['ips'].add(ip)

    if user_suspicious:
        sorted_users = sorted(user_suspicious.items(), key=lambda x: -x[1]['count'])

        print(f"\n  {len(user_suspicious)} users with suspicious IP deletes:\n")

        for user, data in sorted_users[:20]:
            print(f"    {user:<45} | {data['count']:>5} deletes | {len(data['ips']):>2} IPs")
    else:
        print("\n  ✅ No users with suspicious IP deletes")

    # ================================================================
    # CHECK 5: December attack window analysis
    # ================================================================
    print("\n" + "=" * 80)
    print("CHECK 5: December 2025 attack window (Dec 1-17)")
    print("=" * 80)

    dec_deletes = []
    for event in events:
        date_str = event.get('Date', '')
        if date_str.startswith('2025-12-') and int(date_str[8:10]) <= 17:
            dec_deletes.append(event)

    print(f"\n  Deletes during attack window: {len(dec_deletes):,}")

    # Check for suspicious IPs in attack window
    dec_suspicious = [e for e in dec_deletes if is_datacenter_ip(e.get('IP address', ''))]

    if dec_suspicious:
        print(f"  Deletes from suspicious IPs: {len(dec_suspicious)}")

        # Group by user
        by_user = defaultdict(list)
        for e in dec_suspicious:
            by_user[e.get('Owner', '')].append(e)

        print(f"\n  Users with suspicious deletes Dec 1-17:\n")
        for user, user_events in sorted(by_user.items(), key=lambda x: -len(x[1])):
            ips = set(e.get('IP address', '') for e in user_events)
            print(f"    {user}: {len(user_events)} deletes from {len(ips)} IPs")
            for ip in list(ips)[:3]:
                ip_count = len([e for e in user_events if e.get('IP address') == ip])
                print(f"      - {ip}: {ip_count}")
    else:
        print("  ✅ No suspicious IP deletes during attack window")

    # ================================================================
    # CHECK 6: Rapid-fire deletes (evidence destruction pattern)
    # ================================================================
    print("\n" + "=" * 80)
    print("CHECK 6: Rapid-fire delete patterns (potential evidence destruction)")
    print("=" * 80)

    # Group events by user and look for bursts
    user_events = defaultdict(list)
    for event in events:
        user = event.get('Owner', '')
        date_str = event.get('Date', '')
        ip = event.get('IP address', '')
        user_events[user].append({
            'date': date_str,
            'ip': ip,
            'subject': event.get('Subject', '')
        })

    burst_users = []
    for user, evts in user_events.items():
        # Sort by date
        evts.sort(key=lambda x: x['date'])

        # Look for 5+ deletes within 1 minute
        for i in range(len(evts) - 4):
            try:
                t1 = datetime.fromisoformat(evts[i]['date'].replace('Z', '+00:00'))
                t5 = datetime.fromisoformat(evts[i+4]['date'].replace('Z', '+00:00'))
                diff = (t5 - t1).total_seconds()

                if diff <= 60:  # 5 deletes in 1 minute
                    # Check if from suspicious IP
                    ips_in_burst = set(e['ip'] for e in evts[i:i+5])
                    suspicious_in_burst = any(is_datacenter_ip(ip) for ip in ips_in_burst)

                    burst_users.append({
                        'user': user,
                        'start': evts[i]['date'],
                        'count': 5,
                        'seconds': diff,
                        'ips': ips_in_burst,
                        'suspicious': suspicious_in_burst,
                        'subjects': [e['subject'][:30] for e in evts[i:i+5]]
                    })
                    break  # Only report first burst per user
            except:
                continue

    # Filter to suspicious bursts
    suspicious_bursts = [b for b in burst_users if b['suspicious']]

    if suspicious_bursts:
        print(f"\n  🚨 Found {len(suspicious_bursts)} rapid-fire delete bursts from suspicious IPs:\n")
        for b in sorted(suspicious_bursts, key=lambda x: x['start']):
            print(f"    {b['user']}")
            print(f"      Time: {b['start']}")
            print(f"      Deletes: {b['count']} in {b['seconds']:.0f} seconds")
            print(f"      IPs: {b['ips']}")
            print()
    else:
        print("\n  ✅ No suspicious rapid-fire delete patterns detected")

    # ================================================================
    # SUMMARY
    # ================================================================
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)

    print(f"\n  Total delete events analyzed: {len(events):,}")
    print(f"  Deletes from known attacker IPs: {len(attacker_deletes)}")
    print(f"  Deletes from suspicious IPs: {len(suspicious_deletes)}")
    print(f"  Users with suspicious activity: {len(user_suspicious)}")

    if attacker_deletes:
        affected = set(e.get('Owner') for e in attacker_deletes)
        print(f"\n  🚨 ACCOUNTS WITH ATTACKER IP DELETES: {affected}")


if __name__ == '__main__':
    main()
