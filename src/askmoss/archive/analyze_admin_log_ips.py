#!/usr/bin/env python3
"""
Analyze IPs in Admin Email Log Search export CSV.
"""

import csv
from collections import defaultdict

# Known IPs
MOSS_OFFICE = '199.200.88.186'
ATTACKER_IPS = {'172.120.137.37', '45.87.125.150', '46.232.34.229'}

def analyze_ips(filepath):
    """Analyze IPs in the admin email log CSV."""

    ip_counts = defaultdict(int)
    ip_messages = defaultdict(set)
    ip_dates = defaultdict(set)

    with open(filepath, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            msg_id = row.get('Message ID', '')
            date_str = row.get('Date', '')[:10] if row.get('Date') else ''
            ip = row.get('IP address', '')

            if ip and msg_id:
                ip_counts[ip] += 1
                ip_messages[ip].add(msg_id)
                if date_str:
                    ip_dates[ip].add(date_str)

    print("IP Address Analysis")
    print("=" * 80)
    print()

    # Check for attacker IPs
    print("ATTACKER IPs:")
    for ip in ATTACKER_IPS:
        if ip in ip_messages:
            print(f"  *** {ip}: {len(ip_messages[ip])} emails ***")
        else:
            print(f"  {ip}: NOT FOUND")
    print()

    # Group by IP type
    print("All IPs (sorted by unique email count):")
    sorted_ips = sorted(ip_messages.items(), key=lambda x: -len(x[1]))
    for ip, msgs in sorted_ips:
        dates = sorted(ip_dates[ip])
        date_range = f"{dates[0]} - {dates[-1]}" if dates else "N/A"

        # Categorize IP
        if ip == MOSS_OFFICE:
            label = "[OFFICE]"
        elif ip in ATTACKER_IPS:
            label = "[ATTACKER!!!]"
        elif ip.startswith('2600:'):
            label = "[IPv6/Mobile]"
        elif any(ip.startswith(prefix) for prefix in ['10.', '172.16.', '192.168.']):
            label = "[Private]"
        else:
            label = "[UNKNOWN]"

        print(f"  {ip:<25} {label:<15} {len(msgs):>3} emails  ({date_range})")

if __name__ == '__main__':
    analyze_ips('/home/robert/Downloads/lori-send.csv')
