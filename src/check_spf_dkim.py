#!/usr/bin/env python3
"""
Check SPF/DKIM fields for all emails to understand if Canadian VPS is anomalous.
"""

import csv
from collections import defaultdict

spf_by_ip = defaultdict(set)
dkim_by_ip = defaultdict(set)

OFFICE_IP = '199.200.88.186'
SUSPICIOUS_IP = '158.51.123.14'

with open('/home/robert/Downloads/lori-send.csv', 'r') as f:
    reader = csv.DictReader(f)
    for row in reader:
        ip = row.get('IP address', '')
        spf = row.get('SPF domain', '') or '(empty)'
        dkim = row.get('DKIM domain', '') or '(empty)'

        if ip:
            spf_by_ip[ip].add(spf)
            dkim_by_ip[ip].add(dkim)

print("SPF/DKIM Analysis by IP")
print("=" * 70)

print(f"\nOffice IP ({OFFICE_IP}):")
print(f"  SPF domains: {spf_by_ip.get(OFFICE_IP, set())}")
print(f"  DKIM domains: {dkim_by_ip.get(OFFICE_IP, set())}")

print(f"\nSuspicious IP ({SUSPICIOUS_IP}):")
print(f"  SPF domains: {spf_by_ip.get(SUSPICIOUS_IP, set())}")
print(f"  DKIM domains: {dkim_by_ip.get(SUSPICIOUS_IP, set())}")

# Check how many IPs have empty SPF/DKIM
print("\n" + "=" * 70)
print("IPs with empty SPF domain:")
for ip, spf_set in spf_by_ip.items():
    if '(empty)' in spf_set:
        print(f"  {ip}")

print("\nIPs with empty DKIM domain:")
for ip, dkim_set in dkim_by_ip.items():
    if '(empty)' in dkim_set:
        print(f"  {ip}")
