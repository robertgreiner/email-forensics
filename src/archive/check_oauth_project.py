#!/usr/bin/env python3
"""
Check OAuth project IDs in admin log emails, especially from suspicious IPs.
"""

import csv
from collections import defaultdict

SUSPICIOUS_IP = '158.51.123.14'
OFFICE_IP = '199.200.88.186'
AWS_IPS = {'13.59.96.180', '44.224.15.38', '50.17.62.222', '35.166.188.152', '3.132.208.199', '52.4.92.69'}

oauth_by_ip = defaultdict(set)
traffic_by_ip = defaultdict(set)

with open('/home/robert/Downloads/lori-send.csv', 'r') as f:
    reader = csv.DictReader(f)
    for row in reader:
        ip = row.get('IP address', '')
        oauth_project = row.get('OAuth project ID', '')
        traffic_source = row.get('Traffic source', '')

        if ip:
            if oauth_project:
                oauth_by_ip[ip].add(oauth_project)
            if traffic_source:
                traffic_by_ip[ip].add(traffic_source)

print("OAuth Project IDs by IP:")
print("=" * 70)

# Check suspicious IP
print(f"\n{SUSPICIOUS_IP} (Canadian VPS):")
print(f"  OAuth projects: {oauth_by_ip.get(SUSPICIOUS_IP, 'None')}")
print(f"  Traffic sources: {traffic_by_ip.get(SUSPICIOUS_IP, 'None')}")

# Check office IP
print(f"\n{OFFICE_IP} (Office):")
print(f"  OAuth projects: {oauth_by_ip.get(OFFICE_IP, 'None')}")
print(f"  Traffic sources: {traffic_by_ip.get(OFFICE_IP, 'None')}")

# Check AWS IPs
print("\nAWS IPs:")
for ip in AWS_IPS:
    if ip in oauth_by_ip or ip in traffic_by_ip:
        print(f"\n{ip}:")
        print(f"  OAuth projects: {oauth_by_ip.get(ip, 'None')}")
        print(f"  Traffic sources: {traffic_by_ip.get(ip, 'None')}")

# Summary
print("\n" + "=" * 70)
print("All unique OAuth Project IDs found:")
all_oauth = set()
for projects in oauth_by_ip.values():
    all_oauth.update(projects)
for proj in all_oauth:
    if proj:
        print(f"  {proj}")
