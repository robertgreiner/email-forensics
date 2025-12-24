#!/usr/bin/env python3
"""
Check if "missing" emails are duplicate Message-IDs sent from multiple IPs.
"""

import csv
from collections import defaultdict

OFFICE_IP = '199.200.88.186'
AWS_IPS = {'13.59.96.180', '44.224.15.38', '50.17.62.222', '35.166.188.152', '3.132.208.199', '52.4.92.69'}

# Track Message-IDs and which IPs sent them
msg_sources = defaultdict(set)
msg_info = {}

with open('/home/robert/Downloads/lori-send.csv', 'r') as f:
    reader = csv.DictReader(f)
    for row in reader:
        msg_id = row.get('Message ID', '')
        ip = row.get('IP address', '')

        if msg_id:
            msg_sources[msg_id].add(ip)
            if msg_id not in msg_info:
                msg_info[msg_id] = {
                    'subject': row.get('Subject', ''),
                    'to': row.get('To (Envelope)', ''),
                    'date': row.get('Date', '')[:10]
                }

print("Message-ID Source Analysis")
print("=" * 70)
print()

# Categorize messages
office_only = []
aws_only = []
both = []
other = []

for msg_id, ips in msg_sources.items():
    has_office = OFFICE_IP in ips
    has_aws = bool(ips & AWS_IPS)
    has_other = bool(ips - {OFFICE_IP} - AWS_IPS)

    if has_office and not has_aws and not has_other:
        office_only.append(msg_id)
    elif has_aws and not has_office:
        aws_only.append(msg_id)
    elif has_office and has_aws:
        both.append(msg_id)
    else:
        other.append(msg_id)

print(f"Sent from Office ONLY:           {len(office_only)}")
print(f"Sent from AWS ONLY:              {len(aws_only)}")
print(f"Sent from BOTH Office AND AWS:   {len(both)} (duplicates in log)")
print(f"Sent from other sources:         {len(other)}")
print()

# The "real" sent count should be office_only + those in both + other
print("INTERPRETATION:")
print("-" * 70)
print(f"Emails Lori actually sent (office + mobile): ~{len(office_only) + len(other) + len(both)}")
print(f"Additional entries from AWS (Abnormal Security copies): ~{len(both)}")
print()

# Check if AWS-only emails might be from Abnormal creating new emails
if aws_only:
    print(f"\nAWS-ONLY emails (not sent from office - investigate):")
    for mid in aws_only[:10]:
        info = msg_info[mid]
        print(f"  [{info['date']}] To: {info['to'][:40]} Subj: {info['subject'][:30]}")

# Show date distribution
print()
print("Emails per day (Office only):")
office_by_date = defaultdict(int)
for mid in office_only:
    office_by_date[msg_info[mid]['date']] += 1
for date in sorted(office_by_date.keys()):
    print(f"  {date}: {office_by_date[date]}")

print()
print(f"Total unique Message-IDs: {len(msg_sources)}")
print(f"Total if we exclude AWS duplicates: {len(office_only) + len(other)}")
