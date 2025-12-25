#!/usr/bin/env python3
"""
Check all emails sent from suspicious IP 158.51.123.14
"""

import csv

SUSPICIOUS_IP = '158.51.123.14'

with open('/home/robert/Downloads/lori-send.csv', 'r') as f:
    reader = csv.DictReader(f)

    print(f"All emails sent from {SUSPICIOUS_IP}:")
    print("=" * 80)

    seen = set()
    for row in reader:
        ip = row.get('IP address', '')
        msg_id = row.get('Message ID', '')

        if ip == SUSPICIOUS_IP and msg_id not in seen:
            seen.add(msg_id)
            date = row.get('Date', '')
            to_addr = row.get('To (Envelope)', '')
            subject = row.get('Subject', '')

            print(f"Date: {date}")
            print(f"To: {to_addr}")
            print(f"Subject: {subject}")
            print(f"Message-ID: {msg_id[:60]}...")
            print()
