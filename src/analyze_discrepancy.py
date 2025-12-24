#!/usr/bin/env python3
"""
Understand the discrepancy between Admin Log (259) and Gmail SENT (62).
"""

import csv
from collections import defaultdict

MOSS_OFFICE = '199.200.88.186'

def analyze(filepath):
    """Analyze the discrepancy."""

    # Emails by IP type
    office_messages = set()
    cloud_messages = set()
    mobile_messages = set()
    other_messages = set()

    # Track multi-recipient emails
    recipients_per_msg = defaultdict(set)

    with open(filepath, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            msg_id = row.get('Message ID', '')
            ip = row.get('IP address', '')
            to_addr = row.get('To (Envelope)', '')

            if msg_id:
                recipients_per_msg[msg_id].add(to_addr)

                if ip == MOSS_OFFICE:
                    office_messages.add(msg_id)
                elif ip.startswith('2600:'):
                    mobile_messages.add(msg_id)
                elif ip.startswith(('13.', '35.', '44.', '50.', '52.', '3.')):
                    cloud_messages.add(msg_id)
                else:
                    other_messages.add(msg_id)

    print("Analysis of 259 unique emails in Admin Log")
    print("=" * 60)
    print()

    # Emails by source
    print("By source IP:")
    print(f"  Office (199.200.88.186):  {len(office_messages)} unique emails")
    print(f"  AWS/Cloud IPs:            {len(cloud_messages)} unique emails")
    print(f"  Mobile (IPv6):            {len(mobile_messages)} unique emails")
    print(f"  Other:                    {len(other_messages)} unique emails")
    print()

    # Overlap analysis
    all_messages = office_messages | cloud_messages | mobile_messages | other_messages
    print(f"  Total unique:             {len(all_messages)}")
    print()

    # Office ONLY emails (sent from office, not also from cloud)
    office_only = office_messages - cloud_messages - mobile_messages - other_messages
    cloud_only = cloud_messages - office_messages - mobile_messages - other_messages
    both = office_messages & cloud_messages

    print("Overlap analysis:")
    print(f"  Office ONLY:              {len(office_only)} (sent only from office)")
    print(f"  Cloud ONLY:               {len(cloud_only)} (sent only from AWS)")
    print(f"  Both office AND cloud:    {len(both)} (same email from multiple IPs)")
    print()

    # Multi-recipient analysis
    multi_recipient = [msg for msg, recips in recipients_per_msg.items() if len(recips) > 1]
    print(f"Multi-recipient emails:     {len(multi_recipient)}")

    # What's the difference?
    print()
    print("HYPOTHESIS EXPLANATION:")
    print("=" * 60)
    print()
    print("The Admin Email Log shows 259 unique Message-IDs.")
    print("The Gmail SENT label query found 62 emails.")
    print()
    print("Key observations:")
    print(f"  1. {len(cloud_only)} emails appear ONLY from AWS IPs (not user-sent)")
    print(f"  2. {len(both)} emails appear from BOTH office AND AWS (OAuth forwarding)")
    print(f"  3. These AWS IPs are from Abnormal Security processing emails")
    print()

    if len(both) > 0:
        print("The 'overlap' emails (office + cloud) are:")
        print("  - Emails sent by Lori from the office")
        print("  - ALSO processed by Abnormal Security (OAuth app)")
        print()
        print("The 'cloud only' emails are likely:")
        print("  - Automated security scans")
        print("  - Forwarded copies for threat analysis")
        print("  - NOT actual user-sent emails")

if __name__ == '__main__':
    analyze('/home/robert/Downloads/lori-send.csv')
