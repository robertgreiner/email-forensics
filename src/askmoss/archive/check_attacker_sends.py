#!/usr/bin/env python3
"""
Check ALL emails sent from attacker IPs - did they only exfiltrate,
or did they impersonate Lori to send to third parties?
"""

import csv
from collections import defaultdict

ATTACKER_IPS = {
    '147.124.205.9',   # Tier.Net - Dec 4
    '158.51.123.14',   # Canadian VPS - Dec 4-15
}

ATTACKER_DOMAINS = {'ssdhvca.com', 'aksmoss.com', 'sshdvac.com'}

def main():
    filepath = '/home/robert/Downloads/lori-all.csv'

    print("=" * 80)
    print("ALL EMAILS SENT FROM ATTACKER IPs")
    print("Question: Did they impersonate Lori or only exfiltrate?")
    print("=" * 80)

    sends_to_attacker = []
    sends_to_others = []

    with open(filepath, 'r', errors='replace') as f:
        reader = csv.DictReader(f)
        for row in reader:
            ip = row.get('IP address', '')
            if ip not in ATTACKER_IPS:
                continue

            event = row.get('Event', '')
            if event != 'Send':
                continue

            date = row.get('Date', '')
            to_addr = row.get('To (Envelope)', '').lower()
            subject = row.get('Subject', '')

            is_attacker_domain = any(d in to_addr for d in ATTACKER_DOMAINS)

            entry = {
                'ip': ip,
                'date': date,
                'to': to_addr,
                'subject': subject
            }

            if is_attacker_domain:
                sends_to_attacker.append(entry)
            else:
                sends_to_others.append(entry)

    # Summary
    print(f"\nTotal sends from attacker IPs: {len(sends_to_attacker) + len(sends_to_others)}")
    print(f"  - To attacker domains (exfiltration): {len(sends_to_attacker)}")
    print(f"  - To OTHER recipients (impersonation): {len(sends_to_others)}")

    print("\n" + "=" * 80)
    print("SENDS TO ATTACKER DOMAINS (exfiltration):")
    print("=" * 80)
    for s in sends_to_attacker:
        print(f"\n  IP: {s['ip']}")
        print(f"  Date: {s['date']}")
        print(f"  To: {s['to']}")
        print(f"  Subject: {s['subject'][:60]}")

    print("\n" + "=" * 80)
    print("SENDS TO OTHER RECIPIENTS (potential impersonation/fraud):")
    print("=" * 80)
    if sends_to_others:
        for s in sends_to_others:
            print(f"\n  IP: {s['ip']}")
            print(f"  Date: {s['date']}")
            print(f"  To: {s['to']}")
            print(f"  Subject: {s['subject'][:60]}")
    else:
        print("\n  *** NONE - Attacker only sent to their own domains ***")

    # Conclusion
    print("\n" + "=" * 80)
    print("CONCLUSION:")
    print("=" * 80)
    if sends_to_others:
        print(f"  ATTACKER IMPERSONATED LORI - sent {len(sends_to_others)} emails to third parties")
    else:
        print("  EXFILTRATION ONLY - attacker did NOT impersonate Lori")
        print("  All emails from attacker IPs went to attacker-controlled domains")


if __name__ == '__main__':
    main()
