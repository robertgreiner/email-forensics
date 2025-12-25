#!/usr/bin/env python3
"""
Build complete attacker activity timeline from lori-all.csv.
Focus on Canadian VPS IP (158.51.123.14) activity Dec 4-15, 2025.
"""

import csv
from collections import defaultdict, Counter
from datetime import datetime

SUSPICIOUS_IP = '158.51.123.14'
ATTACKER_DOMAINS = {'ssdhvca.com', 'aksmoss.com', 'sshdvac.com'}

def main():
    filepath = '/home/robert/Downloads/lori-all.csv'

    print("=" * 80)
    print("ATTACKER ACTIVITY TIMELINE")
    print(f"IP: {SUSPICIOUS_IP} (GLOBALTELEHOST Corp, Canada)")
    print("=" * 80)

    all_events = []
    events_by_date = defaultdict(list)
    events_by_type = Counter()

    # Subjects accessed
    subjects_viewed = []
    subjects_sent = []
    subjects_deleted = []

    with open(filepath, 'r', errors='replace') as f:
        reader = csv.DictReader(f)
        for row in reader:
            ip = row.get('IP address', '')
            if ip != SUSPICIOUS_IP:
                continue

            event = row.get('Event', '')
            date = row.get('Date', '')
            subject = row.get('Subject', '')
            to_addr = row.get('To (Envelope)', '').lower()
            from_addr = row.get('From (Envelope)', '').lower()

            events_by_type[event] += 1

            evt_data = {
                'datetime': date,
                'event': event,
                'subject': subject,
                'from': from_addr,
                'to': to_addr
            }
            all_events.append(evt_data)

            if date:
                date_key = date[:10]
                events_by_date[date_key].append(evt_data)

            # Categorize by event type
            if event == 'View':
                subjects_viewed.append({'date': date, 'subject': subject})
            elif event == 'Send':
                subjects_sent.append({'date': date, 'subject': subject, 'to': to_addr})
            elif event == 'Delete':
                subjects_deleted.append({'date': date, 'subject': subject})

    # Summary
    print(f"\nTotal events: {len(all_events)}")
    print(f"Date range: {sorted(events_by_date.keys())[0]} to {sorted(events_by_date.keys())[-1]}")
    print(f"Total days active: {len(events_by_date)}")

    print("\n" + "-" * 80)
    print("EVENTS BY TYPE:")
    for evt, count in events_by_type.most_common():
        print(f"  {evt}: {count}")

    print("\n" + "-" * 80)
    print("DAILY ACTIVITY SUMMARY:")
    for date in sorted(events_by_date.keys()):
        evts = events_by_date[date]
        types = Counter(e['event'] for e in evts)
        type_str = ", ".join(f"{k}:{v}" for k, v in types.most_common())
        print(f"  {date}: {len(evts)} events ({type_str})")

    # CRITICAL: Emails sent to attacker domains
    print("\n" + "=" * 80)
    print("CRITICAL: EMAILS SENT TO ATTACKER-CONTROLLED DOMAINS")
    print("=" * 80)
    for evt in subjects_sent:
        is_attacker = any(d in evt['to'] for d in ATTACKER_DOMAINS)
        flag = " *** EXFILTRATION ***" if is_attacker else ""
        print(f"\n  Date: {evt['date']}")
        print(f"  To: {evt['to']}{flag}")
        print(f"  Subject: {evt['subject']}")

    # Deleted emails (covering tracks)
    print("\n" + "=" * 80)
    print("DELETED EMAILS (COVERING TRACKS)")
    print("=" * 80)
    for evt in subjects_deleted:
        print(f"\n  Date: {evt['date']}")
        print(f"  Subject: {evt['subject'][:80]}")

    # Security-related emails viewed
    print("\n" + "=" * 80)
    print("SECURITY-RELATED EMAILS VIEWED (checking if detected)")
    print("=" * 80)
    security_keywords = ['security', 'alert', 'password', 'login', 'sign-in', 'verification']
    for evt in subjects_viewed:
        if any(kw in evt['subject'].lower() for kw in security_keywords):
            print(f"  {evt['date'][:19]} - {evt['subject'][:70]}")

    # Financial/sensitive emails viewed
    print("\n" + "=" * 80)
    print("FINANCIAL/SENSITIVE EMAILS VIEWED (reconnaissance)")
    print("=" * 80)
    financial_keywords = ['invoice', 'payment', 'wire', 'bank', 'ach', 'transfer', 'account', 'routing']
    for evt in subjects_viewed:
        if any(kw in evt['subject'].lower() for kw in financial_keywords):
            print(f"  {evt['date'][:19]} - {evt['subject'][:70]}")

    # Sample of all viewed emails
    print("\n" + "=" * 80)
    print(f"SAMPLE OF EMAILS VIEWED (first 30 of {len(subjects_viewed)}):")
    print("=" * 80)
    for evt in subjects_viewed[:30]:
        print(f"  {evt['date'][:19]} - {evt['subject'][:65]}")


if __name__ == '__main__':
    main()
