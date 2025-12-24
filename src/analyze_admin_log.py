#!/usr/bin/env python3
"""
Analyze Admin Email Log Search export CSV.
"""

import csv
from datetime import datetime
from collections import defaultdict

def analyze_csv(filepath):
    """Analyze the admin email log CSV."""

    message_ids = set()
    messages_by_date = defaultdict(set)
    recipients_by_domain = defaultdict(list)
    all_rows = []

    with open(filepath, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            all_rows.append(row)
            msg_id = row.get('Message ID', '')
            date_str = row.get('Date', '')
            to_envelope = row.get('To (Envelope)', '')
            subject = row.get('Subject', '')
            ip = row.get('IP address', '')

            if msg_id:
                message_ids.add(msg_id)

                # Parse date
                if date_str:
                    try:
                        # Format: 2025-12-17T16:26:01-06:00
                        dt = datetime.fromisoformat(date_str)
                        date_only = dt.strftime('%Y-%m-%d')
                        messages_by_date[date_only].add(msg_id)
                    except:
                        pass

                # Track recipient domains
                if to_envelope and '@' in to_envelope:
                    domain = to_envelope.split('@')[1].lower()
                    recipients_by_domain[domain].append({
                        'date': date_str,
                        'to': to_envelope,
                        'subject': subject,
                        'msg_id': msg_id,
                        'ip': ip
                    })

    print(f"Total rows in CSV: {len(all_rows)}")
    print(f"Unique Message-IDs: {len(message_ids)}")
    print()

    # Date range
    dates = sorted(messages_by_date.keys())
    if dates:
        print(f"Date range: {dates[0]} to {dates[-1]}")
        print()

    # Emails per day
    print("Emails per day:")
    for date in sorted(messages_by_date.keys()):
        print(f"  {date}: {len(messages_by_date[date])} unique emails")
    print()

    # Count emails in Dec 1-17 window
    dec1_17_count = 0
    for date, msgs in messages_by_date.items():
        if date >= '2025-12-01' and date <= '2025-12-17':
            dec1_17_count += len(msgs)
    print(f"Total unique emails Dec 1-17: {dec1_17_count}")
    print()

    # Recipient domains (top 15)
    print("Top recipient domains:")
    domain_counts = [(d, len(set(r['msg_id'] for r in recs))) for d, recs in recipients_by_domain.items()]
    for domain, count in sorted(domain_counts, key=lambda x: -x[1])[:15]:
        print(f"  {domain}: {count} unique emails")
    print()

    # Check for suspicious domains
    suspicious = ['ssdhvca.com', 'aksmoss.com', 'sshdvac.com']
    print("Emails to attacker domains:")
    for domain in suspicious:
        if domain in recipients_by_domain:
            print(f"\n  {domain}:")
            for rec in recipients_by_domain[domain]:
                print(f"    [{rec['date'][:10]}] To: {rec['to']}")
                print(f"      Subject: {rec['subject']}")
                print(f"      IP: {rec['ip']}")
        else:
            print(f"  {domain}: 0 emails")

if __name__ == '__main__':
    analyze_csv('/home/robert/Downloads/lori-send.csv')
