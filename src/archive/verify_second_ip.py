#!/usr/bin/env python3
"""
Verify that 138.199.114.2 (second highest IP) is legitimate.
"""

import csv
from collections import Counter

SECOND_IP = '138.199.114.2'

def main():
    filepath = '/home/robert/Downloads/lori-all.csv'

    print(f"Verifying IP: {SECOND_IP}")
    print("=" * 60)

    events_by_date = Counter()
    events_by_type = Counter()

    with open(filepath, 'r', errors='replace') as f:
        reader = csv.DictReader(f)
        for row in reader:
            ip = row.get('IP address', '')
            if ip != SECOND_IP:
                continue

            date = row.get('Date', '')[:10] if row.get('Date') else ''
            event = row.get('Event', '')

            if date:
                events_by_date[date] += 1
            events_by_type[event] += 1

    print(f"\nTotal events: {sum(events_by_date.values())}")

    # Date range
    sorted_dates = sorted(events_by_date.keys())
    print(f"Date range: {sorted_dates[0]} to {sorted_dates[-1]}")

    # Check if any December activity
    dec_activity = [d for d in sorted_dates if d.startswith('2025-12')]
    print(f"\nDecember activity: {len(dec_activity)} days")
    if dec_activity:
        print("  WARNING: This IP was active in December!")
        for d in dec_activity:
            print(f"    {d}: {events_by_date[d]} events")
    else:
        print("  CLEAR: No December activity - likely legitimate")

    # Event types
    print("\nEvent types:")
    for evt, count in events_by_type.most_common(10):
        print(f"  {evt}: {count}")

    # Show activity pattern
    print("\nMonthly breakdown:")
    monthly = Counter()
    for d in sorted_dates:
        month = d[:7]
        monthly[month] += events_by_date[d]

    for month in sorted(monthly.keys()):
        print(f"  {month}: {monthly[month]} events")

if __name__ == '__main__':
    main()
