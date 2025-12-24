#!/usr/bin/env python3
"""
Comprehensive IP audit - don't just look at volume, look at behavior.
Find ALL suspicious activity regardless of IP event count.
"""

import csv
from collections import defaultdict, Counter

# Known legitimate IPs
OFFICE_IP = '199.200.88.186'
KNOWN_LEGITIMATE = {
    '199.200.88.186',  # Office
    '138.199.114.2',   # Confirmed legitimate (Aug-Oct only)
}

# Known attacker domains
ATTACKER_DOMAINS = {'ssdhvca.com', 'aksmoss.com', 'sshdvac.com'}

# High-risk event types
HIGH_RISK_EVENTS = {'Send', 'Delete', 'Forward', 'Draft'}

def main():
    filepath = '/home/robert/Downloads/lori-all.csv'

    print("=" * 80)
    print("COMPREHENSIVE IP AUDIT - BEHAVIOR-BASED ANALYSIS")
    print("=" * 80)

    # Track everything by IP
    ip_events = defaultdict(list)
    ip_sends_to_attacker = defaultdict(list)
    ip_deletes = defaultdict(list)
    ip_sends = defaultdict(list)
    ip_drafts = defaultdict(list)
    ip_forwards = defaultdict(list)

    # Track all sends to attacker domains regardless of IP
    all_attacker_sends = []

    with open(filepath, 'r', errors='replace') as f:
        reader = csv.DictReader(f)
        for row in reader:
            ip = row.get('IP address', '')
            if not ip:
                continue

            event = row.get('Event', '')
            date = row.get('Date', '')
            subject = row.get('Subject', '')
            to_addr = row.get('To (Envelope)', '').lower()
            from_addr = row.get('From (Envelope)', '').lower()

            # Track all events by IP
            ip_events[ip].append({
                'date': date,
                'event': event,
                'subject': subject,
                'to': to_addr,
                'from': from_addr
            })

            # Check for sends to attacker domains
            if event == 'Send':
                ip_sends[ip].append({'date': date, 'to': to_addr, 'subject': subject})
                for domain in ATTACKER_DOMAINS:
                    if domain in to_addr:
                        ip_sends_to_attacker[ip].append({
                            'date': date, 'to': to_addr, 'subject': subject
                        })
                        all_attacker_sends.append({
                            'ip': ip, 'date': date, 'to': to_addr, 'subject': subject
                        })

            # Track deletes
            if event == 'Delete':
                ip_deletes[ip].append({'date': date, 'subject': subject})

            # Track drafts
            if event == 'Draft':
                ip_drafts[ip].append({'date': date, 'to': to_addr, 'subject': subject})

            # Track forwards
            if 'Forward' in event or 'Fwd' in event:
                ip_forwards[ip].append({'date': date, 'to': to_addr, 'subject': subject})

    # ============================================================
    # CRITICAL: All sends to attacker domains
    # ============================================================
    print("\n" + "=" * 80)
    print("CRITICAL: ALL EMAILS SENT TO ATTACKER DOMAINS")
    print("=" * 80)
    if all_attacker_sends:
        for send in sorted(all_attacker_sends, key=lambda x: x['date']):
            print(f"\n  IP: {send['ip']}")
            print(f"  Date: {send['date']}")
            print(f"  To: {send['to']}")
            print(f"  Subject: {send['subject'][:60]}")
    else:
        print("  None found")

    # ============================================================
    # All IPs that performed Delete events
    # ============================================================
    print("\n" + "=" * 80)
    print("ALL IPs THAT PERFORMED DELETE EVENTS")
    print("=" * 80)
    for ip in sorted(ip_deletes.keys(), key=lambda x: len(ip_deletes[x]), reverse=True):
        deletes = ip_deletes[ip]
        is_legit = ip in KNOWN_LEGITIMATE or ip.startswith('199.200.')
        flag = "" if is_legit else " *** SUSPICIOUS ***"
        print(f"\n  {ip}: {len(deletes)} deletes{flag}")

        # Show December deletes specifically
        dec_deletes = [d for d in deletes if d['date'].startswith('2025-12')]
        if dec_deletes and not is_legit:
            print(f"    December deletes: {len(dec_deletes)}")
            for d in dec_deletes[:5]:
                print(f"      {d['date'][:19]} - {d['subject'][:50]}")

    # ============================================================
    # All IPs that sent emails (excluding office)
    # ============================================================
    print("\n" + "=" * 80)
    print("ALL IPs THAT SENT EMAILS (non-office)")
    print("=" * 80)
    for ip in sorted(ip_sends.keys(), key=lambda x: len(ip_sends[x]), reverse=True):
        if ip in KNOWN_LEGITIMATE or ip.startswith('199.200.'):
            continue

        sends = ip_sends[ip]
        print(f"\n  {ip}: {len(sends)} sends")

        # Check for December sends
        dec_sends = [s for s in sends if s['date'].startswith('2025-12')]
        if dec_sends:
            print(f"    December sends: {len(dec_sends)}")
            for s in dec_sends[:5]:
                to_flag = ""
                for domain in ATTACKER_DOMAINS:
                    if domain in s['to']:
                        to_flag = " *** ATTACKER DOMAIN ***"
                print(f"      {s['date'][:19]} -> {s['to'][:40]}{to_flag}")

    # ============================================================
    # Unknown/suspicious IPs with any December activity
    # ============================================================
    print("\n" + "=" * 80)
    print("ALL UNKNOWN IPs WITH DECEMBER ACTIVITY")
    print("=" * 80)

    for ip in sorted(ip_events.keys()):
        # Skip known legitimate
        if ip in KNOWN_LEGITIMATE or ip.startswith('199.200.'):
            continue

        # Skip IPv6 (likely mobile)
        if ':' in ip:
            continue

        events = ip_events[ip]
        dec_events = [e for e in events if e['date'].startswith('2025-12')]

        if dec_events:
            event_types = Counter(e['event'] for e in dec_events)
            print(f"\n  {ip}")
            print(f"    Total events: {len(events)}, December: {len(dec_events)}")
            print(f"    December event types: {dict(event_types.most_common(5))}")

            # Date range
            dates = sorted(set(e['date'][:10] for e in dec_events))
            print(f"    Active dates: {dates[0]} to {dates[-1]} ({len(dates)} days)")

    # ============================================================
    # Check for any drafts to attacker domains
    # ============================================================
    print("\n" + "=" * 80)
    print("DRAFTS TO ATTACKER DOMAINS (potential unsent exfiltration)")
    print("=" * 80)
    found_any = False
    for ip, drafts in ip_drafts.items():
        for draft in drafts:
            for domain in ATTACKER_DOMAINS:
                if domain in draft['to']:
                    found_any = True
                    print(f"\n  IP: {ip}")
                    print(f"  Date: {draft['date']}")
                    print(f"  To: {draft['to']}")
                    print(f"  Subject: {draft['subject'][:60]}")
    if not found_any:
        print("  None found")

    # ============================================================
    # Summary of all unique IPs
    # ============================================================
    print("\n" + "=" * 80)
    print("SUMMARY: ALL UNIQUE IPs IN LOGS")
    print("=" * 80)

    all_ips = sorted(ip_events.keys(), key=lambda x: len(ip_events[x]), reverse=True)
    print(f"Total unique IPs: {len(all_ips)}")

    print("\nTop 20 by event count:")
    for ip in all_ips[:20]:
        count = len(ip_events[ip])
        label = ""
        if ip == OFFICE_IP:
            label = " [OFFICE]"
        elif ip in KNOWN_LEGITIMATE:
            label = " [KNOWN LEGIT]"
        elif ':' in ip:
            label = " [IPv6/Mobile]"

        # Check for suspicious activity
        if ip in ip_sends_to_attacker:
            label += " [SENT TO ATTACKER]"
        if ip in ip_deletes and ip not in KNOWN_LEGITIMATE:
            dec_del = [d for d in ip_deletes[ip] if d['date'].startswith('2025-12')]
            if dec_del:
                label += f" [DEC DELETES: {len(dec_del)}]"

        print(f"  {ip}: {count:,} events{label}")


if __name__ == '__main__':
    main()
