#!/usr/bin/env python3
"""
Extract all domains from email logs and look for potential typosquats/fakes.
"""

import csv
import re
from collections import Counter, defaultdict
from difflib import SequenceMatcher

def extract_domain(email):
    """Extract domain from email address."""
    if not email or '@' not in email:
        return None
    return email.split('@')[-1].lower().strip()

def similar(a, b):
    """Return similarity ratio between two strings."""
    return SequenceMatcher(None, a, b).ratio()

def find_similar_domains(domains):
    """Find domains that look like typosquats of each other."""
    domain_list = list(domains)
    similar_pairs = []

    for i, d1 in enumerate(domain_list):
        for d2 in domain_list[i+1:]:
            # Skip if same domain
            if d1 == d2:
                continue
            # Skip common domains
            if d1 in ['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com']:
                continue
            if d2 in ['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com']:
                continue

            ratio = similar(d1, d2)
            if ratio > 0.7 and ratio < 1.0:  # Similar but not identical
                similar_pairs.append((d1, d2, ratio))

    return sorted(similar_pairs, key=lambda x: x[2], reverse=True)

def main():
    filepath = '/home/robert/Downloads/lori-all.csv'

    print("=" * 80)
    print("DOMAIN EXTRACTION AND TYPOSQUAT ANALYSIS")
    print("=" * 80)

    from_domains = Counter()
    to_domains = Counter()
    all_domains = set()

    # Track which IPs sent to/from each domain
    domain_ips = defaultdict(set)

    with open(filepath, 'r', errors='replace') as f:
        reader = csv.DictReader(f)
        for row in reader:
            from_addr = row.get('From (Envelope)', '').lower()
            to_addr = row.get('To (Envelope)', '').lower()
            ip = row.get('IP address', '')

            from_domain = extract_domain(from_addr)
            to_domain = extract_domain(to_addr)

            if from_domain:
                from_domains[from_domain] += 1
                all_domains.add(from_domain)
                if ip:
                    domain_ips[from_domain].add(ip)

            if to_domain:
                to_domains[to_domain] += 1
                all_domains.add(to_domain)
                if ip:
                    domain_ips[to_domain].add(ip)

    print(f"\nTotal unique domains: {len(all_domains)}")

    # Known attacker domains
    KNOWN_ATTACKER = {'ssdhvca.com', 'aksmoss.com', 'sshdvac.com'}

    # Known legitimate Moss domains
    KNOWN_MOSS = {'askmoss.com', 'mossmechanical.com', 'mossutilities.com'}

    # Known legitimate Standard Supply
    KNOWN_SSDHVAC = {'ssdhvac.com'}

    print("\n" + "=" * 80)
    print("KNOWN ATTACKER DOMAINS FOUND:")
    print("=" * 80)
    for domain in KNOWN_ATTACKER:
        if domain in all_domains:
            from_count = from_domains.get(domain, 0)
            to_count = to_domains.get(domain, 0)
            print(f"  {domain}: From={from_count}, To={to_count}")

    print("\n" + "=" * 80)
    print("POTENTIAL TYPOSQUATS (similar domain pairs):")
    print("=" * 80)
    similar_pairs = find_similar_domains(all_domains)

    if similar_pairs:
        for d1, d2, ratio in similar_pairs[:30]:
            flag = ""
            if d1 in KNOWN_ATTACKER or d2 in KNOWN_ATTACKER:
                flag = " *** KNOWN ATTACKER ***"
            print(f"\n  {d1} <-> {d2}")
            print(f"    Similarity: {ratio:.1%}{flag}")
            print(f"    {d1}: From={from_domains.get(d1, 0)}, To={to_domains.get(d1, 0)}")
            print(f"    {d2}: From={from_domains.get(d2, 0)}, To={to_domains.get(d2, 0)}")

    print("\n" + "=" * 80)
    print("ALL EXTERNAL DOMAINS (excluding common providers):")
    print("=" * 80)

    # Common email providers to exclude
    COMMON = {
        'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com',
        'googlemail.com', 'icloud.com', 'aol.com', 'msn.com',
        'live.com', 'me.com', 'mail.com', 'protonmail.com',
        'google.com', 'amazonses.com'
    }

    # Also exclude Google/AWS infrastructure
    INFRASTRUCTURE = {d for d in all_domains if
                      'google' in d or 'amazon' in d or 'aws' in d or
                      d.endswith('.gserviceaccount.com')}

    external = []
    for domain in all_domains:
        if domain in COMMON or domain in INFRASTRUCTURE:
            continue
        if domain in KNOWN_MOSS:
            continue

        total = from_domains.get(domain, 0) + to_domains.get(domain, 0)
        external.append({
            'domain': domain,
            'from': from_domains.get(domain, 0),
            'to': to_domains.get(domain, 0),
            'total': total,
            'is_attacker': domain in KNOWN_ATTACKER
        })

    # Sort by total count
    external.sort(key=lambda x: x['total'], reverse=True)

    print(f"\nTotal external domains: {len(external)}")
    print("\nTop 50 by activity:")
    for e in external[:50]:
        flag = " *** ATTACKER ***" if e['is_attacker'] else ""
        print(f"  {e['domain']}: From={e['from']}, To={e['to']}{flag}")

    # Look for suspicious patterns
    print("\n" + "=" * 80)
    print("SUSPICIOUS PATTERNS TO CHECK:")
    print("=" * 80)

    suspicious = []
    for e in external:
        domain = e['domain']
        # Check for patterns
        issues = []

        # Recently registered TLDs often used for fraud
        if domain.endswith('.xyz') or domain.endswith('.top') or domain.endswith('.click'):
            issues.append("suspicious TLD")

        # Very short domains
        if len(domain.split('.')[0]) <= 3:
            issues.append("very short name")

        # Contains 'moss' or 'ssdhvac' variants
        if 'moss' in domain and domain not in KNOWN_MOSS and domain not in KNOWN_ATTACKER:
            issues.append("contains 'moss'")
        if 'ssd' in domain or 'hvac' in domain:
            if domain not in KNOWN_SSDHVAC and domain not in KNOWN_ATTACKER:
                issues.append("similar to ssdhvac")

        # Only received from (never sent to) - could be spoofed
        if e['from'] > 0 and e['to'] == 0 and e['from'] < 10:
            issues.append("only inbound, low volume")

        if issues:
            suspicious.append({**e, 'issues': issues})

    if suspicious:
        for s in suspicious[:20]:
            print(f"\n  {s['domain']}")
            print(f"    Issues: {', '.join(s['issues'])}")
            print(f"    From={s['from']}, To={s['to']}")
    else:
        print("  None found beyond known attacker domains")


if __name__ == '__main__':
    main()
