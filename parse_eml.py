#!/usr/bin/env python3
"""
Parse .eml file and extract forensic headers.
No API keys, no OAuth, no bullshit.

Usage:
    python parse_eml.py email.eml
    python parse_eml.py  (scans current directory for .eml files)
"""

import sys
import email
from email import policy
from pathlib import Path


def parse_eml(file_path):
    """Parse an .eml file and extract headers."""
    with open(file_path, 'rb') as f:
        msg = email.message_from_binary_file(f, policy=policy.default)
    return msg


def print_forensic_analysis(msg, file_path):
    """Print forensic header analysis."""
    print("\n" + "="*80)
    print(f"FORENSIC EMAIL HEADER ANALYSIS")
    print(f"File: {file_path}")
    print("="*80)

    # Critical headers for BEC detection
    print("\n[CRITICAL - Reply Destination Headers]")
    print("-"*60)

    from_header = msg.get('From', 'NOT PRESENT')
    reply_to = msg.get('Reply-To', 'NOT PRESENT')
    return_path = msg.get('Return-Path', 'NOT PRESENT')
    sender = msg.get('Sender', 'NOT PRESENT')

    print(f"From:        {from_header}")
    print(f"Reply-To:    {reply_to}", end="")

    # FLAG THE BEC INDICATOR
    if reply_to != 'NOT PRESENT' and reply_to.lower() != from_header.lower():
        # Check for typosquatting
        print("\n" + "*"*60)
        print("*** WARNING: Reply-To DIFFERS from From! ***")
        print("*** This is a common BEC/phishing indicator ***")
        print("*"*60)
    else:
        print()

    print(f"Return-Path: {return_path}")
    print(f"Sender:      {sender}")

    # Check for lookalike domains
    if reply_to != 'NOT PRESENT':
        from_domain = from_header.split('@')[-1].rstrip('>').lower() if '@' in from_header else ''
        reply_domain = reply_to.split('@')[-1].rstrip('>').lower() if '@' in reply_to else ''

        if from_domain and reply_domain and from_domain != reply_domain:
            print(f"\n*** DOMAIN MISMATCH ***")
            print(f"    From domain:     {from_domain}")
            print(f"    Reply-To domain: {reply_domain}")

            # Check for typosquatting (similar but not identical)
            if len(from_domain) > 3 and len(reply_domain) > 3:
                # Simple Levenshtein-like check
                common = sum(1 for a, b in zip(from_domain, reply_domain) if a == b)
                similarity = common / max(len(from_domain), len(reply_domain))
                if similarity > 0.7:
                    print(f"    *** LIKELY TYPOSQUATTING - {similarity*100:.0f}% similar ***")

    # Message identification
    print("\n[Message Identification]")
    print("-"*60)
    print(f"Message-ID:  {msg.get('Message-ID', 'NOT PRESENT')}")
    print(f"Date:        {msg.get('Date', 'NOT PRESENT')}")
    print(f"Subject:     {msg.get('Subject', 'NOT PRESENT')}")

    # Routing
    print("\n[Routing]")
    print("-"*60)
    print(f"To:          {msg.get('To', 'NOT PRESENT')}")
    print(f"Cc:          {msg.get('Cc', 'NOT PRESENT')}")
    print(f"Delivered-To:{msg.get('Delivered-To', 'NOT PRESENT')}")

    # Authentication results
    print("\n[Authentication Results]")
    print("-"*60)
    auth_results = msg.get('Authentication-Results', 'NOT PRESENT')
    if auth_results != 'NOT PRESENT':
        # Parse out SPF, DKIM, DMARC results
        print(f"Authentication-Results:")
        for part in str(auth_results).split(';'):
            part = part.strip()
            if part:
                print(f"  {part}")
    else:
        print("Authentication-Results: NOT PRESENT")

    spf = msg.get('Received-SPF', 'NOT PRESENT')
    print(f"Received-SPF: {spf}")

    # X-headers that might indicate spoofing
    print("\n[Suspicious X-Headers]")
    print("-"*60)
    suspicious_headers = [
        'X-Original-From', 'X-Original-Sender', 'X-Original-To',
        'X-Originating-IP', 'X-Mailer', 'X-Source', 'X-Source-Args',
        'X-MS-Exchange-Organization-AuthSource',
        'X-MS-Exchange-Organization-AuthAs',
        'X-MS-Has-Attach', 'X-MS-TNEF-Correlator'
    ]
    for h in suspicious_headers:
        val = msg.get(h)
        if val:
            print(f"{h}: {val}")

    # Received headers (mail path)
    print("\n[Mail Path - Received Headers]")
    print("-"*60)
    received_headers = msg.get_all('Received', [])
    for i, r in enumerate(received_headers):
        print(f"\n[Hop {i+1}]")
        # Clean up formatting
        r_clean = ' '.join(str(r).split())
        print(r_clean[:500] + "..." if len(r_clean) > 500 else r_clean)

    # All headers
    print("\n" + "="*80)
    print("ALL HEADERS")
    print("="*80)
    for key, value in msg.items():
        val_str = str(value)
        if len(val_str) > 200:
            print(f"{key}: {val_str[:200]}...")
        else:
            print(f"{key}: {val_str}")

    # Save to file
    output_file = Path(file_path).stem + "_headers.txt"
    with open(output_file, 'w') as f:
        f.write(f"Forensic Analysis of: {file_path}\n")
        f.write("="*80 + "\n\n")
        for key, value in msg.items():
            f.write(f"{key}: {value}\n")
    print(f"\n[+] Full headers saved to: {output_file}")


def main():
    if len(sys.argv) > 1:
        eml_files = [Path(sys.argv[1])]
    else:
        # Find all .eml files in current directory
        eml_files = list(Path('.').glob('*.eml'))
        if not eml_files:
            print("Usage: python parse_eml.py <file.eml>")
            print("Or drop .eml files in current directory and run without args")
            return

    for eml_file in eml_files:
        if not eml_file.exists():
            print(f"[-] File not found: {eml_file}")
            continue

        try:
            msg = parse_eml(eml_file)
            print_forensic_analysis(msg, eml_file)
        except Exception as e:
            print(f"[-] Error parsing {eml_file}: {e}")
            import traceback
            traceback.print_exc()


if __name__ == '__main__':
    main()
