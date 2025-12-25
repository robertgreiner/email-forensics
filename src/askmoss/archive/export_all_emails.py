#!/usr/bin/env python3
"""
Export ALL emails from ssdhvac.com and ssdhvca.com with full headers and body.
Includes INBOX, SENT, TRASH, and ALL OTHER LOCATIONS.
Outputs to a single comprehensive file for evidence preservation.
"""

import os
import base64
import google.auth
from google.auth import iam
from google.auth.transport import requests as auth_requests
from google.oauth2 import service_account
from googleapiclient.discovery import build
from datetime import datetime
from email import policy
from email.parser import BytesParser

SERVICE_ACCOUNT_EMAIL = 'moss-service-account@hvac-labs.iam.gserviceaccount.com'
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

USERS_TO_SCAN = [
    'lori.maynard@askmoss.com',
    'madelin.martinez@askmoss.com',
]

DOMAINS_TO_EXPORT = ['ssdhvac.com', 'ssdhvca.com']

# Output to ../output/ directory (relative to src/)
OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'output')
OUTPUT_FILE = os.path.join(OUTPUT_DIR, 'all_emails_complete_export.txt')

def get_service(delegated_user):
    """Create Gmail API service with domain-wide delegation."""
    source_credentials, project = google.auth.default(scopes=['https://www.googleapis.com/auth/cloud-platform'])
    request = auth_requests.Request()
    signer = iam.Signer(request=request, credentials=source_credentials, service_account_email=SERVICE_ACCOUNT_EMAIL)
    delegated_credentials = service_account.Credentials(
        signer=signer,
        service_account_email=SERVICE_ACCOUNT_EMAIL,
        token_uri='https://oauth2.googleapis.com/token',
        scopes=SCOPES,
        subject=delegated_user
    )
    return build('gmail', 'v1', credentials=delegated_credentials)

def get_email_labels(service, msg_id):
    """Get the labels for an email to determine its location."""
    msg = service.users().messages().get(userId='me', id=msg_id, format='minimal').execute()
    label_ids = msg.get('labelIds', [])

    locations = []
    if 'INBOX' in label_ids:
        locations.append('INBOX')
    if 'SENT' in label_ids:
        locations.append('SENT')
    if 'TRASH' in label_ids:
        locations.append('TRASH')
    if 'SPAM' in label_ids:
        locations.append('SPAM')
    if 'DRAFT' in label_ids:
        locations.append('DRAFT')

    return locations if locations else ['ARCHIVE/OTHER']

def get_body_text(payload):
    """Extract body text from email payload."""
    body_text = ""

    if 'body' in payload and payload['body'].get('data'):
        try:
            body_text = base64.urlsafe_b64decode(payload['body']['data']).decode('utf-8', errors='replace')
        except:
            body_text = "[Could not decode body]"

    if 'parts' in payload:
        for part in payload['parts']:
            mime_type = part.get('mimeType', '')
            if mime_type == 'text/plain':
                if part.get('body', {}).get('data'):
                    try:
                        body_text += base64.urlsafe_b64decode(part['body']['data']).decode('utf-8', errors='replace')
                    except:
                        pass
            elif mime_type == 'text/html' and not body_text:
                if part.get('body', {}).get('data'):
                    try:
                        body_text += "\n[HTML Content]\n" + base64.urlsafe_b64decode(part['body']['data']).decode('utf-8', errors='replace')
                    except:
                        pass
            elif 'parts' in part:
                body_text += get_body_text(part)

    return body_text

def export_email(service, msg_id, f, email_num, location):
    """Export a single email with full headers and body."""
    # Get raw format for complete headers
    raw_msg = service.users().messages().get(userId='me', id=msg_id, format='raw').execute()
    raw_data = base64.urlsafe_b64decode(raw_msg['raw'])

    # Also get full format for easier body extraction
    full_msg = service.users().messages().get(userId='me', id=msg_id, format='full').execute()
    headers = {h['name']: h['value'] for h in full_msg['payload']['headers']}

    f.write(f"\n{'#'*80}\n")
    f.write(f"# EMAIL #{email_num}\n")
    f.write(f"# Message ID (Gmail): {msg_id}\n")
    f.write(f"# Location: {location}\n")
    f.write(f"{'#'*80}\n\n")

    # Write key headers summary
    f.write("="*60 + "\n")
    f.write("KEY HEADERS SUMMARY\n")
    f.write("="*60 + "\n")
    f.write(f"Location: {location}\n")
    f.write(f"Date: {headers.get('Date', 'N/A')}\n")
    f.write(f"From: {headers.get('From', 'N/A')}\n")
    f.write(f"To: {headers.get('To', 'N/A')}\n")
    f.write(f"Cc: {headers.get('Cc', 'N/A')}\n")
    f.write(f"Subject: {headers.get('Subject', 'N/A')}\n")
    f.write(f"Reply-To: {headers.get('Reply-To', 'NOT PRESENT')}\n")
    f.write(f"Return-Path: {headers.get('Return-Path', 'N/A')}\n")
    f.write(f"Message-ID: {headers.get('Message-ID', headers.get('Message-Id', 'N/A'))}\n")
    f.write(f"In-Reply-To: {headers.get('In-Reply-To', 'NOT PRESENT')}\n")
    f.write(f"References: {headers.get('References', 'NOT PRESENT')}\n")

    # DKIM info
    dkim_sig = headers.get('DKIM-Signature', '')
    dkim_domain = 'N/A'
    if dkim_sig and 'd=' in dkim_sig:
        dkim_domain = dkim_sig.split('d=')[1].split(';')[0].strip()
    f.write(f"DKIM Signing Domain: {dkim_domain}\n")
    f.write(f"X-OriginatorOrg: {headers.get('X-OriginatorOrg', 'N/A')}\n")
    f.write(f"X-MS-Exchange-CrossTenant-id: {headers.get('X-MS-Exchange-CrossTenant-id', 'N/A')}\n")

    # Classify email
    from_addr = headers.get('From', '').lower()
    if 'ssdhvca.com' in from_addr:
        f.write("Classification: *** FRAUDULENT (ssdhvca.com) ***\n")
    elif 'ssdhvac.com' in from_addr:
        f.write("Classification: LEGITIMATE (ssdhvac.com)\n")
    elif 'askmoss.com' in from_addr:
        f.write("Classification: OUTBOUND (Moss employee)\n")
    else:
        f.write("Classification: OTHER\n")

    # Write complete raw headers
    f.write("\n" + "="*60 + "\n")
    f.write("COMPLETE RAW HEADERS\n")
    f.write("="*60 + "\n")

    # Parse raw message to separate headers from body
    try:
        parsed = BytesParser(policy=policy.default).parsebytes(raw_data)
        for header_name, header_value in parsed.items():
            f.write(f"{header_name}: {header_value}\n")
    except Exception as e:
        f.write(f"[Error parsing headers: {e}]\n")
        # Fallback: write all headers from full format
        for h in full_msg['payload']['headers']:
            f.write(f"{h['name']}: {h['value']}\n")

    # Write body
    f.write("\n" + "="*60 + "\n")
    f.write("EMAIL BODY\n")
    f.write("="*60 + "\n")

    body = get_body_text(full_msg['payload'])
    if body:
        f.write(body)
    else:
        f.write("[No text body found or body is empty]\n")

    # Write attachments info
    attachments = []
    if 'parts' in full_msg['payload']:
        for part in full_msg['payload']['parts']:
            if part.get('filename'):
                attachments.append({
                    'filename': part['filename'],
                    'mimeType': part.get('mimeType', 'unknown'),
                    'size': part.get('body', {}).get('size', 0)
                })

    if attachments:
        f.write("\n" + "="*60 + "\n")
        f.write("ATTACHMENTS\n")
        f.write("="*60 + "\n")
        for att in attachments:
            f.write(f"  - {att['filename']} ({att['mimeType']}, {att['size']} bytes)\n")

    f.write("\n" + "-"*80 + "\n")
    f.write("END OF EMAIL #{}\n".format(email_num))
    f.write("-"*80 + "\n")

    return headers.get('From', ''), headers.get('Subject', ''), headers.get('Date', '')

def main():
    # Ensure output directory exists
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    print("="*80)
    print("EXPORTING ALL EMAILS - FULL HEADERS AND BODY")
    print("INCLUDING: INBOX, SENT, TRASH, SPAM, AND ALL LOCATIONS")
    print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Output file: {OUTPUT_FILE}")
    print("="*80)

    seen_message_ids = set()
    email_count = 0
    stats = {
        'inbox': 0,
        'sent': 0,
        'trash': 0,
        'spam': 0,
        'other': 0,
        'from_legit': 0,
        'from_fraud': 0,
        'to_legit': 0,
        'to_fraud': 0,
    }

    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write("="*80 + "\n")
        f.write("EMAIL FORENSICS - COMPLETE EMAIL EXPORT\n")
        f.write("INCLUDING ALL LOCATIONS: INBOX, SENT, TRASH, SPAM, ARCHIVE\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Domains: {', '.join(DOMAINS_TO_EXPORT)}\n")
        f.write(f"Users scanned: {', '.join(USERS_TO_SCAN)}\n")
        f.write("="*80 + "\n")

        for user in USERS_TO_SCAN:
            print(f"\nScanning: {user}")
            f.write(f"\n{'='*60}\n")
            f.write(f"USER: {user}\n")
            f.write(f"{'='*60}\n")

            try:
                service = get_service(user)
            except Exception as e:
                print(f"  ERROR connecting to {user}: {e}")
                continue

            for domain in DOMAINS_TO_EXPORT:
                # Use "in:anywhere" to search ALL locations including trash
                # This ensures we get emails from inbox, sent, trash, spam, etc.
                queries = [
                    (f'from:{domain}', f'FROM {domain}'),
                    (f'to:{domain}', f'TO {domain}'),
                    (f'in:trash from:{domain}', f'TRASH FROM {domain}'),
                    (f'in:trash to:{domain}', f'TRASH TO {domain}'),
                    (f'in:spam from:{domain}', f'SPAM FROM {domain}'),
                ]

                for query, label in queries:
                    print(f"  Query: {query}")

                    try:
                        results = service.users().messages().list(userId='me', q=query, maxResults=500).execute()
                        messages = results.get('messages', [])
                    except Exception as e:
                        print(f"    ERROR: {e}")
                        continue

                    if not messages:
                        print(f"    No messages found")
                        continue

                    print(f"    Found {len(messages)} messages")

                    for msg in messages:
                        msg_id = msg['id']

                        # Skip if we've already exported this message
                        if msg_id in seen_message_ids:
                            continue
                        seen_message_ids.add(msg_id)

                        # Get email location
                        locations = get_email_labels(service, msg_id)
                        location_str = ', '.join(locations)

                        # Update stats
                        for loc in locations:
                            if loc == 'INBOX':
                                stats['inbox'] += 1
                            elif loc == 'SENT':
                                stats['sent'] += 1
                            elif loc == 'TRASH':
                                stats['trash'] += 1
                            elif loc == 'SPAM':
                                stats['spam'] += 1
                            else:
                                stats['other'] += 1

                        email_count += 1
                        try:
                            from_addr, subject, date = export_email(service, msg_id, f, email_count, location_str)

                            # Update domain stats
                            if 'ssdhvac.com' in from_addr.lower():
                                stats['from_legit'] += 1
                            elif 'ssdhvca.com' in from_addr.lower():
                                stats['from_fraud'] += 1

                            loc_short = location_str[:10]
                            print(f"    Exported #{email_count} [{loc_short}]: {from_addr[:30]} - {subject[:25]}...")
                        except Exception as e:
                            print(f"    ERROR exporting {msg_id}: {e}")
                            f.write(f"\n[ERROR EXPORTING MESSAGE {msg_id}: {e}]\n")

        # Write summary at end
        f.write("\n\n" + "="*80 + "\n")
        f.write("EXPORT SUMMARY\n")
        f.write("="*80 + "\n")
        f.write(f"Total unique emails exported: {email_count}\n")
        f.write(f"Users scanned: {len(USERS_TO_SCAN)}\n")
        f.write(f"Domains searched: {', '.join(DOMAINS_TO_EXPORT)}\n")
        f.write(f"\nBy Location:\n")
        f.write(f"  - INBOX: {stats['inbox']}\n")
        f.write(f"  - SENT: {stats['sent']}\n")
        f.write(f"  - TRASH: {stats['trash']}\n")
        f.write(f"  - SPAM: {stats['spam']}\n")
        f.write(f"  - OTHER/ARCHIVE: {stats['other']}\n")
        f.write(f"\nBy Domain:\n")
        f.write(f"  - From ssdhvac.com (legitimate): {stats['from_legit']}\n")
        f.write(f"  - From ssdhvca.com (FRAUDULENT): {stats['from_fraud']}\n")
        f.write(f"\nExport completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    print(f"\n{'='*80}")
    print(f"EXPORT COMPLETE")
    print(f"{'='*80}")
    print(f"Total unique emails exported: {email_count}")
    print(f"\nBy Location:")
    print(f"  - INBOX: {stats['inbox']}")
    print(f"  - SENT: {stats['sent']}")
    print(f"  - TRASH: {stats['trash']}")
    print(f"  - SPAM: {stats['spam']}")
    print(f"  - OTHER: {stats['other']}")
    print(f"\nBy Domain:")
    print(f"  - From ssdhvac.com (legitimate): {stats['from_legit']}")
    print(f"  - From ssdhvca.com (FRAUDULENT): {stats['from_fraud']}")
    print(f"\nOutput saved to: {OUTPUT_FILE}")

if __name__ == '__main__':
    main()
