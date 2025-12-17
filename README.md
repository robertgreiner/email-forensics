# Email Forensics Toolkit

A collection of Python scripts for investigating Business Email Compromise (BEC) attacks using the Gmail API with Google Workspace domain-wide delegation.

## Overview

This toolkit was developed to investigate a BEC attack where an attacker:
1. Registered a lookalike domain (ssdhvca.com vs legitimate ssdhvac.com)
2. Compromised the vendor's email (read access) to obtain Message-IDs
3. Inserted themselves into an existing email thread
4. Impersonated a vendor to redirect payments

The scripts analyze email headers to determine the attack vector and identify whether the compromise originated from the victim's side or the vendor's side.

## Directory Structure

```
email-forensics/
├── src/                    # Source code
│   ├── export_all_emails.py       # Complete email export (headers + body)
│   ├── comprehensive_review.py    # 30-day review with anomaly detection
│   ├── analyze_thread_flow.py     # Thread flow analysis
│   ├── analyze_sent.py            # Sent folder analysis
│   ├── analyze_madelin.py         # Secondary user analysis
│   ├── get_email_headers.py       # Header extraction script
│   └── parse_eml.py               # EML file parser
│
├── output/                 # Program output (raw data)
│   ├── all_emails_complete_export.txt  # Full export (3.3MB, 208 emails)
│   └── comprehensive_review_output.txt # Anomaly detection results
│
├── reports/                # Reports for sharing
│   └── findings.md         # Complete forensic investigation report
│
├── venv/                   # Python virtual environment
├── README.md               # This file
├── requirements.txt        # Python dependencies
└── .env                    # Configuration (not in git)
```

## Prerequisites

- Python 3.8+
- Google Cloud project with Gmail API enabled
- Service account with domain-wide delegation configured
- Google Workspace admin access to configure delegation

## Setup

### 1. Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### 2. Install Dependencies

```bash
pip install google-auth google-auth-oauthlib google-api-python-client
```

### 3. Configure Service Account

You have two options for authentication:

#### Option A: Service Account Key File (if allowed by org policy)
```bash
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account-key.json
```

#### Option B: Application Default Credentials with Impersonation (recommended)
```bash
# Grant yourself Token Creator role on the service account
gcloud iam service-accounts add-iam-policy-binding SERVICE_ACCOUNT_EMAIL \
    --member="user:YOUR_EMAIL" \
    --role="roles/iam.serviceAccountTokenCreator" \
    --project=YOUR_PROJECT

# Grant service account Token Creator role on itself (for signBlob)
gcloud iam service-accounts add-iam-policy-binding SERVICE_ACCOUNT_EMAIL \
    --member="serviceAccount:SERVICE_ACCOUNT_EMAIL" \
    --role="roles/iam.serviceAccountTokenCreator" \
    --project=YOUR_PROJECT

# Authenticate with impersonation
gcloud auth application-default login --impersonate-service-account=SERVICE_ACCOUNT_EMAIL
```

### 4. Configure Domain-Wide Delegation

1. Go to Google Admin Console: https://admin.google.com
2. Navigate to: Security → Access and data control → API controls → Manage Domain Wide Delegation
3. Add the service account client ID with scope: `https://www.googleapis.com/auth/gmail.readonly`

## Scripts

### export_all_emails.py (Primary Export Tool)

Exports ALL emails with full headers and body content, including INBOX, SENT, TRASH, and SPAM.

**Usage:**
```bash
cd src
python export_all_emails.py
```

**Output:** `output/all_emails_complete_export.txt`

**Features:**
- Exports from multiple user mailboxes
- Includes ALL locations (INBOX, SENT, TRASH, SPAM, ARCHIVE)
- Full RFC 2822 headers
- Email body (text and HTML)
- Attachment listing
- Classification (LEGITIMATE vs FRAUDULENT)
- Location tracking for each email

### comprehensive_review.py

Performs anomaly detection across all emails from specified domains.

**Checks for:**
- Reply-To header poisoning
- DKIM domain mismatches
- Suspicious patterns

**Usage:**
```bash
python src/comprehensive_review.py
```

### analyze_thread_flow.py

Analyzes email threading to determine who initiated contact and trace the conversation flow.

**Usage:**
```bash
python src/analyze_thread_flow.py
```

## Key Findings from This Investigation

| Metric | Count |
|--------|-------|
| Total emails exported | 208 |
| From ssdhvac.com (legitimate) | 77 |
| From ssdhvca.com (FRAUDULENT) | 21 unique |
| Emails in TRASH | 40 |
| Emails with Reply-To header | 0 |

### Data Completeness Verification

Fraudulent email capture was **verified against Google Workspace Admin Email Log Search**:
- Admin log search: 21 unique Message-IDs from ssdhvca.com
- Our export: 21 unique Message-IDs from ssdhvca.com
- **Result: 100% MATCH** - Every fraudulent email ever sent to askmoss.com was captured

### Conclusions

1. **No Reply-To Poisoning** - All 77 legitimate emails had NO Reply-To header
2. **Attack Vector Identified** - Lookalike domain + external M365 tenant (warehouseathletics.onmicrosoft.com)
3. **Compromise Location** - Standard Supply (vendor) had read-access compromise, NOT the victim organization
4. **Evidence** - Attacker knew Message-IDs from victim's emails, only possible if they could read vendor's inbox
5. **13 fraudulent emails were in TRASH** - Discovered after victim identified the fraud

## Investigation Methodology

### Hypotheses Tested

| # | Hypothesis | Verdict |
|---|------------|---------|
| 1 | Reply-To Poisoning | ❌ REFUTED |
| 2 | Moss (Victim) Compromise | ❌ REFUTED |
| 3 | Standard Supply Read-Access Compromise | ✅ CONFIRMED |
| 4 | Man-in-the-Middle | ❌ UNLIKELY |
| 5 | Social Engineering Only | ❌ RULED OUT |

### Headers Analyzed

| Header | Purpose |
|--------|---------|
| `From` | Sender identification |
| `Reply-To` | Detect poisoning attacks |
| `Return-Path` | Envelope sender verification |
| `Message-ID` | Identify originating mail server |
| `In-Reply-To` | Thread relationship analysis |
| `DKIM-Signature` | Signing domain verification |
| `X-OriginatorOrg` | M365 organization identifier |
| `X-MS-Exchange-CrossTenant-id` | M365 tenant UUID |

## Attacker Infrastructure

| Attribute | Value |
|-----------|-------|
| Fraudulent Domain | ssdhvca.com |
| M365 Tenant | warehouseathletics.onmicrosoft.com |
| Tenant ID | 4b0f3443-6891-4079-a2a5-de733068808c |
| Mail Server | BYAPR13MB2743.namprd13.prod.outlook.com |

## Security Considerations

- Scripts only require `gmail.readonly` scope - no write access
- Service account credentials should be protected
- Audit logs are generated for all API access
- Consider data handling policies when analyzing email content

## Reports

The main forensic report is located at `reports/findings.md` and includes:
- Executive summary
- Investigation methodology
- Hypotheses tested with evidence
- Complete email inventories
- Attack timeline
- Counter-arguments addressed
- Investigation guide for the vendor

## License

Internal use only. Contains investigation-specific configurations.
