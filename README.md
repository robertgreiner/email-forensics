# Email Forensics Toolkit

A collection of Python scripts for investigating Business Email Compromise (BEC) attacks using the Gmail API with Google Workspace domain-wide delegation.

## Overview

This toolkit was developed to investigate a BEC attack where an attacker:
1. Registered a lookalike domain (ssdhvca.com vs legitimate ssdhvac.com)
2. Inserted themselves into an existing email thread
3. Impersonated a vendor to redirect payments

The scripts analyze email headers to determine the attack vector and identify whether the compromise originated from the victim's side or the vendor's side.

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

### get_email_headers.py

Retrieves and analyzes email headers for a specific user, searching for emails from specified domains.

**Configuration:** Edit the script to set:
- `SERVICE_ACCOUNT_EMAIL` - Your service account email
- `DELEGATED_USER` - The user's mailbox to access
- `SCOPES` - Gmail API scopes

**Usage:**
```bash
python get_email_headers.py
```

### comprehensive_review.py

Performs a comprehensive 30-day review of all emails from/to specified domains across multiple users. Checks for:
- Reply-To header poisoning
- DKIM domain mismatches
- Anomalous email patterns

**Configuration:** Edit the script to set:
- `SERVICE_ACCOUNT_EMAIL` - Your service account email
- `USERS_TO_SCAN` - List of user emails to analyze
- `LEGITIMATE_DOMAIN` - The real vendor domain
- `FRAUDULENT_DOMAIN` - The lookalike/attacker domain

**Usage:**
```bash
python comprehensive_review.py
```

**Output:**
- Summary of emails analyzed
- Anomaly detection results
- Reply-To header analysis
- Detailed email inventory
- Final verdict on compromise

### analyze_sent.py

Analyzes a user's sent folder to determine if they sent emails to the fraudulent domain (indicating they were fooled by the attack).

**Usage:**
```bash
python analyze_sent.py
```

### analyze_madelin.py

Analyzes a secondary user's mailbox (useful for checking if multiple employees were targeted).

**Usage:**
```bash
python analyze_madelin.py
```

## Output Files

- `findings.md` - Comprehensive forensic investigation report
- `comprehensive_review_output.txt` - Raw output from comprehensive review
- `email_headers_*.txt` - Individual email header dumps

## Key Findings from This Investigation

The toolkit helped determine:

1. **No Reply-To Poisoning** - All 63+ legitimate emails had no Reply-To header
2. **Attack Vector Identified** - Lookalike domain + external M365 tenant (warehouseathletics.onmicrosoft.com)
3. **Compromise Location** - Standard Supply (vendor) had read-access compromise, NOT the victim organization
4. **Evidence** - Attacker knew Message-IDs from victim's emails, only possible if they could read vendor's inbox

## Investigation Methodology

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

### Hypotheses Tested

1. **Reply-To Poisoning** - ❌ Refuted (no Reply-To headers found)
2. **Victim Compromise** - ❌ Refuted (attack required external infrastructure)
3. **Vendor Read-Access Compromise** - ✅ Confirmed (attacker knew victim's Message-IDs)
4. **Man-in-the-Middle** - ❌ Unlikely (TLS verified, no interception evidence)
5. **Social Engineering Only** - ❌ Ruled out (too precise, knew internal Message-IDs)

## Security Considerations

- Scripts only require `gmail.readonly` scope - no write access
- Service account credentials should be protected
- Audit logs are generated for all API access
- Consider data handling policies when analyzing email content

## License

Internal use only. Contains investigation-specific configurations.

## Contributing

This toolkit was developed for a specific investigation. To adapt for other investigations:

1. Update domain names in scripts
2. Update user email lists
3. Modify search queries as needed
4. Adjust date ranges for relevant timeframe
