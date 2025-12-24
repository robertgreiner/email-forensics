# Technical Analysis for Standard Supply

**Prepared by:** Robert, Moss Mechanical IT
**Date:** December 16, 2025
**Status:** Ready to share if requested

---

## Purpose

This document provides a detailed technical analysis of the BEC attack, including methodology, hypotheses tested, and evidence. It was prepared in the event Standard Supply's team wants additional details or a walkthrough of our findings.

---

## Executive Summary

After analyzing the complete RFC 2822 headers of all emails exchanged between Moss Mechanical and Standard Supply, the evidence suggests the attacker had **read access to Janet Halstead-Wiggins' mailbox at Standard Supply** rather than access to Moss's environment.

Key findings:
1. The attacker knew Message-IDs that only appear in Janet's inbox
2. If they had Moss access, they wouldn't need the lookalike domain
3. The spam attack on Janet fits the pattern of covering tracks on a compromised account
4. The attacker communicated as "fake Janet" for **11 days (Dec 4-15)** sending **21 fraudulent emails**

---

## The Thread Switch: Where Legitimate Became Fraudulent

This is the critical moment where the attacker inserted themselves into the email thread:

| Date | Time (UTC) | From | Domain | Event |
|------|------------|------|--------|-------|
| Nov 21, 2025 | 17:07 | Janet Halstead-Wiggins | **ssdhvac.com** | **LAST LEGITIMATE EMAIL** - RE: 125604 Moss Mechanical LLC |
| | | | | *-- 13 day gap --* |
| **Dec 4, 2025** | **16:15** | Janet Halstead- Wiggins | **ssdhvca.com** | **FIRST FRAUDULENT EMAIL** - Attacker enters thread |
| Dec 4, 2025 | 16:57 | Lori Maynard | askmoss.com | Lori replies to attacker (unknowingly) |
| Dec 4, 2025 | 18:53 | Janet Halstead- Wiggins | ssdhvca.com | Second fraudulent email |
| Dec 5-15 | Various | Janet Halstead- Wiggins | ssdhvca.com | 19 additional fraudulent emails |
| **Dec 15, 2025** | **19:08** | Janet Halstead-Wiggins | **ssdhvac.com** | **REAL JANET RESPONDS** - Fraud discovered |

**Key observations:**
- The attacker waited 13 days after the last legitimate email
- The attacker knew Janet was out of office (auto-reply)
- Lori replied to the attacker within 42 minutes of the first fraudulent email
- The attacker maintained the impersonation for 11 days before discovery
- Note the subtle difference: attacker used "Janet Halstead- Wiggins" (extra space before hyphen)

---

## Investigation Methodology

### Data Sources
1. **Gmail API with Domain-Wide Delegation** - Programmatic access to Moss user mailboxes via service account impersonation
2. **Full RFC 2822 Headers** - Complete email header extraction for every message (not just what's visible in email clients)
3. **Google Workspace Admin Email Log Search** - Independent verification of email delivery at the transport layer

### Scope

| Item | Count |
|------|-------|
| Users analyzed | 2 (lori.maynard, madelin.martinez) |
| Total emails exported | 208 |
| Emails from ssdhvac.com (legitimate) | 77 |
| Emails from ssdhvca.com (fraudulent) | 21 unique |
| Emails in TRASH (discovered post-fraud) | 40 |
| Date range | September 25 - December 16, 2025 |

### Data Completeness Verification

To ensure forensic completeness, I verified my capture against Google Workspace Admin Email Log Search:

| Source | Unique Message-IDs from ssdhvca.com |
|--------|-------------------------------------|
| Google Workspace Admin Log | 21 |
| Gmail API Export | 21 |
| **Result** | **100% match - all Message-IDs identical** |

Every fraudulent email ever delivered to askmoss.com has been captured and analyzed.

### Headers Examined

For each email, I extracted and analyzed:

| Header | Purpose |
|--------|---------|
| `From`, `To`, `Cc` | Sender/recipient identification |
| `Reply-To` | Critical for detecting poisoning attacks |
| `Return-Path` | Envelope sender verification |
| `Message-ID` | Unique identifier revealing originating mail server |
| `In-Reply-To`, `References` | Thread relationship (how attacker inserted into conversation) |
| `DKIM-Signature` | Signing domain verification |
| `Authentication-Results` | SPF/DKIM/DMARC pass/fail status |
| `X-OriginatorOrg` | Microsoft 365 organization identifier |
| `X-MS-Exchange-CrossTenant-id` | Microsoft 365 tenant UUID |

---

## Hypotheses Tested

### Hypothesis 1: Reply-To Header Poisoning

**Theory:** Attacker compromised Standard Supply and modified outgoing emails to include a `Reply-To` header pointing to the fraudulent domain. When Moss employees clicked "Reply," responses would go to the attacker.

**Test:** Examine ALL legitimate emails from ssdhvac.com for Reply-To headers.

**Result:** ❌ **REFUTED**
- Analyzed 77 legitimate emails from ssdhvac.com
- **0 out of 77 emails contained a Reply-To header**
- No Reply-To poisoning occurred

---

### Hypothesis 2: Moss Mechanical Compromise

**Theory:** Attacker compromised Moss's email environment, had access to Lori's mailbox, and used this to coordinate the attack.

**Test:** Analyze whether the attack pattern requires external infrastructure.

**Result:** ❌ **REFUTED**

**Evidence:**
- Attacker registered external lookalike domain (ssdhvca.com) on December 4, 2025
- Attacker created external M365 tenant (warehouseathletics.onmicrosoft.com)
- Lori sent 6 emails TO the fraudulent domain (as replies)

**Logic:** If the attacker had access to Lori's mailbox:
- They could read her inbox directly (see Janet's replies)
- They could read her sent folder (see her outgoing messages)
- They could BCC themselves on outgoing messages
- **They would NOT need a lookalike domain to capture her replies**

The external infrastructure proves the attacker was OUTSIDE Moss's environment. The lookalike domain's entire purpose was to receive Lori's replies - something only necessary if you cannot read her sent folder.

---

### Hypothesis 3: Standard Supply Read-Access Compromise

**Theory:** Attacker had read access to Janet's mailbox, could see incoming emails from Moss (including Message-IDs), and used this to craft thread-injected impersonation emails.

**Test:** Analyze fraudulent email headers for evidence of insider knowledge.

**Result:** ✅ **CONFIRMED**

**Evidence:**
The fraudulent emails contain valid `In-Reply-To` headers referencing Lori's Gmail Message-IDs:

```
In-Reply-To: <CAEDQfwXn8B...@mail.gmail.com>
References: <CAEDQfwXn8B...@mail.gmail.com>
```

These Message-IDs (format: `<CAEDQfw...@mail.gmail.com>`) are generated by Gmail when Lori sends an email. They appear in exactly two locations:

1. **Lori's Sent folder** - as the Message-ID of what she sent
2. **Janet's Inbox** - in the email headers of messages Lori sent to Janet

The attacker knew these exact Message-IDs and used them to properly thread their fraudulent emails into the existing conversation.

**Critical Question:** How did the attacker obtain Lori's outgoing Message-IDs?

| If Moss Compromised | If Standard Supply Compromised |
|---------------------|-------------------------------|
| Attacker reads Lori's Sent folder | Attacker reads Janet's Inbox |
| Attacker sees Message-IDs | Attacker sees Message-IDs |
| Attacker can read Janet's replies in Lori's Inbox | Attacker CANNOT read Lori's Inbox |
| **No need for lookalike domain** | **Lookalike domain needed to receive replies** |

The only scenario requiring BOTH the Message-ID knowledge AND the lookalike domain is Standard Supply compromise.

---

### Hypothesis 4: Man-in-the-Middle Attack

**Theory:** Attacker intercepted emails in transit between Moss and Standard Supply.

**Test:** Verify TLS encryption and look for interception signs.

**Result:** ❌ **UNLIKELY**
- All legitimate emails show proper TLS transport in headers
- No evidence of certificate manipulation
- MitM attacks on Gmail/M365 TLS traffic are extremely difficult
- Attack pattern better matches mailbox compromise than network interception

---

### Hypothesis 5: Social Engineering Without Compromise (Lucky Timing)

**Theory:** Attacker guessed timing and context through public information.

**Test:** Assess precision of thread insertion.

**Result:** ❌ **RULED OUT**
- Attacker's emails properly thread with legitimate conversation (correct In-Reply-To headers)
- Attacker knew specific Message-IDs that are NOT publicly available
- Attacker knew exact invoice numbers and payment amounts
- Attacker knew Janet was out of office
- Too precise to be coincidental

---

## Hypothesis Summary Table

| # | Hypothesis | Test Method | Evidence | Verdict |
|---|------------|-------------|----------|---------|
| 1 | Reply-To Poisoning | Check Reply-To on all legit emails | 0/77 had Reply-To | ❌ REFUTED |
| 2 | Moss Compromise | Check if attack needs external infra | Lookalike domain + external M365 | ❌ REFUTED |
| 3 | Standard Supply Read-Access | Check if attacker knew Moss Message-IDs | Valid In-Reply-To headers | ✅ CONFIRMED |
| 4 | Man-in-the-Middle | Verify TLS, check for interception | All TLS verified | ❌ UNLIKELY |
| 5 | Lucky Timing | Assess thread insertion precision | Too precise, knew internal IDs | ❌ RULED OUT |

---

## Attacker Infrastructure

| Attribute | Value |
|-----------|-------|
| Fraudulent Domain | ssdhvca.com |
| Domain Registrar | [Available via WHOIS lookup] |
| Registration Date | December 4, 2025 |
| Email Platform | Microsoft 365 |
| M365 Tenant | warehouseathletics.onmicrosoft.com |
| Tenant ID | 4b0f3443-6891-4079-a2a5-de733068808c |
| Mail Server | BYAPR13MB2743.namprd13.prod.outlook.com |
| DKIM Signing Domain | warehouseathletics.onmicrosoft.com |

All 21 fraudulent emails originated from the same M365 tenant and mail server.

---

## How We Know the Attacker Used Microsoft 365

The fraudulent email headers contain Microsoft-specific fields:

```
Message-ID: <BYAPR13MB2743025E6863F738B8AD40ACE2A3A@BYAPR13MB2743.namprd13.prod.outlook.com>
X-MS-Exchange-CrossTenant-id: 4b0f3443-6891-4079-a2a5-de733068808c
X-MS-Exchange-Organization-SCL: 1
X-MS-Exchange-Organization-AuthSource: BYAPR13MB2743.namprd13.prod.outlook.com
DKIM-Signature: ... d=warehouseathletics.onmicrosoft.com; ...
```

**Key identifiers:**
- `BYAPR13MB2743.namprd13.prod.outlook.com` = Microsoft Exchange Online server (North America datacenter)
- `X-MS-Exchange-CrossTenant-id` = Microsoft 365 specific header
- `.onmicrosoft.com` = Default tenant domain assigned to every M365 tenant

The attacker created a tenant, added ssdhvca.com as a custom domain, and sent mail through Microsoft's legitimate infrastructure - which is why SPF/DKIM/DMARC all passed.

---

## How We Know Standard Supply Uses Microsoft 365

The legitimate email headers from ssdhvac.com also show Microsoft infrastructure:

```
Message-ID: <BLAPR19MB4417...@BLAPR19MB4417.namprd19.prod.outlook.com>
X-OriginatorOrg: ssdhvac.com
DKIM-Signature: d=ssdhvac.com
```

**Comparison:**

| Attribute | Legitimate (ssdhvac.com) | Fraudulent (ssdhvca.com) |
|-----------|--------------------------|--------------------------|
| Mail Server | BLAPR19MB4417.namprd19.prod.outlook.com | BYAPR13MB2743.namprd13.prod.outlook.com |
| Platform | Microsoft 365 | Microsoft 365 |
| DKIM Domain | ssdhvac.com | warehouseathletics.onmicrosoft.com |
| Tenant | Standard Supply's legitimate tenant | Attacker's separate tenant |

Both use M365, but completely different tenants. The attacker did not compromise Standard Supply's M365 tenant directly - they created their own tenant and added the lookalike domain to it.

---

## The Spam Attack on Janet

The spam campaign against Janet immediately after fraud discovery is significant.

**Spam bombing is a known technique used to:**
1. Bury specific emails under thousands of spam messages
2. Create chaos during investigation
3. Distract the victim from reviewing their mailbox
4. Potentially trigger auto-archive or deletion rules

**Analysis:**

If the attacker compromised Moss:
- They would spam bomb **Lori** to cover tracks in her mailbox
- They would have no reason to attack Janet

The fact that Janet was targeted specifically suggests:
- The attacker had a specific interest in disrupting Janet's mailbox
- The attacker wanted to create confusion at Standard Supply during investigation
- This is consistent with covering tracks in an account they had accessed

**Note:** Moss was not impacted by a similar spam campaign.

---

## Recommended Investigation Steps for Standard Supply

### 1. Check Inbox Rules
```powershell
Get-InboxRule -Mailbox "jhalstead-wiggins@ssdhvac.com" | Select-Object Name, Enabled, RedirectTo, ForwardTo, DeleteMessage, MoveToFolder
```

Look for rules that:
- Forward to external addresses
- Move messages to obscure folders (RSS Feeds, Conversation History)
- Delete messages matching certain criteria

### 2. Pull Unified Audit Logs (90 days)
```powershell
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-90) -EndDate (Get-Date) -UserIds "jhalstead-wiggins@ssdhvac.com" -ResultSize 5000 | Export-Csv "janet_audit.csv" -NoTypeInformation
```

Look for:
- `MailItemsAccessed` from unusual IPs or user agents
- `New-InboxRule` or `Set-InboxRule` events
- `Add-MailboxPermission` grants
- `UpdateInboxRules` operations
- OAuth application consent events

### 3. Review Azure AD Sign-In Logs
- Check for impossible travel scenarios
- Look for unfamiliar devices or locations
- Check for legacy authentication protocols (often exploited)

### 4. Check OAuth/App Permissions
```powershell
Get-AzureADUserOAuth2PermissionGrant -ObjectId "[janet-object-id]" | Select-Object ClientId, Scope, ConsentType
```

### 5. Review Mail Flow Rules (Organization-Wide)
```powershell
Get-TransportRule | Select-Object Name, State, Priority, Conditions, Actions
```

---

## Conclusion

The forensic evidence supports the following conclusions:

1. **No Reply-To poisoning occurred** - 0/77 legitimate emails had Reply-To headers
2. **Moss was not compromised** - The lookalike domain proves the attacker was external to our environment
3. **Standard Supply likely had read-access compromise** - Attacker knew Message-IDs only visible in Janet's inbox
4. **The spam attack on Janet supports this** - Cover-up technique targeting the potentially compromised account
5. **Other Standard Supply customers may be at risk** - If the attacker had Janet's mailbox access for an extended period, they could be running similar operations against other customers

---

## Appendix: Data Verification

### Message-ID Verification Against Google Workspace Admin Logs

All 21 fraudulent Message-IDs from our export match exactly with Google Workspace Admin Email Log Search:

```
<BYAPR13MB2743025E6863F738B8AD40ACE2A3A@BYAPR13MB2743.namprd13.prod.outlook.com>
<BYAPR13MB274302926F15496CDFD62329E2A2A@BYAPR13MB2743.namprd13.prod.outlook.com>
<BYAPR13MB27430D62098E833D58DE2260E2AAA@BYAPR13MB2743.namprd13.prod.outlook.com>
<BYAPR13MB27430DB92140EF366C818F97E2A3A@BYAPR13MB2743.namprd13.prod.outlook.com>
<BYAPR13MB27430E0E320FDB65F832A566E2AEA@BYAPR13MB2743.namprd13.prod.outlook.com>
<BYAPR13MB27431AF3A13F10EDCFC44615E2A0A@BYAPR13MB2743.namprd13.prod.outlook.com>
<BYAPR13MB27431D4603B20C64143737DEE2A0A@BYAPR13MB2743.namprd13.prod.outlook.com>
<BYAPR13MB274325C45B4C839E1B20A36EE2A2A@BYAPR13MB2743.namprd13.prod.outlook.com>
<BYAPR13MB274330BA084F33378AFC7E48E2A7A@BYAPR13MB2743.namprd13.prod.outlook.com>
<BYAPR13MB2743331AD810028D3EEB5BA4E2AEA@BYAPR13MB2743.namprd13.prod.outlook.com>
<BYAPR13MB27434D35A88667EDB4B16131E2AAA@BYAPR13MB2743.namprd13.prod.outlook.com>
<BYAPR13MB27435540B7AE02DC9EFCE6E5E2A7A@BYAPR13MB2743.namprd13.prod.outlook.com>
<BYAPR13MB274365CF79CB2EDECB1A48BEE2A6A@BYAPR13MB2743.namprd13.prod.outlook.com>
<BYAPR13MB27436A8D7D1AA82524A706B6E2AEA@BYAPR13MB2743.namprd13.prod.outlook.com>
<BYAPR13MB27436B7CBC8CE9FF9440719FE2A0A@BYAPR13MB2743.namprd13.prod.outlook.com>
<BYAPR13MB2743B16460544309A3000655E2AEA@BYAPR13MB2743.namprd13.prod.outlook.com>
<BYAPR13MB2743B826B9936CD8B3871D07E2ADA@BYAPR13MB2743.namprd13.prod.outlook.com>
<BYAPR13MB2743D3FED797EB3AE5D3DD22E2A6A@BYAPR13MB2743.namprd13.prod.outlook.com>
<BYAPR13MB2743E0F7051E7162F590B359E2ADA@BYAPR13MB2743.namprd13.prod.outlook.com>
<BYAPR13MB2743E8B6FB987147ED7220FBE2A3A@BYAPR13MB2743.namprd13.prod.outlook.com>
<BYAPR13MB2743FFE8647DC8BF67CC7982E2AEA@BYAPR13MB2743.namprd13.prod.outlook.com>
```

**Verification result:** 100% match. Every fraudulent email delivered to askmoss.com has been captured.

---

## Repository Contents

The full analysis is available in the GitHub repository:

```
email-forensics/
├── src/                                    # Analysis scripts
│   ├── export_all_emails.py               # Complete email export
│   ├── comprehensive_review.py            # Anomaly detection
│   ├── analyze_thread_flow.py             # Thread analysis
│   └── ...
├── output/                                 # Raw data
│   ├── all_emails_complete_export.txt     # 208 emails with full headers
│   └── comprehensive_review_output.txt    # Anomaly scan results
└── reports/                                # Documentation
    ├── findings.md                         # Main investigation report
    └── technical_analysis_for_standard_supply.md  # This document
```

Happy to share access upon request.
