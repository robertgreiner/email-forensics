# Executive Briefing: Ongoing BEC Attack - Standard Supply

**Date:** December 17, 2025
**Prepared by:** Robert Greiner, Moss Mechanical IT
**Classification:** Confidential - For Executive Review
**Status:** URGENT - Active Threat

---

## Summary

Moss Mechanical has been targeted by a sophisticated Business Email Compromise (BEC) attack impersonating Janet Halstead-Wiggins of Standard Supply. The attacker attempted to redirect a > $200,000 in payments to a fraudulent bank account over a period of weeks. The payment was stopped before funds were lost.

**Critical Update (December 17, 2025):** The attacker is still active. This morning, a new fraudulent email was received from a second lookalike domain, using entirely different infrastructure. This demonstrates the attacker is persistent, well-resourced, and has not been deterred.

**Our assessment:** Based on forensic email analysis, we believe the attacker has or had read access to Janet Halstead-Wiggins' mailbox at Standard Supply. If this is correct, other Standard Supply customers may be at risk.

---

## Attack Timeline

| Date | Event | Domain | Details |
|------|-------|--------|---------|
| Nov 21, 2025 | Last legitimate email from Janet | ssdhvac.com | Normal business correspondence |
| Dec 4, 2025 | **First fraudulent email** | ssdhvca.com | Attacker enters thread, impersonating Janet |
| Dec 4-15, 2025 | Ongoing fraud campaign | ssdhvca.com | 21 fraudulent emails sent over 11 days |
| Dec 15, 2025 | Fraud discovered | - | Moss identifies the attack, stops payment |
| Dec 15, 2025 | Janet spam-bombed | - | Attacker floods Janet's inbox with spam |
| Dec 16, 2025 | Standard Supply notified | - | Their IT concludes Moss was compromised |
| **Dec 17, 2025** | **NEW fraudulent email** | **sshdvac.com** | Attacker pivots to new domain and platform |

---

## The Two Attacks

### Attack #1: ssdhvca.com (December 4-15)

| Attribute | Value |
|-----------|-------|
| Fraudulent Domain | ssdhvca.com (typo: "vca" instead of "vac") |
| Email Platform | Microsoft 365 |
| M365 Tenant | warehouseathletics.onmicrosoft.com |
| Tenant ID | 4b0f3443-6891-4079-a2a5-de733068808c |
| Mail Server | BYAPR13MB2743.namprd13.prod.outlook.com |
| Emails Sent | 21 |
| Duration | 11 days |

### Attack #2: sshdvac.com (December 17 - NEW)

| Attribute | Value |
|-----------|-------|
| Fraudulent Domain | sshdvac.com (typo: "ssh" instead of "ssd") |
| Email Platform | **Google Workspace** (different from Attack #1) |
| DKIM Signing Domain | sshdvac-com.20230601.gappssmtp.com |
| Message-ID Format | Gmail format (@mail.gmail.com) |
| Status | **ACTIVE** |

**Key observation:** The attacker switched from Microsoft 365 to Google Workspace between attacks. This indicates they have resources to spin up new infrastructure and are adapting after being detected.

---

## Evidence Summary

### What the Attacker Knew

During the original attack, the attacker demonstrated knowledge of:

1. **Internal Message-IDs** - The fraudulent emails contained valid `In-Reply-To` headers referencing Lori Maynard's outgoing Gmail Message-IDs. These IDs are only visible in two places:
   - Lori's Sent folder (at Moss)
   - Janet's Inbox (at Standard Supply)

2. **Janet's out-of-office status** - The attack began while Janet was unavailable

3. **Invoice numbers and payment amounts** - Specific financial details from the business relationship

4. **Email signatures and formatting** - The attacker copied Janet's signature block exactly

### Why This Points to Standard Supply (Not Moss)

If the attacker had access to Moss's email environment, they would NOT need to:
- Register a lookalike domain
- Set up external email infrastructure
- Trick Lori into sending replies to a fake address

They could simply read Janet's replies directly in Lori's inbox.

**The lookalike domain proves the attacker was OUTSIDE Moss's environment.** They needed Lori to voluntarily send emails to a domain they controlled because they could not read her mailbox.

The only scenario that explains both:
- The attacker knowing Lori's outgoing Message-IDs, AND
- The attacker needing a lookalike domain to receive replies

...is that the attacker had read access to Janet's inbox at Standard Supply.

### The Spam Attack on Janet

Immediately after the fraud was discovered, Janet's inbox was flooded with spam. Spam-bombing is a known technique used to:
- Bury evidence under thousands of messages
- Create confusion during investigation
- Distract the victim from reviewing their mailbox

If the attacker had compromised Moss, they would have spam-bombed Lori (to cover their tracks at Moss). The fact that Janet was targeted suggests the attacker had reason to create chaos in her mailbox specifically.

---

## Standard Supply's Response (December 16)

Standard Supply's IT team (Jason Muhlberger, reporting to Devon) provided their assessment approximately 2 hours after being notified. Their conclusions:

1. Moss Mechanical was compromised
2. The attacker was monitoring Moss's mailboxes
3. They are "confident there's nothing going on" at Standard Supply
4. They are "confident their other customers are not impacted"

**Our concern:** This assessment was made quickly, without access to the fraudulent email exchanges, and before the second attack occurred. We do not believe Standard Supply has conducted a thorough investigation of Janet's account.

---

## What Happened Today (December 17)

At 9:31 AM CST, Lori Maynard received a new fraudulent email:

```
From: Janet Halstead-Wiggins <jhalstead-wiggins@sshdvac.com>
Subject: Re: Moss Mechnical - Invoices
Date: Wed, 17 Dec 2025 07:31:38 -0800

Hi Lori,

Please do you have any update on the payment as we haven't
seen it come through to our account.

Regards,

Janet Halstead-Wiggins - CBA
Senior Credit Manager
NACM MEMBER
```

**Analysis of this email:**

| Attribute | Value | Significance |
|-----------|-------|--------------|
| Domain | sshdvac.com | NEW typosquat ("ssh" vs "ssd") |
| Platform | Google Workspace | DIFFERENT from Attack #1 (was M365) |
| Message-ID | Gmail format | Confirms Google, not Microsoft |
| Content | Asking about payment status | Attacker knows payment didn't go through |

The attacker:
1. Registered a new lookalike domain
2. Set up entirely new email infrastructure (Google instead of Microsoft)
3. Is continuing to pursue the fraudulent payment

---

## Risk Assessment

### Risk to Moss Mechanical

| Risk | Status | Mitigation |
|------|--------|------------|
| Financial loss | ✅ Mitigated | Payment stopped before clearing |
| Email compromise | ⚠️ Under review | No evidence found; Lori's sessions refreshed |
| Ongoing targeting | 🔴 Active | Both fraudulent domains now blocked |

### Risk to Standard Supply

| Risk | Status | Concern |
|------|--------|---------|
| Janet's account compromise | ⚠️ Unknown | Not investigated per their response |
| Other customers targeted | ⚠️ Unknown | If attacker has Janet's mailbox, they can see all her correspondence |
| Reputation | 🔴 At risk | Their vendor (Moss) was nearly defrauded via their employee's identity |

### Risk to Standard Supply's Other Customers

If the attacker has persistent access to Janet's mailbox, they can:
- See all invoices Janet sends to any customer
- Monitor payment conversations
- Identify other high-value targets
- Launch similar attacks against other companies

The attacker demonstrated they were willing to pursue $300,000 from Moss. There is no reason to believe they would not pursue similar amounts from other Standard Supply customers.

---

## Data Verification

To ensure our analysis is complete, we verified our email capture against Google Workspace Admin Email Log Search:

| Source | Fraudulent Emails (ssdhvca.com) |
|--------|--------------------------------|
| Google Admin Logs | 21 unique Message-IDs |
| Our Gmail API Export | 21 unique Message-IDs |
| **Match** | **100%** |

Every fraudulent email from the first attack domain (ssdhvca.com) that was delivered to Moss has been captured and analyzed.

---

## Recommended Actions for Standard Supply

We recommend Standard Supply's IT team investigate the following:

### 1. Janet's Inbox Rules
Check for rules that forward email to external addresses or move messages to hidden folders.

### 2. Janet's Account Audit Logs
Review Microsoft 365 Unified Audit Logs for the past 90 days. Look for:
- `MailItemsAccessed` events from unusual IP addresses
- `New-InboxRule` or `Set-InboxRule` events
- OAuth application consent grants
- Sign-ins from unfamiliar locations or devices

### 3. Azure AD Sign-In Logs
Check for impossible travel scenarios, legacy authentication, or unfamiliar devices.

### 4. OAuth/Third-Party App Permissions
Review what applications have access to Janet's mailbox.

### 5. Organization-Wide Mail Flow Rules
Check for transport rules that could be exfiltrating email.

---

## What We're Asking

1. **Acknowledge the ongoing threat** - The attacker sent a new email this morning. This is not a concluded incident.

2. **Investigate Janet's account** - We believe Standard Supply's initial assessment was premature. A thorough investigation of Janet's account is warranted.

3. **Consider other customers** - If the attacker had access to Janet's mailbox, other Standard Supply customers may be at risk. They deserve to be warned.

4. **Share findings** - We are happy to provide all of our forensic data, analysis code, and methodology. We request Standard Supply share their investigation findings with us.

---

## Our Actions Taken

| Action | Status |
|--------|--------|
| Payment stopped | ✅ Complete |
| Lori's sessions refreshed | ✅ Complete |
| ssdhvca.com blocked | ✅ Complete |
| sshdvac.com blocked | ✅ Complete |
| Forensic analysis complete | ✅ Complete |
| Standard Supply notified | ✅ Complete |
| Ongoing monitoring via Abnormal | ✅ Active |

---

## Attachments Available Upon Request

1. Complete forensic analysis with methodology (40+ pages)
2. Full email headers from all 21 fraudulent emails (Attack #1)
3. Full email headers from new fraudulent email (Attack #2)
4. GitHub repository with analysis code
5. Google Workspace Admin Log verification

---

## Contact

Robert Greiner
IT, Moss Mechanical
robert@mossutilities.com

---

*This briefing contains confidential investigation details. Please handle accordingly.*
