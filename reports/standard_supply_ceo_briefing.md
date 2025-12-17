# Business Email Compromise Investigation
## Prepared for Standard Supply Executive Leadership

**Date:** December 17, 2025
**From:** Moss Mechanical
**Re:** Fraudulent emails impersonating Janet Halstead-Wiggins

---

**We believe Standard Supply systems are at risk.** We have conducted a thorough forensic investigation and the evidence does not support the conclusions in Standard Supply's initial assessment. We are sharing this report because we have information your team has not yet seen - including 21 fraudulent emails and their complete headers - and your other customers may be at risk.

---

## Executive Summary

- **Background:** Attacker impersonated Janet Halstead-Wiggins to redirect >$200K in payments; attack identified before funds lost but attacker remains active as of today
- **What Happened:** Two lookalike domains used (ssdhvca.com, sshdvac.com); 21 fraudulent emails over 11 days; attacker switched from Microsoft 365 to Google Workspace after detection
- **Our Investigation:** Analyzed 208 emails with complete headers; tested 5 hypotheses; ruled out Reply-To poisoning, man-in-the-middle, and social engineering
- **Key Finding:** Attacker knew internal Message-IDs only visible in Janet's inbox, enabling them to thread into legitimate conversations
- **Why This Points to Standard Supply:** The lookalike domain proves attacker couldn't read Moss mailboxes; if they could, no fake domain would be needed
- **Status of Moss Systems:** No evidence of compromise found; investigation ongoing; engaged third-party security provider
- **Spam Attack on Janet:** Janet was spam-bombed after fraud discovered - consistent with attacker covering tracks in her mailbox
- **Attacker Infrastructure:** Well-resourced; operates M365 tenant and Google Workspace; adapts quickly when detected
- **Risk to Other Customers:** If Janet's mailbox is compromised, attacker can see all her correspondence with all customers
- **Recommended Actions:** Investigate Janet's inbox rules, audit logs, sign-in history, and third-party app access
- **What We're Asking:** Acknowledge ongoing threat, investigate thoroughly, consider notifying other customers, share findings

---

## Background

Between December 4-17, 2025, Moss Mechanical received fraudulent emails impersonating Janet Halstead-Wiggins, Senior Credit Manager at Standard Supply. The attacker used lookalike domains designed to appear as Standard Supply and attempted to redirect payments exceeding $200,000 to fraudulent bank accounts.

The attack was identified before funds were lost. However, as of this morning (December 17), **the attacker remains active** and continues to send fraudulent emails using new infrastructure.

We are sharing this report because our forensic analysis raises concerns about the security of Standard Supply systems. We believe this warrants a thorough investigation to protect both our organizations and your other customers.

---

## What Happened

An attacker impersonated Janet Halstead-Wiggins using two fraudulent domains:

| Domain | Typosquat Method | Active Period |
|--------|------------------|---------------|
| ssdhvca.com | "vca" instead of "vac" | Dec 4-15, 2025 |
| sshdvac.com | "ssh" instead of "ssd" | Dec 17, 2025 (today) |

The attacker sent **21 fraudulent emails** from the first domain over 11 days, inserting themselves into a legitimate email thread about invoices. When the first domain was identified and blocked, the attacker registered a second domain and resumed contact this morning.

**The attacker also switched email platforms between attacks** - from Microsoft 365 to Google Workspace - indicating they have resources to rapidly deploy new infrastructure when detected.

---

## Our Investigation

We conducted a forensic analysis of all emails exchanged between Moss and Standard Supply over the past 90 days. This included extraction and analysis of complete email headers (not visible in standard email clients) for 208 emails.

### Methodology

1. **Data Collection:** Used Gmail API to extract complete RFC 2822 headers from all relevant emails
2. **Verification:** Cross-referenced against Google Workspace Admin Email Log Search to confirm 100% capture of fraudulent emails
3. **Header Analysis:** Examined authentication records (SPF, DKIM, DMARC), message threading (Message-ID, In-Reply-To, References), and origin indicators (X-OriginatorOrg, mail server hostnames)
4. **Hypothesis Testing:** Developed and tested five hypotheses about the attack vector

### Hypotheses Tested

| Hypothesis | Description | Result |
|------------|-------------|--------|
| Reply-To Poisoning | Attacker modified legitimate Standard Supply emails to redirect replies | **Ruled Out** - 0 of 77 legitimate emails contained Reply-To headers |
| Moss Systems Compromised | Attacker had access to Moss email environment | **Not Supported** - See analysis below |
| Standard Supply Read Access | Attacker had read access to Janet's mailbox | **Supported by Evidence** - See analysis below |
| Man-in-the-Middle | Attacker intercepted emails in transit | **Ruled Out** - All emails show proper TLS encryption |
| Social Engineering Only | Attacker guessed timing and context | **Ruled Out** - Attacker knew non-public information |

---

## Key Finding: How the Attacker Threaded Into the Conversation

The fraudulent emails successfully "threaded" into the legitimate email conversation. Email threading is controlled by the `In-Reply-To` header, which must reference the `Message-ID` of the email being replied to.

**The attacker's emails contained valid In-Reply-To headers referencing Lori Maynard's outgoing email Message-IDs.**

These Message-IDs (format: `<CAEDQfw...@mail.gmail.com>`) are generated by Gmail when Lori sends an email. They appear in only two places:

1. Lori's Sent folder at Moss
2. Janet's Inbox at Standard Supply (in emails Lori sent to Janet)

The attacker knew these exact Message-IDs and used them to thread their fraudulent emails into the conversation.

---

## Why This Points to a potential Standard Supply security compromise

**If the attacker had access to Moss systems:**
- They could read Lori's inbox directly
- They could see Janet's replies without any external infrastructure
- They would have no need to register lookalike domains
- They would have no need to trick Lori into sending emails to fake addresses

**The existence of the lookalike domains suggests the attacker could not read Lori's mailbox.** The entire purpose of the fraudulent domain was to receive Lori's replies - something only necessary if you cannot access her sent folder directly.

**The combination of:**
- Knowing Lori's outgoing Message-IDs (only visible to Janet), AND
- Needing a lookalike domain to receive replies (proving no access to Lori's mailbox)

...is consistent with the attacker having read access to Janet's inbox at Standard Supply.

NOTE: we are still investigating the potential for compromised systems within Moss' infrastructure. Even if one "side" is compromised, it does not mean the other isn't - we are taking this very seriously.

---

## Status of Moss Systems

We have conducted an internal review and **have not found evidence of a compromise within Moss systems**. However, we have not definitively ruled it out. Our investigation is ongoing.

Actions taken at Moss:
- All sessions for affected user terminated and re-authenticated
- Both fraudulent domains blocked at mail gateway
- Enhanced monitoring enabled through our email security platform
- Forensic review of email logs in progress

We have also opened two spearate security tickets with our security platform provider to help with independent 3rd party investigation.

---

## Additional Concern: The Spam Attack on Janet

On December 15, immediately after the fraud was discovered, Janet's inbox was flooded with spam emails. Spam-bombing is a known technique used to bury evidence or create confusion during an investigation.

If the attacker had compromised Moss, we would expect them to spam-bomb Lori to cover their tracks. The targeting of Janet specifically is consistent with the attacker having reason to obscure activity in her mailbox.

---

## The Attacker's Infrastructure

### Attack #1 (December 4-15)

| Attribute | Value |
|-----------|-------|
| Domain | ssdhvca.com |
| Platform | Microsoft 365 |
| M365 Tenant | warehouseathletics.onmicrosoft.com |
| Tenant ID | 4b0f3443-6891-4079-a2a5-de733068808c |
| Mail Server | BYAPR13MB2743.namprd13.prod.outlook.com |

### Attack #2 (December 17 - Today)

| Attribute | Value |
|-----------|-------|
| Domain | sshdvac.com |
| Platform | Google Workspace |
| DKIM Domain | sshdvac-com.20230601.gappssmtp.com |
| Message-ID Format | Gmail (@mail.gmail.com) |

The platform switch from Microsoft to Google indicates the attacker is adapting and has resources to deploy new infrastructure quickly.

---

## Concern for Other Standard Supply Customers

If the attacker has persistent access to Janet's mailbox, they have visibility into all of her email correspondence - not just communications with Moss. This could include:

- Invoice and payment discussions with other customers
- Banking and ACH information
- Contact details for accounts payable personnel at other companies

We were targeted for over $200,000. There is no reason to believe the attacker would not pursue similar opportunities with other Standard Supply customers.

---

## Recommended Investigation

We recommend Standard Supply conduct a thorough investigation of Janet's account, including:

1. **Inbox Rules** - Check for rules forwarding email to external addresses or moving messages to hidden folders

2. **Audit Logs** - Review Microsoft 365 Unified Audit Logs (90 days) for unusual access patterns, particularly:
   - MailItemsAccessed events from unfamiliar IPs
   - New inbox rule creation
   - OAuth application consents

3. **Sign-In History** - Review Azure AD sign-in logs for impossible travel, unfamiliar devices, or legacy authentication protocols

4. **Third-Party App Access** - Review what applications have been granted access to Janet's mailbox

5. **Mail Flow Rules** - Check organization-wide transport rules for any that could exfiltrate email

---

## What We're Asking

1. **Acknowledge the ongoing threat** - The attacker sent a new email this morning from new infrastructure. This is an active situation.

2. **Investigate Janet's account** - A thorough investigation is warranted given the evidence.

3. **Consider notifying other customers** - If compromise is confirmed, other customers who correspond with Janet may be at risk.

4. **Share findings** - We are happy to provide our complete forensic data and analysis. We request Standard Supply share their investigation findings so we can collectively understand and address this threat.

---

## Materials Available

We have prepared detailed technical documentation and are happy to share:

- Complete email header analysis for all 21 fraudulent emails (Attack #1)
- Complete email header analysis for new fraudulent email (Attack #2)
- Methodology documentation
- Timeline with specific Message-IDs showing thread injection
- Raw data exports
