# BEC Incident Report - Final Investigation Findings

**Incident ID:** MOSS-2025-001
**Date:** December 23, 2025
**Prepared by:** Robert Greiner, CTO
**Classification:** Internal - Incident Response

---

## Executive Summary

Between December 4-16, 2025, Moss Mechanical was targeted in a Business Email Compromise (BEC) attack resulting in fraudulent payment requests to our customer, Standard Supply (ssdhvac.com). Our investigation identified **unauthorized access to an employee's Google Workspace account on December 1, 2025** with **active attacker operations continuing through December 15**.

**Key Findings:**
- Lori Maynard's account was compromised via password-only authentication
- Attacker accessed her mailbox from **five datacenter IPs** (three for initial login, two for sustained operations)
- **Attacker maintained access for 12 days** (Dec 4-15) viewing 1,267 emails
- **Confirmed data exfiltration**: 4 emails sent to attacker-controlled domains (all deleted)
- **Evidence destruction**: 9 emails permanently deleted by attacker
- No other Moss accounts were compromised
- Only 17% of Moss users currently have 2FA enabled

**Status:** Compromised account remediated. Full user audit complete. **Cintas vendor relationship requires immediate review** due to exfiltrated invoice data.

---

## Incident Timeline

| Date | Event | Source |
|------|-------|--------|
| Before Dec 1 | Attacker obtains Lori Maynard's password | Unknown (phishing, breach, infostealer) |
| **Dec 1, 19:05-19:09 UTC** | **Attacker logs into Lori's Gmail from 3 datacenter IPs** | Google Workspace audit logs |
| Dec 1-3 | Attacker establishes persistent access (OAuth token) | Inferred |
| **Dec 4** | **Attacker begins active operations from Canadian VPS (158.51.123.14)** | Admin Email Log |
| Dec 4 | First fraudulent email sent impersonating Janet at Standard Supply | Email headers analysis |
| Dec 4-15 | Attacker views 1,267 emails, focuses on financial data | Admin Email Log |
| **Dec 10, 12:05 CST** | **Exfiltration #1: Email sent to ssdhvca.com, deleted** | Admin Email Log |
| Dec 10-14 | Continued surveillance, checking for detection | Admin Email Log |
| **Dec 15, 07:40 CST** | **Exfiltration #2: Cintas invoice sent to aksmoss.com, deleted** | Admin Email Log |
| Dec 15 | Fraud discovered when real Janet responds | Customer report |
| Dec 16 | Initial investigation begins | Email forensics |
| **Dec 17** | **Remediation: Password reset, 2FA enrolled for Lori** | Admin action |
| Dec 19 | Standard Supply DFIR report received (no compromise found) | Partner communication |
| **Dec 23** | **Full Google Workspace audit - Canadian VPS activity discovered** | This report |

---

## Account Compromise Details

### Unauthorized Access - December 1-15, 2025

**Phase 1: Initial Compromise (December 1)**

Three successful logins to `lori.maynard@askmoss.com` within 4 minutes from datacenter IPs:

| Time (UTC) | IP Address | Location | Provider | ASN |
|------------|------------|----------|----------|-----|
| 19:05:00 | 172.120.137.37 | Secaucus, NJ | HOST TELECOM LTD | AS214238 |
| 19:06:18 | 45.87.125.150 | Los Angeles, CA | Clouvider | AS62240 |
| 19:08:53 | 46.232.34.229 | New York City, NY | Clouvider | AS62240 |

**Phase 2: Sustained Operations (December 4-15)**

| Period | IP Address | Location | Provider | Events |
|--------|------------|----------|----------|--------|
| Dec 4 only | 147.124.205.9 | US | Tier.Net Technologies | 74 |
| Dec 4-15 | 158.51.123.14 | Canada | GLOBALTELEHOST Corp | 1,532 |

The attacker used **two different IPs** for ongoing operations, leveraging an OAuth token obtained during the initial compromise. These IPs were used without triggering new login events.

**Key finding:** The Tier.Net IP (147.124.205.9) was used for the **first exfiltration test** on Dec 4, sending 2 emails to the attacker domain and deleting them within seconds. The attacker then switched to the Canadian VPS for the remainder of the campaign.

**Attack Indicators:**
- All IPs belong to VPS/datacenter providers (commonly used by attackers)
- Three different geographic locations in 4 minutes (impossible for legitimate user)
- All logins triggered Google login challenges - all passed
- Chrome browser authorized within 1 second of login (indicates automation)
- Lori confirmed she was not traveling and does not use VPN
- GLOBALTELEHOST has 67/100 fraud risk score (Scamalytics)

### Why The Attack Succeeded

At the time of compromise:
- **Lori did not have 2FA enabled**
- Login challenges were weak (CAPTCHA or "is this you?" prompts)
- `login_challenge_method: None` in audit logs confirms no second factor
- Attacker only needed Lori's password

### Legitimate IP Baseline

For comparison, Lori's legitimate logins come from:
- `199.200.88.186` - Moss Mechanical office (Unite Private Networks, Farmers Branch, TX)
- AT&T residential IPs in Dallas area

---

## Full User Audit Results

### Scope
- **Total Google Workspace users:** 91
- **Active users:** 89 (2 suspended)
- **Login events analyzed:** 373 (30-day period)
- **Method:** Cross-referenced attacker IPs against all user login events

### Suspicious IP Search

Searched all login and activity events for attacker IPs:
```
172.120.137.37 (Secaucus, NJ - HOST TELECOM) - Login IP
45.87.125.150 (Los Angeles, CA - Clouvider) - Login IP
46.232.34.229 (New York City, NY - Clouvider) - Login IP
147.124.205.9 (US - Tier.Net Technologies) - Operations IP (Dec 4 only)
158.51.123.14 (Canada - GLOBALTELEHOST) - Operations IP (Dec 4-15)
```

**Result: Only Lori Maynard's account was accessed from these IPs.**

No evidence of lateral movement or additional account compromise. Both operational IPs only appear in Lori's Gmail activity logs.

**See: [Complete Attacker IP Inventory](all_attacker_ips.md) for full analysis.**

### Individual Account Audit

| Account | Role | Login Activity | Gmail Settings | Status |
|---------|------|----------------|----------------|--------|
| lori.maynard@askmoss.com | Accounting Manager | Compromised Dec 1 | Clean | **Remediated** |
| madelin.martinez@askmoss.com | AP Specialist | Clean (4 logins) | Clean | OK |
| invoices@askmoss.com | Shared mailbox | Clean (2 logins) | Clean | OK |

**Gmail settings verified clean:**
- No auto-forwarding enabled
- No suspicious email filters
- No unauthorized delegates
- No external send-as addresses
- IMAP/POP disabled

---

## 2FA Adoption Gap

### Current State

| Metric | Count | Percentage |
|--------|-------|------------|
| Active users | 89 | 100% |
| **With 2FA enabled** | **15** | **17%** |
| **WITHOUT 2FA** | **74** | **83%** |

### Risk Assessment

The December 1st compromise was enabled by lack of 2FA. **83% of active users remain vulnerable to identical attacks.**

### Users WITH 2FA Enabled (15)

| User | Role/Notes |
|------|------------|
| aimee.cooley@askmoss.com | |
| april.posey@askmoss.com | |
| chris.mariot@askmoss.com | |
| clayton.hampton@askmoss.com | |
| garrett.moss@askmoss.com | |
| info@mossmechanical.com | Shared account |
| josh.moulden@askmoss.com | |
| kelly.roberts@askmoss.com | |
| kevyn.ritchey@askmoss.com | |
| lori.lierman@askmoss.com | |
| lori.maynard@askmoss.com | Enrolled Dec 17 (post-incident) |
| marshal.sproull@askmoss.com | |
| matthew.gilmore@askmoss.com | |
| robert.greiner@askmoss.com | CTO |
| voicemail@mossmechanical.com | Service account |

### High-Risk Accounts WITHOUT 2FA

| Account | Role | Risk |
|---------|------|------|
| madelin.martinez@askmoss.com | Accounts Payable Specialist | Handles payments |
| invoices@askmoss.com | Shared mailbox | Receives all invoices |

---

## Remediation Actions

### Completed (December 17, 2025)

| Action | Target | Status |
|--------|--------|--------|
| Password reset | lori.maynard@askmoss.com | ✅ Complete |
| 2FA enrollment | lori.maynard@askmoss.com | ✅ Complete |
| Session invalidation | lori.maynard@askmoss.com | ✅ Complete |

### Verified Clean (December 23, 2025)

| Check | lori.maynard | madelin.martinez | invoices@ |
|-------|--------------|------------------|-----------|
| Auto-forwarding | ✅ Disabled | ✅ Disabled | ✅ Disabled |
| Email filters | ✅ None | ✅ None | ✅ None |
| Delegates | ✅ None | ✅ None | ✅ None |
| IMAP/POP | ✅ Disabled | ✅ Disabled | ✅ Disabled |
| Vacation responder | ✅ Off | ✅ Off | ✅ Off |

### Pending Verification

| Item | Status | Action Required |
|------|--------|-----------------|
| Passkey (Galaxy S25 Ultra) | ⚠️ Unverified | Confirm device belongs to Lori |
| Password source | ⚠️ Unknown | Investigate how password was obtained |

---

## Correlation with Standard Supply DFIR

Standard Supply's DFIR team found no evidence of compromise in their environment. **Our findings are consistent with theirs:**

| Original Hypothesis | Revised Understanding |
|---------------------|----------------------|
| Standard Supply's Janet mailbox compromised | Moss Mechanical's Lori mailbox compromised |
| Attacker viewed incoming emails to Janet | Attacker viewed Lori's sent AND received emails |
| Message-IDs obtained from recipient side | Message-IDs obtained from sender side |

The attacker accessed Lori's mailbox directly, gaining visibility into:
- Full email thread history with Standard Supply
- Message-IDs for thread injection attacks
- Business context, timing, and invoice details
- No need to compromise Standard Supply systems

---

## Recommendations

### Immediate Priority (This Week)

1. **Enable 2FA for accounting/finance users**
   - `madelin.martinez@askmoss.com`
   - `invoices@askmoss.com`
   - Any user with payment authority

2. **Verify Lori's passkey device**
   - Galaxy S25 Ultra passkey created November 9, 2025
   - Confirm this is Lori's personal device
   - If unknown device: remove immediately

3. **Check credential exposure**
   - Query haveibeenpwned.com for `lori.maynard@askmoss.com`
   - Review Lori's inbox for phishing emails before December 1

### Short-Term (30 Days)

4. **Enforce mandatory 2FA organization-wide**
   - Google Admin Console > Security > 2-Step Verification
   - Set enforcement with 14-day grace period for enrollment
   - Require phishing-resistant methods (security keys, passkeys)

5. **Implement login anomaly alerting**
   - Configure Abnormal Security for datacenter IP detection
   - Alert on impossible travel scenarios
   - Alert on new device/location combinations

### Long-Term

6. **Security awareness training**
   - Phishing recognition
   - Password hygiene (unique passwords, password manager)
   - BEC fraud indicators
   - Reporting suspicious emails

7. **Advanced access controls**
   - Context-aware access policies
   - Require managed devices for sensitive accounts
   - FIDO2 security keys for privileged users

---

## Attacker Infrastructure

### Domain Registration Timeline

The attacker registered multiple typosquat domains to execute this attack:

| Domain | Legitimate Version | Registered | Registrar | Purpose |
|--------|-------------------|------------|-----------|---------|
| `ssdhvca.com` | `ssdhvac.com` | **Dec 4, 2025** | GoDaddy | Impersonate Standard Supply |
| `aksmoss.com` | `askmoss.com` | **Dec 5, 2025** | GoDaddy | Catch Moss typos/replies |
| `sshdvac.com` | `ssdhvac.com` | **Dec 17, 2025** | NameCheap | Last-ditch attempt after remediation |

### Shared Microsoft 365 Tenant

All attacker domains resolve to the **same Microsoft 365 tenant**:

```
Tenant ID: 4b0f3443-6891-4079-a2a5-de733068808c
Base domain: warehouseathletics.onmicrosoft.com
```

| Domain | M365 Tenant ID |
|--------|----------------|
| `ssdhvca.com` | `4b0f3443-6891-4079-a2a5-de733068808c` |
| `aksmoss.com` | `4b0f3443-6891-4079-a2a5-de733068808c` |
| `warehouseathletics.onmicrosoft.com` | `4b0f3443-6891-4079-a2a5-de733068808c` |

This proves all domains were controlled by the same threat actor.

### Emails Involving Attacker Domains

| Domain | Direction | Count | Notes |
|--------|-----------|-------|-------|
| `ssdhvca.com` | Received (from attacker) | 7 | Fraudulent Janet emails |
| `ssdhvca.com` | Sent (Lori's replies) | 14 | Lori falling for the trap |
| `aksmoss.com` | Sent (Lori's typo) | 1 | Accidental typo Dec 18 |

---

## Attacker Activity Analysis

### Did the Attacker Send Emails as Lori?

**REVISED CONCLUSION: YES - attacker conducted active operations**

**See: [Addendum - Canadian VPS Operations](addendum_20251223_canadian_vps.md) for full details**

A fourth attacker IP was discovered: **158.51.123.14** (GLOBALTELEHOST Corp, Canada)

| Metric | Finding |
|--------|---------|
| Active period | December 4-15, 2025 (12 days) |
| Total events | 1,532 |
| Emails viewed | 1,267 |
| **Emails sent to attacker domains** | **2** |
| **Emails permanently deleted** | **7** |

**Confirmed Exfiltration:**
1. **Dec 10, 12:05 CST** - Email sent to `jhalstead-wiggins@ssdhvca.com` (attacker domain)
2. **Dec 15, 07:40 CST** - "Re: Cintas Invoices/Payments" sent to `lori.maynard@aksmoss.com`

Both emails were **deleted within seconds** to destroy evidence.

Initial conclusion was wrong because we searched for the Dec 1 login IPs in email activity. The attacker used a **different IP** for sustained operations, leveraging the OAuth token obtained during initial compromise.

### SENT Folder Analysis (Revised)

Initial SENT folder analysis showed 62 emails with no deletions. However, **Admin Email Log Search captures events that Gmail folder counts don't** - including permanently deleted emails.

The comprehensive event log (lori-all.csv) revealed:
- **7 emails permanently deleted** by attacker (not visible in SENT folder count)
- **2 of these were exfiltration emails** sent to attacker domains

Gmail's SENT label count only reflects **current** state, not historical. The attacker's deletion of sent emails within seconds removed them before any folder sync could capture them.

### SMTP-Level Verification: Admin Email Log Search

We conducted an Admin Email Log Search to verify all emails sent from Lori's account at the SMTP level. This analysis revealed important context:

| Metric | Count |
|--------|-------|
| Unique Message-IDs in Admin Log | 259 |
| Emails in Gmail SENT folder | 62 |
| **Apparent discrepancy** | **197** |

**Analysis of discrepancy:**

The Admin Email Log shows more entries because it includes:
1. **Abnormal Security processing** - 93 emails appear from BOTH office IP and AWS IPs (Abnormal Security reprocessing copies for threat analysis)
2. **Calendar responses** - 5 auto-generated calendar acceptances ("Accepted: Secret Santa...")
3. **Multi-recipient logging** - Same email to multiple recipients logged separately
4. **Internal routing** - Emails to @askmoss.com and @mossutilities.com may have additional routing entries

**IP Source Analysis:**

| Source | Unique Emails | Notes |
|--------|---------------|-------|
| Office (199.200.88.186) | 237 | Lori's legitimate sends |
| AWS/Abnormal Security | 110 | Security processing (93 overlap with office) |
| Mobile (IPv6) | 13 | AT&T cellular |
| Other | 6 | Various including calendar system |

**Critical finding: Attacker IPs NOT found in email sends:**
```
172.120.137.37 (Secaucus, NJ)   - NOT FOUND
45.87.125.150 (Los Angeles, CA) - NOT FOUND
46.232.34.229 (New York, NY)    - NOT FOUND
```

This confirms the attacker only had **READ access** and did not send any emails from Lori's account.

### Attacker's Operational Pattern

The attacker's strategy was intelligence-gathering, not impersonation:

1. **Access Lori's mailbox** → Read invoice threads with Standard Supply
2. **Extract Message-IDs** → Enable thread injection attacks
3. **Send FROM typosquat domain** → Impersonate Janet at `ssdhvca.com`
4. **Intercept replies** → Lori's responses went to attacker-controlled domain

The attacker did not need to send emails as Lori because:
- They already had visibility into her inbox
- Their goal was to impersonate the VENDOR (Standard Supply), not Moss

### Sent Folder Analysis (Dec 1-17)

External domains Lori emailed during compromise window:
- `cintas.com` - Legitimate vendor (fire protection)
- `lennox.com` - Legitimate vendor (HVAC equipment)
- `reece.com` - Legitimate vendor
- `shearersupply.com` - Legitimate vendor
- `veteransac.com` - Legitimate contact

No suspicious external recipients identified.

---

## Technical Appendix

### Audit Log Sources

| Source | Events | Period |
|--------|--------|--------|
| Login events | 373 | Nov 23 - Dec 23, 2025 |
| Gmail events (Lori) | 12,670 | Nov 23 - Dec 23, 2025 |
| OAuth/Token events | 896 | Nov 23 - Dec 23, 2025 |
| Admin Email Log Search (Lori sends) | 672 rows / 259 unique | Dec 1 - Dec 17, 2025 |
| **Admin Email Log (All Events - lori-all.csv)** | **37,117 filtered / 515K+ total** | **Aug 16 - Dec 23, 2025** |

The comprehensive event log (lori-all.csv) was critical in discovering the Canadian VPS attacker activity that was not visible in the send-only export.

### Legitimate OAuth Applications

| Application | Purpose | Status |
|-------------|---------|--------|
| Abnormal Security | Email security monitoring | ✅ Legitimate |
| WiseStamp for Teams | Email signature management | ✅ Legitimate |

### Scripts Used

| Script | Purpose |
|--------|---------|
| `src/audit_logs.py` | Pull Google Workspace audit logs |
| `src/check_gmail_settings.py` | Verify Gmail settings for persistence |
| `src/list_users.py` | List users and 2FA enrollment status |
| `src/analyze_admin_log.py` | Analyze Admin Email Log Search exports |
| `src/analyze_admin_log_ips.py` | IP analysis of sent emails |
| `src/compare_message_ids.py` | Compare Message-IDs between sources |
| `src/categorize_missing.py` | Categorize emails by type and destination |
| `src/analyze_lori_all.py` | Comprehensive Gmail event analysis (lori-all.csv) |
| `src/deep_dive_suspicious.py` | Deep dive into suspicious IP activity |
| `src/attacker_timeline.py` | Build attacker activity timeline from Canadian VPS |

### Commands Executed

```bash
# List all users with 2FA status
python src/list_users.py

# Check Gmail settings
python src/check_gmail_settings.py --user lori.maynard@askmoss.com
python src/check_gmail_settings.py --user madelin.martinez@askmoss.com
python src/check_gmail_settings.py --user invoices@askmoss.com

# Pull audit logs
python src/audit_logs.py --user lori.maynard@askmoss.com --days 30
python src/audit_logs.py --user invoices@askmoss.com --days 30
```

---

## Conclusions

1. **Root cause identified:** Lori Maynard's Google account was compromised on December 1, 2025, due to lack of 2FA protection.

2. **Attack was more extensive than initially believed:** Attacker maintained active access for 12 days (Dec 4-15), viewed 1,267 emails, sent 2 exfiltration emails to attacker domains, and permanently deleted 7 emails to cover tracks.

3. **Data exfiltration confirmed:** At minimum, Cintas invoice data was sent to attacker-controlled domain. Additional data may have been exfiltrated via the blank-subject email to ssdhvca.com.

4. **Scope contained:** No other Moss accounts were accessed by the attacker. The compromise was limited to Lori's account.

5. **Remediation complete:** Password reset, 2FA enrolled, and account verified clean as of December 23, 2025.

6. **Systemic risk remains:** 83% of users lack 2FA, leaving the organization vulnerable to similar attacks.

7. **Standard Supply findings validated:** Their DFIR conclusion of "no compromise" is consistent with our analysis. The attack originated from the Moss side.

8. **Additional vendor risk:** Cintas should be notified that their invoice data may have been compromised and to watch for BEC attempts.

---

**Report Status:** Final (Revised Dec 23, 2025 - Canadian VPS findings added)
**Next Review:** After 2FA enforcement implementation
**Distribution:** Executive team, IT, Legal, Insurance (as needed)
**Related:** [Addendum - Canadian VPS Operations](addendum_20251223_canadian_vps.md)
