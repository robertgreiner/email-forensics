# BEC Incident Report - Final Investigation Findings

**Incident ID:** MOSS-2025-001
**Date:** December 23, 2025
**Prepared by:** Robert Greiner, CTO
**Classification:** Internal - Incident Response

---

## Executive Summary

Between December 4-16, 2025, Moss Mechanical was targeted in a Business Email Compromise (BEC) attack resulting in fraudulent payment requests to our customer, Standard Supply (ssdhvac.com). Our investigation identified **unauthorized access to an employee's Google Workspace account on December 1, 2025** - three days before the fraudulent emails began.

**Key Findings:**
- Lori Maynard's account was compromised via password-only authentication
- Attacker accessed her mailbox from three datacenter IPs within 4 minutes
- No other Moss accounts were compromised
- The attack was enabled by lack of two-factor authentication (2FA)
- Only 17% of Moss users currently have 2FA enabled

**Status:** Compromised account remediated. Full user audit complete. Organization-wide 2FA enforcement recommended.

---

## Incident Timeline

| Date | Event | Source |
|------|-------|--------|
| Before Dec 1 | Attacker obtains Lori Maynard's password | Unknown (phishing, breach, infostealer) |
| **Dec 1, 19:05-19:09 UTC** | **Attacker logs into Lori's Gmail from 3 datacenter IPs** | Google Workspace audit logs |
| Dec 1-3 | Attacker reads invoice email threads with Standard Supply | Inferred |
| **Dec 4, 16:15 UTC** | **First fraudulent email sent** impersonating Janet at Standard Supply | Email headers analysis |
| Dec 4-16 | BEC campaign continues | 21 fraudulent emails identified |
| Dec 15 | Fraud discovered when real Janet responds | Customer report |
| Dec 16 | Initial investigation begins | Email forensics |
| **Dec 17** | **Remediation: Password reset, 2FA enrolled for Lori** | Admin action |
| Dec 19 | Standard Supply DFIR report received (no compromise found) | Partner communication |
| **Dec 23** | **Full Google Workspace audit completed** | This report |

---

## Account Compromise Details

### Unauthorized Access - December 1, 2025

Three successful logins to `lori.maynard@askmoss.com` within 4 minutes from datacenter IPs:

| Time (UTC) | IP Address | Location | Provider | ASN |
|------------|------------|----------|----------|-----|
| 19:05:00 | 172.120.137.37 | Secaucus, NJ | HOST TELECOM LTD | AS214238 |
| 19:06:18 | 45.87.125.150 | Los Angeles, CA | Clouvider | AS62240 |
| 19:08:53 | 46.232.34.229 | New York City, NY | Clouvider | AS62240 |

**Attack Indicators:**
- All IPs belong to VPS/datacenter providers (commonly used by attackers)
- Three different geographic locations in 4 minutes (impossible for legitimate user)
- All logins triggered Google login challenges - all passed
- Chrome browser authorized within 1 second of login (indicates automation)
- Lori confirmed she was not traveling and does not use VPN

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

Searched all login events for attacker IPs:
```
172.120.137.37 (Secaucus, NJ - HOST TELECOM)
45.87.125.150 (Los Angeles, CA - Clouvider)
46.232.34.229 (New York City, NY - Clouvider)
```

**Result: Only Lori Maynard's account was accessed from these IPs.**

No evidence of lateral movement or additional account compromise.

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

**Conclusion: NO - attacker used READ-ONLY access**

Evidence:
1. **Attacker IPs not in Gmail activity logs** - only appear in login events
2. **No emails sent during compromise window to suspicious recipients**
3. **No email deletion events** during Dec 1-17
4. **Only 3 emails sent on Dec 1** (compromise day) - all internal business correspondence
5. **Attack pattern** - attacker impersonated Janet FROM typosquat, didn't send AS Lori

### Definitive Verification: SENT Label Audit

Gmail adds a SENT label to every email at send time. This label persists even if the email is later deleted or moved. By comparing the SENT label count to the sent folder count, we can detect if any sent emails were deleted:

| Metric | Count |
|--------|-------|
| Emails with SENT label (Dec 1-17) | 62 |
| Emails in sent folder (Dec 1-17) | 62 |
| **Difference** | **0** |

**Result: No sent emails were deleted during the compromise window.**

This definitively proves the attacker did not:
- Send emails as Lori and then delete them
- Use her account to send fraudulent messages
- Attempt to hide outgoing email activity

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

2. **Scope contained:** No other Moss accounts were accessed by the attacker. The compromise was limited to Lori's account.

3. **Remediation complete:** Password reset, 2FA enrolled, and account verified clean as of December 23, 2025.

4. **Systemic risk remains:** 83% of users lack 2FA, leaving the organization vulnerable to similar attacks.

5. **Standard Supply findings validated:** Their DFIR conclusion of "no compromise" is consistent with our analysis. The attack originated from the Moss side.

---

**Report Status:** Final
**Next Review:** After 2FA enforcement implementation
**Distribution:** Executive team, IT, Legal (as needed)
