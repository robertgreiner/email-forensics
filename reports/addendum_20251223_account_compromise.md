# BEC Investigation Addendum - Account Compromise Analysis

**Date:** December 23, 2025
**Analyst:** Robert Greiner, CTO
**Purpose:** Document findings from Google Workspace audit log analysis

---

## Executive Summary

Following Standard Supply's DFIR report (which found no evidence of compromise in their environment), we conducted an audit of Moss Mechanical's Google Workspace environment. **We discovered evidence of unauthorized access to Lori Maynard's Gmail account on December 1, 2025** - three days before the first fraudulent email was sent.

This finding **revises our original hypothesis**. The attacker likely gained visibility into the invoice email threads by accessing Lori's mailbox, not Janet's. Standard Supply's DFIR conclusion may be correct.

---

## Key Finding: Unauthorized Account Access

### Suspicious Login Events - December 1, 2025

| Time (UTC) | IP Address | Location | Provider | Event |
|------------|------------|----------|----------|-------|
| 19:05:00 | 172.120.137.37 | Secaucus, NJ | HOST TELECOM (datacenter) | login_challenge → **PASSED** |
| 19:05:00 | 172.120.137.37 | Secaucus, NJ | HOST TELECOM (datacenter) | login_success |
| 19:05:00 | 172.120.137.37 | Secaucus, NJ | HOST TELECOM (datacenter) | Chrome authorized |
| 19:06:18 | 45.87.125.150 | Los Angeles, CA | Clouvider (VPS/datacenter) | login_challenge → **PASSED** |
| 19:06:18 | 45.87.125.150 | Los Angeles, CA | Clouvider (VPS/datacenter) | login_success |
| 19:06:19 | 45.87.125.150 | Los Angeles, CA | Clouvider (VPS/datacenter) | Chrome authorized |
| 19:08:53 | 46.232.34.229 | New York City, NY | Clouvider (VPS/datacenter) | login_challenge → **PASSED** |
| 19:08:53 | 46.232.34.229 | New York City, NY | Clouvider (VPS/datacenter) | login_success |
| 19:08:54 | 46.232.34.229 | New York City, NY | Clouvider (VPS/datacenter) | Chrome authorized |

### Analysis

**Three different datacenter IPs in 4 minutes:**
- All from VPS/hosting providers (commonly used by attackers)
- All triggered Google login challenges (risk-based authentication)
- All challenges were **passed** (not blocked)
- All immediately authorized "Google Chrome" as a native desktop client
- Authorization happened within 1 second of login (indicates automation)

**Lori confirmed she does not use VPN and was not traveling on December 1st.**

### Why Challenges Passed

At the time of the incident:
- **Lori did not have 2FA enabled**
- Login challenges were likely CAPTCHA or "is this you?" prompts
- `login_challenge_method: None` indicates no strong second factor was required
- Attacker only needed Lori's password

---

## Revised Attack Timeline

| Date | Event | Evidence |
|------|-------|----------|
| Before Dec 1 | Attacker obtains Lori's password | Unknown vector (phishing, infostealer, credential reuse, breach) |
| **Dec 1, 19:05-19:09 UTC** | **Attacker logs into Lori's Gmail from 3 datacenter IPs** | Google Workspace audit logs |
| Dec 1-3 | Attacker reads invoice email threads, extracts Message-IDs | Inferred from subsequent attack |
| **Dec 4, 16:15 UTC** | **First fraudulent email sent** | Email headers analysis |
| Dec 4-16 | Ongoing BEC fraud campaign | 21 fraudulent emails sent |
| Dec 15 | Fraud discovered | Real Janet responds |
| **Dec 17** | **Remediation: Password reset, 2FA enrolled** | Google Workspace audit logs |
| Dec 23 | This analysis conducted | - |

---

## Comparison: Original vs. Revised Hypothesis

### Original Hypothesis (Dec 16)
> Standard Supply (ssdhvac.com) experienced a read-access compromise of Janet's mailbox. Attacker could see incoming emails from Lori, including Message-IDs.

### Revised Hypothesis (Dec 23)
> Moss Mechanical experienced an account compromise of Lori's Gmail. Attacker could see the entire email thread (both incoming and outgoing), including all Message-IDs.

### Why This Matters

**Original logic was:**
- Attacker knew Lori's outgoing Message-IDs
- Only recipients of Lori's emails would have those IDs
- Therefore, Standard Supply was compromised

**Revised understanding:**
- Attacker **accessed Lori's mailbox directly**
- Could see both sent and received emails
- Could extract Message-IDs from either
- Standard Supply's "clean" DFIR finding is consistent with this

---

## Remediation Actions Taken

### December 17, 2025 (by Robert Greiner)
| Action | Status | Evidence |
|--------|--------|----------|
| Password reset | ✅ Complete | `password_edit` event in audit log |
| 2FA enrollment | ✅ Complete | `2sv_enroll` event in audit log |
| Session invalidation | ✅ Complete | All sessions signed out |

### December 23, 2025 (verification)
| Check | Result |
|-------|--------|
| Auto-forwarding | ✅ NOT enabled |
| Email filters | ✅ None configured |
| Mailbox delegates | ✅ None configured |
| Send-as addresses | ✅ Only primary address |
| IMAP/POP access | ✅ Disabled |
| Vacation responder | ✅ OFF |

### Pending Verification
| Item | Status |
|------|--------|
| Passkey (Galaxy S25 Ultra) | ⚠️ Verify this is Lori's device |
| App passwords | ⚠️ Check if any exist |
| Password source | ⚠️ Determine how password was compromised |

---

## Outstanding Questions

### 1. How was Lori's password obtained?
Possible vectors:
- Phishing email (check Lori's inbox for suspicious emails before Dec 1)
- Credential stuffing from a data breach (check haveibeenpwned.com)
- Infostealer malware on her workstation
- Password reuse from another compromised account

### 2. Is the Galaxy S25 Ultra passkey legitimate?
- Created: November 9, 2025 (before the compromise)
- If it's Lori's phone: Legitimate, adds security
- If it's not Lori's phone: Attacker device, remove immediately

### 3. Were other Moss accounts compromised?
- Need to audit all users involved in Standard Supply communications
- Specifically: Anyone CC'd on invoice threads

---

## Implications for Standard Supply Response

Standard Supply's DFIR found no evidence of compromise in their environment. **Our findings are now consistent with theirs:**

- The attacker did not need access to Standard Supply's systems
- Access to Lori's mailbox provided all necessary information:
  - Full thread history
  - Message-IDs for thread injection
  - Business context and timing
  - Invoice details

### Recommended Communication to Standard Supply

> "Following our own internal investigation of Google Workspace audit logs, we identified unauthorized access to an employee account on December 1, 2025 - prior to the fraud emails being sent. This is consistent with your DFIR findings. We have completed remediation including password reset and 2FA enrollment."

---

## Audit Log Data Sources

| Source | Records | Period |
|--------|---------|--------|
| Login events | 22 | Nov 23 - Dec 23, 2025 |
| Gmail events | 12,670 | Nov 23 - Dec 23, 2025 |
| OAuth/Token events | 896 | Nov 23 - Dec 23, 2025 |

### Legitimate OAuth Applications Identified
| App | Purpose | Status |
|-----|---------|--------|
| Abnormal Security | Email security monitoring | ✅ Legitimate |
| WiseStamp for Teams | Email signature management | ✅ Legitimate |

---

## Technical Details

### IP Address Analysis

**Legitimate IP (Moss Mechanical office):**
```
199.200.88.186
Location: Farmers Branch, TX
Provider: Unite Private Networks LLC
Usage: Regular logins throughout the period
```

**Suspicious IPs (December 1st compromise):**
```
172.120.137.37
Location: Secaucus, NJ
Provider: HOST TELECOM LTD (AS214238)
Type: Datacenter/hosting

45.87.125.150
Location: Los Angeles, CA
Provider: Clouvider (AS62240)
Type: VPS/datacenter - commonly used by VPNs and attackers

46.232.34.229
Location: New York City, NY
Provider: Clouvider (AS62240)
Type: VPS/datacenter - commonly used by VPNs and attackers
```

### Login Challenge Details

```
login_challenge_method: None
login_challenge_status: passed
is_suspicious: None
```

The `None` values indicate:
- No strong 2FA method was configured
- Challenge was likely a basic verification (CAPTCHA, device prompt)
- Google did not flag as suspicious (despite datacenter IPs)

---

## Scripts Used for Analysis

| Script | Purpose | Location |
|--------|---------|----------|
| `audit_logs.py` | Pull Google Workspace audit logs | `src/audit_logs.py` |
| `check_gmail_settings.py` | Check Gmail settings for persistence | `src/check_gmail_settings.py` |

### Commands Executed

```bash
# Check Gmail settings
python src/check_gmail_settings.py --user lori.maynard@askmoss.com

# Pull 30-day audit logs
python src/audit_logs.py --user lori.maynard@askmoss.com --days 30

# Pull Dec 1st specific logs
python src/audit_logs.py --user lori.maynard@askmoss.com --start 2025-12-01 --end 2025-12-02
```

---

## Conclusions

1. **Lori Maynard's Google account was compromised on December 1, 2025**
   - Unauthorized logins from 3 datacenter IPs within 4 minutes
   - No 2FA was enabled at the time
   - Attacker passed login challenges

2. **This explains the attacker's knowledge of the email threads**
   - Direct access to Lori's inbox = full thread visibility
   - No need to compromise Standard Supply

3. **Standard Supply's DFIR findings are consistent with our analysis**
   - They found no compromise because there likely wasn't one
   - The compromise was on Moss Mechanical's side

4. **Remediation is complete but password source is unknown**
   - Need to determine how attacker obtained Lori's password
   - Check for credential exposure, phishing, or malware

---

---

## User Account Audit Results

### Audit Date: December 23, 2025

| User | Gmail Settings | Login Activity | Suspicious IPs | Status |
|------|----------------|----------------|----------------|--------|
| lori.maynard@askmoss.com | ✅ Clean | ⚠️ Compromised Dec 1 | 3 datacenter IPs | **Remediated Dec 17** |
| madelin.martinez@askmoss.com | ✅ Clean | ✅ Clean (4 logins, all legit) | None | **OK** |

### Lori Maynard - Detailed Findings
- **Dec 1, 2025:** Unauthorized access from 3 datacenter IPs (Clouvider, HOST TELECOM)
- **Dec 17, 2025:** Password reset, 2FA enrolled, sessions invalidated
- **Post-remediation:** All logins from legitimate IPs (office + AT&T residential)

### Madelin Martinez - Detailed Findings
- **Login history:** Only 4 logins in 30 days
- **All IPs legitimate:** Office (199.200.88.186) + AT&T Dallas residential
- **Gmail settings:** No forwarding, no filters, no delegates
- **Status:** No evidence of compromise

---

## Full User Audit Results

### Audit Scope
- **Total users in Google Workspace:** 91
- **Active users:** 89 (2 suspended)
- **Audit method:** Cross-referenced suspicious IPs against all login events (30 days)

### Suspicious IP Search Results

Searched all 373 login events for attacker IPs:
- `172.120.137.37` (Secaucus, NJ - HOST TELECOM)
- `45.87.125.150` (Los Angeles, CA - Clouvider)
- `46.232.34.229` (New York, NY - Clouvider)

**Result: Only Lori Maynard's account was accessed from these IPs.**

No other user accounts show evidence of compromise from the same threat actor.

### Individual Account Checks

| Account | Login Activity | Gmail Settings | Status |
|---------|---------------|----------------|--------|
| lori.maynard@askmoss.com | Compromised Dec 1 | Clean | **Remediated** |
| madelin.martinez@askmoss.com | Clean (4 logins, all legit) | Clean | **OK** |
| invoices@askmoss.com | Clean (2 logins, office IP only) | Clean | **OK** |

---

## CRITICAL FINDING: 2FA Adoption Gap

### Current State
| Metric | Count | Percentage |
|--------|-------|------------|
| Active users | 89 | 100% |
| **With 2FA enabled** | **15** | **17%** |
| **WITHOUT 2FA** | **74** | **83%** |

### Risk Assessment

The lack of 2FA directly contributed to the December 1st compromise:
- Lori's account had no 2FA at the time of attack
- Login challenges were passed with password only
- Attacker gained full mailbox access

**83% of active users remain vulnerable to the same attack vector.**

### Users WITH 2FA (15 users)
- aimee.cooley@askmoss.com
- april.posey@askmoss.com
- chris.mariot@askmoss.com
- clayton.hampton@askmoss.com
- garrett.moss@askmoss.com
- info@mossmechanical.com
- josh.moulden@askmoss.com
- kelly.roberts@askmoss.com
- kevyn.ritchey@askmoss.com
- lori.lierman@askmoss.com
- lori.maynard@askmoss.com (enrolled Dec 17 post-incident)
- marshal.sproull@askmoss.com
- matthew.gilmore@askmoss.com
- robert.greiner@askmoss.com
- voicemail@mossmechanical.com

### High-Risk Accounts WITHOUT 2FA (accounting/finance)
- madelin.martinez@askmoss.com (Accounts Payable Specialist)
- invoices@askmoss.com (shared mailbox)

---

## Recommendations

### Immediate (This Week)
1. **Enforce 2FA for all accounting/finance users**
   - madelin.martinez@askmoss.com
   - invoices@askmoss.com
   - Any user handling payments or invoices

2. **Verify Lori's passkey device**
   - Galaxy S25 Ultra passkey created Nov 9, 2025
   - Confirm this is Lori's personal device

### Short-Term (30 Days)
3. **Enable mandatory 2FA for all users**
   - Google Workspace Admin Console > Security > 2-Step Verification
   - Set enforcement with grace period for enrollment

4. **Investigate credential theft vector**
   - Check haveibeenpwned.com for lori.maynard@askmoss.com
   - Review for phishing emails before Dec 1
   - Check for password reuse from breached sites

### Long-Term
5. **Implement security awareness training**
   - Focus on phishing recognition
   - Password hygiene and unique passwords
   - BEC fraud indicators

6. **Consider advanced protections**
   - Context-aware access policies
   - Abnormal Security alerting for datacenter IP logins
   - FIDO2 security keys for privileged accounts

---

**Report Generated:** December 23, 2025
**Classification:** Internal - Incident Response
**Status:** Full user audit complete. Recommend immediate 2FA enforcement.
