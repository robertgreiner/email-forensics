# Executive Summary: BEC Attacks on Moss Portfolio Companies

**Date:** December 25, 2025
**Prepared by:** Robert Greiner, CTO
**For:** Garrett Moss (CEO, Moss Utilities), Kelly Roberts (CSO Moss Utilities, CEO Moss HVAC), Sean (CFO, Moss Utilities)
**Classification:** Executive Briefing

---

## Overview

In early December 2025, two Moss portfolio companies were targeted in coordinated Business Email Compromise (BEC) attacks on consecutive days:

| Company | Tenant | Compromised Account | Date | Duration |
|---------|--------|---------------------|------|----------|
| Moss HVAC | askmoss.com | Lori Maynard | Dec 1, 2025 | 12 days |
| Moss Utilities | mossutilities.com | Vaughn Muller | Dec 2, 2025 | 14 days |

**Bottom Line:** Both attacks exploited accounts without two-factor authentication (2FA). No financial loss occurred, but the attacks reveal a critical security gap requiring immediate attention.

---

## What Happened

### Moss HVAC (Lori Maynard - Dec 1)

An attacker gained access to Lori Maynard's email account and used it to:
- Monitor email conversations for 12 days
- Exfiltrate invoice data (Cintas, Standard Supply)
- Facilitate a fraud attempt against Standard Supply ($300K payment)

**The fraud failed because Standard Supply verified the payment request through a phone call.**

### Moss Utilities (Vaughn Muller - Dec 2)

An attacker gained access to Vaughn Muller's email account and used it to:
- Monitor financial emails (payment apps, bids, invoices) for 14 days
- Send 3 fraudulent emails to Christina and Alamara requesting aging invoices
- Create an email filter to hide responses

**The fraud failed because Christina flagged the suspicious email as spam.**

---

## How We Investigated

### Process

1. **Initial Alert:** Customer/employee reported suspicious email activity
2. **Account Lockdown:** Password reset and 2FA enrollment
3. **Audit Log Analysis:** Pulled Google Workspace login and activity logs
4. **IP Investigation:** Traced attacker IPs to datacenter/VPS providers
5. **Email Export Analysis:** Analyzed complete email activity for attacker actions
6. **Full User Audit:** Scanned all users in both tenants for compromise
7. **Persistence Check:** Verified no backdoors (forwarding, filters, delegates)
8. **Remediation Verification:** Confirmed attacker locked out

### Tools Used

- Google Workspace Admin Reports API
- Custom Python scripts for log analysis
- WHOIS/IP reputation databases
- Gmail API for settings verification

---

## What We Know

### Attack Attribution

| Factor | Lori (HVAC) | Vaughn (Utilities) | Assessment |
|--------|-------------|-------------------|------------|
| Attack Date | Dec 1 | Dec 2 | 1 day apart |
| Attacker IPs | 5 unique | 5 unique | Different IPs |
| IP Overlap | None | None | Different infrastructure |
| Attack Method | Password only | Password only | Same technique |
| Target Type | Accounting | Estimating/Finance | Similar roles |

**Likely same threat actor** using different VPS providers for each attack, or credentials obtained from the same source (breach database, dark web marketplace).

### Confirmed Facts

| Finding | Moss HVAC | Moss Utilities |
|---------|-----------|----------------|
| Account compromised | ✅ Lori Maynard | ✅ Vaughn Muller |
| 2FA enabled at time | ❌ No | ❌ No |
| Duration of access | 12 days | 14 days |
| Emails accessed | 1,267+ | Hundreds |
| BEC emails sent | 4 (to attacker domains) | 3 (to internal staff) |
| Other accounts compromised | None | None |
| Financial loss | $0 | $0 |
| Account remediated | ✅ Dec 17 | ✅ Dec 16-19 |
| Attacker locked out | ✅ Confirmed | ✅ Confirmed |

---

## How We Remediated

### Immediate Actions (Complete)

| Action | Moss HVAC | Moss Utilities |
|--------|-----------|----------------|
| Password reset | ✅ Dec 17 | ✅ Dec 16 |
| 2FA enrollment | ✅ Dec 17 | ✅ Dec 19 |
| Session invalidation | ✅ | ✅ |
| Malicious filter removed | N/A | ✅ Dec 25 |
| Email settings verified | ✅ Clean | ✅ Clean |
| Full user audit | ✅ Complete | ✅ Complete |

### Current Security Posture

| Metric | Moss HVAC | Moss Utilities |
|--------|-----------|----------------|
| Total users | 89 | 217 |
| 2FA enabled | 15 (17%) | 6 (3%) |
| 2FA NOT enabled | 74 (83%) | 211 (97%) |

**Critical Gap:** The vast majority of users in both organizations remain vulnerable to identical attacks.

---

## Proposed Next Steps

### Immediate (This Week)

1. **Verify no financial impact**
   - Confirm Christina and Alamara did not act on fraudulent requests
   - Review any recent payment changes or new vendor bank accounts

2. **Protect finance users first**
   - Mandatory 2FA for all users with payment authority
   - Priority: Accounting, AP/AR, CFO, Controller

### Short-Term (30 Days)

3. **Enforce mandatory 2FA organization-wide**
   - Google Workspace setting: Security > 2-Step Verification > Enforcement
   - Set 14-day grace period for enrollment
   - Communicate to all employees with clear instructions

4. **Deploy phishing-resistant authentication**
   - Hardware security keys for executives and finance
   - Passkeys (device-based) for general users
   - Eliminate SMS-based 2FA where possible

### Medium-Term (90 Days)

5. **Implement advanced security controls**
   - Login anomaly detection (datacenter IP alerts)
   - Context-aware access policies
   - Abnormal Security tuning for BEC detection

6. **Security awareness training**
   - BEC fraud recognition
   - Payment verification procedures
   - Reporting suspicious emails

### Long-Term (Ongoing)

7. **Regular security audits**
   - Quarterly 2FA adoption review
   - Annual penetration testing
   - Continuous monitoring of login patterns

---

## Business Impact Summary

### What Could Have Happened

| Scenario | Potential Loss |
|----------|----------------|
| Standard Supply ACH fraud (Moss HVAC) | $300,600.82 |
| Vendor payment fraud (Moss Utilities) | Unknown (prevented) |
| Regulatory/legal exposure | Data breach notification costs |
| Reputation damage | Customer/partner trust |

### What Actually Happened

| Impact | Amount |
|--------|--------|
| Financial loss | $0 |
| Data exfiltrated | Invoice/payment data (extent unknown) |
| Downtime | None |
| Remediation cost | Internal staff time only |

### Why We Got Lucky

1. **Standard Supply** called to verify the $300K payment request
2. **Christina** recognized the suspicious email and flagged it as spam
3. **Both attackers** were detected before completing their fraud

**Without these interventions, losses could have been substantial.**

---

## Key Takeaways

1. **The attacks were sophisticated but preventable.** Simple 2FA would have stopped both compromises at the login stage.

2. **The attackers were patient.** They maintained access for 12-14 days, studying email patterns before striking.

3. **Our people saved us.** Employee vigilance (Christina) and partner verification (Standard Supply) prevented losses.

4. **Systemic risk remains high.** With 83-97% of users lacking 2FA, we are vulnerable to identical attacks tomorrow.

5. **The attacks may be connected.** Consecutive days, same technique, different infrastructure suggests coordinated targeting of Moss portfolio.

---

## Recommendation Summary

| Priority | Action | Owner | Timeline |
|----------|--------|-------|----------|
| 🔴 Critical | Mandatory 2FA for finance users | IT | This week |
| 🔴 Critical | Verify no payment fraud occurred | Finance | This week |
| 🟠 High | Organization-wide 2FA enforcement | IT | 30 days |
| 🟠 High | Security keys for executives | IT | 30 days |
| 🟡 Medium | Login anomaly alerting | IT | 60 days |
| 🟡 Medium | Security awareness training | HR/IT | 90 days |

---

## Questions?

Robert Greiner is available to discuss findings and answer questions.

**Detailed Reports Available:**
- `incident_report_20251223_final.md` - Moss HVAC (Lori Maynard)
- `mossutilities_incident_report_20251225.md` - Moss Utilities (Vaughn Muller)

---

**Document Status:** Final
**Distribution:** Garrett Moss, Kelly Roberts, Sean (CFO)
**Classification:** Internal - Executive
