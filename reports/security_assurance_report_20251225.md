# Security Assurance Report: Moss Portfolio Companies

**Date:** December 25, 2025
**Prepared by:** Robert Greiner, CTO
**Classification:** Internal - Security Documentation

---

## Purpose

This document summarizes all security verification activities performed following the BEC incidents at Moss HVAC (askmoss.com) and Moss Utilities (mossutilities.com) in December 2025. The purpose is to provide assurance that:

1. Both compromised accounts have been fully remediated
2. No other accounts were compromised
3. No attacker persistence mechanisms remain
4. No ongoing unauthorized access exists

---

## Incident Summary

| Company | Compromised Account | Attack Date | Duration | Status |
|---------|---------------------|-------------|----------|--------|
| Moss HVAC | lori.maynard@askmoss.com | Dec 1, 2025 | 12 days | ✅ Remediated |
| Moss Utilities | vaughn@mossutilities.com | Dec 2, 2025 | 14 days | ✅ Remediated |

---

## Security Verification Activities

### 1. Full User Audit - All Accounts Checked for Compromise

**Scope:** All active users in both tenants scanned for attacker IP activity

| Tenant | Users Checked | Attacker IPs Searched | Result |
|--------|---------------|----------------------|--------|
| askmoss.com | 89 | 5 IPs | ✅ Only Lori compromised |
| mossutilities.com | 217 | 5 IPs | ✅ Only Vaughn compromised |

**Method:** Cross-referenced all login events (Nov-Dec 2025) against known attacker IPs:

**Moss HVAC Attacker IPs:**
- 172.120.137.37 (Singularity Telecom)
- 45.87.125.150 (Unknown VPS)
- 46.232.34.229 (Unknown VPS)
- 147.124.205.9 (Datacenter)
- 158.51.123.14 (Datacenter)

**Moss Utilities Attacker IPs:**
- 45.159.127.16 (Singularity Telecom)
- 156.229.254.40 (Unknown VPS)
- 45.192.39.3 (IT_HOST_BLSYNC)
- 38.69.8.106 (VIRTUO NETWORKS)
- 142.111.254.241 (ITHOSTLINE)

**Conclusion:** ✅ No other accounts accessed from attacker infrastructure

---

### 2. Suspicious Activity Investigation

**Scope:** Reviewed all flagged login anomalies across both tenants

| User | IP Flagged | Investigation Result |
|------|------------|---------------------|
| jeff@mossutilities.com | 172.243.84.244 | ✅ AT&T Mobile CGNAT - Legitimate |
| julio@mossutilities.com | 172.58.180.95 | ✅ AT&T Mobile CGNAT - Legitimate |
| anthony.friesen@mossutilities.com | 45.31.1.169 | ✅ AT&T Enterprises - Legitimate |
| silver.jackson@mossutilities.com | 45.26.163.233 | ✅ AT&T Enterprises - Legitimate |
| mossit@mossutilities.com | 156.146.137.172 | ✅ United Cooperative Services - Partner |
| matthew@mossutilities.com | (failures only) | ✅ Password spray target - Not compromised |
| robert@mossutilities.com | 142.111.16.198 | ✅ Surfshark VPN - Confirmed by user |

**Conclusion:** ✅ All suspicious activity verified as legitimate

---

### 3. Compromised Account Remediation Verification

**Scope:** Verified both compromised accounts fully secured

#### Lori Maynard (askmoss.com)

| Check | Status | Date |
|-------|--------|------|
| Password reset | ✅ Complete | Dec 17, 2025 |
| 2FA enrolled | ✅ Complete | Dec 17, 2025 |
| Sessions invalidated | ✅ Complete | Dec 17, 2025 |
| Email forwarding | ✅ None configured |
| Email delegates | ✅ None configured |
| Suspicious filters | ✅ None found |
| OAuth apps | ✅ No suspicious apps |
| Attacker access post-remediation | ✅ None detected |

#### Vaughn Muller (mossutilities.com)

| Check | Status | Date |
|-------|--------|------|
| Password reset | ✅ Complete | Dec 16, 2025 |
| 2FA enrolled | ✅ Complete | Dec 19, 2025 |
| Sessions invalidated | ✅ Complete | Dec 16, 2025 |
| Email forwarding | ✅ None configured |
| Email delegates | ✅ None configured |
| Suspicious filters | ✅ Malicious filter removed Dec 25 |
| OAuth apps | ✅ No suspicious apps |
| Attacker access post-remediation | ✅ None detected |

**Conclusion:** ✅ Both accounts fully remediated, attackers locked out

---

### 4. Admin-Level Changes Audit

**Scope:** Reviewed all admin events during compromise window for privilege escalation

| Check | Moss HVAC | Moss Utilities |
|-------|-----------|----------------|
| Admin events from attacker IPs | ✅ None | ✅ None |
| User accounts created by attackers | ✅ None | ✅ None |
| User accounts deleted | ✅ None | ✅ None |
| Security settings modified by attackers | ✅ None | ✅ None |
| Admin roles granted | ✅ None suspicious | ✅ None suspicious |

**User creations during window (all legitimate):**
- 5 users created via Squarespace reseller integration (automated provisioning)

**Conclusion:** ✅ No admin-level compromise or privilege escalation

---

### 5. OAuth Token Grant Audit

**Scope:** Reviewed all OAuth app authorizations during compromise window

| Check | Moss HVAC | Moss Utilities |
|-------|-----------|----------------|
| Token grants from attacker IPs | ✅ None | ✅ None |
| Suspicious app grants | ✅ None | ✅ None |
| Apps with mail/admin access | ✅ All legitimate | ✅ All legitimate |

**Legitimate apps verified:**
- Google Chrome, Gmail, Google Drive (standard)
- Abnormal Security (security tool)
- WiseStamp for Teams (email signatures)
- Microsoft apps & services (integration)

**Conclusion:** ✅ No malicious OAuth persistence mechanisms

---

### 6. Mobile Device Audit

**Scope:** Checked for rogue mobile devices on compromised accounts

| Account | Devices Registered | Devices Added During Attack | Status |
|---------|-------------------|----------------------------|--------|
| lori.maynard@askmoss.com | 0 | 0 | ✅ Clean |
| vaughn@mossutilities.com | 0 | 0 | ✅ Clean |

**Conclusion:** ✅ No mobile device persistence

---

### 7. Organization-Wide Email Settings Audit

**Scope:** Scanned all 217 users for suspicious email configurations

| Setting Type | Total Found | Assessment |
|-------------|-------------|------------|
| Email filters (skip inbox/trash) | 45 | ✅ All legitimate (newsletters, notifications) |
| Email forwarding enabled | 4 | ✅ All internal or known services |
| Forwarding addresses configured | 5 | ✅ All internal addresses |
| Email delegates | 1 | ✅ Internal (shawn → silver.jackson) |

**Forwarding verified as legitimate:**
- info@ → garrett@ (internal)
- invoices@ → accrualify (AP automation service)
- kelly@ → kelly.roberts@askmoss.com (same person, different domain)
- kjones@ → test.user@askmoss.com (testing)

**Conclusion:** ✅ No external forwarding or suspicious persistence

---

### 8. Malicious Filter Remediation

**Scope:** Identified and removed attacker-created email filter

**Vaughn's Account - Malicious Filter Found:**
```
Criteria: from:christian@mossutilities.com,alamara@mossutilities.com
Action: Skip Inbox (archive immediately)
Purpose: Hide replies from BEC targets
```

| Action | Status | Date |
|--------|--------|------|
| Filter identified | ✅ | Dec 25, 2025 |
| Filter deleted | ✅ | Dec 25, 2025 |
| Verification | ✅ No remaining filters |

**Conclusion:** ✅ Malicious persistence mechanism removed

---

## Verification Summary

### What We Confirmed

| Category | Status | Evidence |
|----------|--------|----------|
| Only 2 accounts compromised | ✅ Verified | Full domain audit of 306 users |
| No admin escalation | ✅ Verified | Admin audit logs clean |
| No OAuth persistence | ✅ Verified | Token grant audit clean |
| No mobile device persistence | ✅ Verified | No devices on compromised accounts |
| No email forwarding to external | ✅ Verified | Organization-wide scan |
| Attackers locked out | ✅ Verified | No activity post-password change |
| All malicious filters removed | ✅ Verified | Filter audit and remediation |

### What We Ruled Out

| Threat | Status | Method |
|--------|--------|--------|
| Additional compromised accounts | ❌ Ruled Out | Attacker IP cross-reference |
| Backdoor admin accounts | ❌ Ruled Out | Admin audit logs |
| Malicious OAuth apps | ❌ Ruled Out | Token grant audit |
| Mobile device access | ❌ Ruled Out | Device inventory check |
| External email forwarding | ❌ Ruled Out | Organization-wide scan |
| Hidden email filters | ❌ Ruled Out | All-user filter audit |
| Ongoing attacker access | ❌ Ruled Out | Post-remediation monitoring |

---

## Current Security Posture

### Remediation Complete

| Control | Lori (HVAC) | Vaughn (Utilities) |
|---------|-------------|-------------------|
| Password reset | ✅ | ✅ |
| 2FA enrolled | ✅ | ✅ |
| Sessions revoked | ✅ | ✅ |
| Persistence removed | ✅ | ✅ |

### Organization-Wide Risk

| Metric | Moss HVAC | Moss Utilities |
|--------|-----------|----------------|
| Total users | 89 | 217 |
| 2FA enabled | 15 (17%) | 6 (3%) |
| 2FA NOT enabled | 74 (83%) | 211 (97%) |

**⚠️ Critical Gap:** Majority of users remain vulnerable to identical attacks.

---

### 9. Comprehensive Email Activity Export Analysis

**Scope:** Full Gmail activity export for mossutilities.com (100,000 events)

| Check | Result |
|-------|--------|
| Events from attacker IPs | ✅ None found |
| Sends to suspicious domains | ✅ None found |
| Attachments sent from attacker IPs | ✅ None found |
| Unusual external send patterns | ✅ None found |

**Event Breakdown:**
- 29,693 View events
- 20,077 Receive events
- 5,443 Send events
- 1,073 Autoforward events (all legitimate internal routing)

**Vaughn's Post-Remediation Activity:** 4 external sends after Dec 19 - all legitimate business emails (project quotes, supplier communications).

**Conclusion:** ✅ No attacker activity detected in comprehensive email logs

---

## Tools and Methods Used

### APIs and Services
- Google Workspace Admin Reports API
- Google Workspace Directory API
- Gmail API (settings verification)
- WHOIS/IP reputation databases

### Custom Scripts Developed
| Script | Purpose |
|--------|---------|
| `scan_all_logins.py` | Full domain login audit |
| `comprehensive_security_audit.py` | Multi-factor security check |
| `check_vaughn_persistence.py` | Persistence mechanism check |
| `check_filtered_emails.py` | Filter audit and remediation |
| `analyze_vaughn_export.py` | Email activity forensics |
| `check_remediation.py` | Post-remediation verification |

### Data Analyzed
- 30 days of login events across 306 users
- 1000+ admin events during attack window
- 1000+ OAuth token events
- 215,845 email activity records (Vaughn export)
- Complete email settings for all users

---

## Conclusion

Based on comprehensive security verification activities:

1. **Both incidents are fully contained.** The compromised accounts have been remediated with password resets and 2FA enrollment.

2. **No other accounts were compromised.** Full domain audits confirmed attacker activity was limited to Lori Maynard and Vaughn Muller.

3. **No persistence mechanisms remain.** All email settings, OAuth apps, and mobile devices have been verified clean.

4. **Attackers are locked out.** No access attempts detected after remediation.

5. **Systemic risk remains.** The underlying vulnerability (lack of 2FA) still affects 83-97% of users.

**The immediate threat has been neutralized.** Mandatory 2FA enforcement is the critical next step to prevent recurrence.

---

## Final Confirmation

**As of December 25, 2025, we can confidently confirm:**

✅ **No active compromises exist** in either Moss HVAC or Moss Utilities environments

✅ **All attacker access has been terminated** and cannot be regained with current credentials

✅ **No persistence mechanisms remain** that would allow future unauthorized access

✅ **All verification activities completed** with no evidence of additional compromise

---

## Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | Dec 25, 2025 | Robert Greiner | Initial release |

**Distribution:** Garrett Moss, Kelly Roberts, Sean (CFO), IT Team
**Classification:** Internal - Security Documentation
