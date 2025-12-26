# Complete Attacker IP Inventory

**Date:** December 23, 2025
**Status:** Final - Comprehensive Behavior-Based Analysis

---

## Summary

| Phase | IP Address | Provider | Location | Events | Purpose |
|-------|------------|----------|----------|--------|---------|
| Initial Login | 172.120.137.37 | HOST TELECOM LTD | Secaucus, NJ | 3 | Credential test |
| Initial Login | 45.87.125.150 | Clouvider | Los Angeles, CA | 3 | Credential test |
| Initial Login | 46.232.34.229 | Clouvider | New York, NY | 3 | Credential test |
| **Day 1 Operations** | **147.124.205.9** | **Tier.Net Technologies** | **US** | **74** | **Initial exfiltration test** |
| **Sustained Operations** | **158.51.123.14** | **GLOBALTELEHOST Corp** | **Canada** | **1,532** | **Main attack platform** |

**Total: 5 Attacker IPs**

---

## Discovery Method

Initial analysis only searched for the **login IPs** in email activity - this missed the operational IPs because:
1. Attacker obtained OAuth token on Dec 1, used it from different IPs
2. Operational IPs never appeared in login events
3. Volume-based analysis found Canadian VPS, but missed the Dec 4 Tier.Net IP

**Behavior-based analysis** (searching for Delete events, sends to attacker domains) caught both operational IPs.

---

## Phase 1: Initial Compromise (December 1, 2025)

Three successful logins within 4 minutes:

| Time (UTC) | IP | ASN | Provider |
|------------|-----|-----|----------|
| 19:05:00 | 172.120.137.37 | AS214238 | HOST TELECOM LTD |
| 19:06:18 | 45.87.125.150 | AS62240 | Clouvider |
| 19:08:53 | 46.232.34.229 | AS62240 | Clouvider |

**Purpose:** Credential testing, obtain OAuth token

---

## Phase 2: Day 1 Operations (December 4, 2025)

**IP:** 147.124.205.9
**Provider:** Tier.Net Technologies LLC
**ASN:** AS174
**Total Events:** 74 (all on Dec 4)

### Activity Breakdown

| Event Type | Count |
|------------|-------|
| View | 51 |
| Draft | 11 |
| Open | 3 |
| Attachment preview | 2 |
| Delete | 2 |
| Move to Trash | 2 |
| Send | 2 |

### Critical Finding: ACH Payment Thread

The attacker specifically targeted an email thread containing:
- **ACH payment confirmation for $300,600.82**
- Thread between Lori and Standard Supply (jhalstead-wiggins@ssdhvac.com)

### Attack Sequence (Dec 4, 09:08-09:18 CST)

| Time | Event | Details |
|------|-------|---------|
| 09:08:45 | Draft | To: jhalstead-wiggins@ssdhvac.com (real) |
| 09:10:45 | Draft | To: jhalstead-wiggins@ssdhvca.com **(TYPOSQUAT)** |
| 09:11:18 | Draft | Added subject line |
| 09:11:31 | Move to Trash | Staging |
| **09:11:33** | **SEND** | **To: jhalstead-wiggins@ssdhvca.com** |
| 09:12:40 | **DELETE** | **Destroyed evidence** |
| 09:17:35 | Draft | Second exfiltration attempt |
| **09:17:55** | **SEND** | **To: jhalstead-wiggins@ssdhvca.com** |
| 09:17:57 | Move to Trash | Staging |
| 09:18:14 | **DELETE** | **Destroyed evidence** |

---

## Phase 3: Sustained Operations (December 4-15, 2025)

**IP:** 158.51.123.14
**Provider:** GLOBALTELEHOST Corp
**Location:** Canada
**Fraud Score:** 67/100 (Scamalytics)
**Total Events:** 1,532 (12 days)

### Activity Breakdown

| Event Type | Count |
|------------|-------|
| View | 1,267 |
| Open | 132 |
| Attachment preview | 69 |
| Mark unread | 15 |
| Move to Inbox | 14 |
| Move out of trash | 9 |
| Delete | 7 |
| Draft | 5 |
| Archive | 5 |
| Link click | 4 |
| Send | 2 |
| Move to Trash | 2 |
| Reply | 1 |

### Exfiltration Events

| Date | Recipient | Subject |
|------|-----------|---------|
| Dec 10, 12:05 | jhalstead-wiggins@ssdhvca.com | (blank) |
| Dec 15, 07:40 | lori.maynard@aksmoss.com | Re: Cintas Invoices/Payments |

### Surveillance Activity

Attacker repeatedly viewed:
- "Security Alert: Valid Password" emails (checking if detected)
- Invoice threads with vendors
- Vendor payment schedules
- Bank account information

---

## Confirmed Exfiltration Summary

| Date | IP | Recipient | Subject | Deleted |
|------|-----|-----------|---------|---------|
| Dec 4, 09:11 | 147.124.205.9 | jhalstead-wiggins@ssdhvca.com | RE: 125604 Moss Mechanical... | Yes |
| Dec 4, 09:17 | 147.124.205.9 | jhalstead-wiggins@ssdhvca.com | Re: 125604 Moss Mechanical... | Yes |
| Dec 10, 12:05 | 158.51.123.14 | jhalstead-wiggins@ssdhvca.com | (blank) | Yes |
| Dec 15, 07:40 | 158.51.123.14 | lori.maynard@aksmoss.com | Re: Cintas Invoices/Payments | Yes |

**Total: 4 exfiltration emails confirmed, all deleted within seconds**

---

## Emails Deleted by Attacker

| Date | IP | Subject |
|------|-----|---------|
| Dec 4, 09:12 | 147.124.205.9 | RE: 125604 Moss Mechanical LLC... |
| Dec 4, 09:18 | 147.124.205.9 | Re: 125604 Moss Mechanical LLC... |
| Dec 4, 06:14 | 158.51.123.14 | REF-G1W9-QA52 The Good Contractors List (5 emails) |
| Dec 10, 12:05 | 158.51.123.14 | (blank) |
| Dec 15, 07:40 | 158.51.123.14 | Re: Cintas Invoices/Payments |

**Total: 9 emails permanently deleted**

---

## Legitimate IPs Verified

| IP | Provider | Activity | Status |
|----|----------|----------|--------|
| 199.200.88.186 | Unite Private Networks | Office | ✅ Legitimate |
| 138.199.114.2 | Unite Private Networks | Aug-Oct only | ✅ Legitimate (pre-attack) |
| 2600:387:* (IPv6) | AT&T | Mobile | ✅ Legitimate |
| 44.224.*, 52.4.*, 35.166.*, 50.17.*, 13.59.*, 3.132.* | AWS | Abnormal Security | ✅ Security processing |
| 209.85.220.* | Google | Mail receiving | ✅ Google infrastructure |

---

## Key Finding: No Impersonation

**The attacker did NOT impersonate Lori to commit fraud.**

| Emails Sent From Attacker IPs | Count |
|-------------------------------|-------|
| To attacker-controlled domains | 4 |
| To legitimate third parties | **0** |

All emails sent from the attacker IPs went to their own typosquat domains for data exfiltration. The fraud was committed FROM the attacker's domains (impersonating Janet at Standard Supply), not FROM Lori's account.

### What the Attacker Actually Did (1,606 events)

| Activity | Count | % | Purpose |
|----------|-------|---|---------|
| View | 1,318 | 82.1% | Reading emails |
| Open | 135 | 8.4% | Opening emails |
| Attachment preview | 71 | 4.4% | Looking at attachments |
| Draft | 16 | 1.0% | Composing exfiltration |
| Mark unread | 16 | 1.0% | Hiding that they read emails |
| Move to Inbox | 14 | 0.9% | Recovering emails |
| Delete | 9 | 0.6% | Destroying evidence |
| Move out of trash | 9 | 0.6% | Retrieving trashed emails |
| Archive | 5 | 0.3% | Organizing |
| Send | 4 | 0.2% | Exfiltration only |
| Move to Trash | 4 | 0.2% | Staging for delete |
| Link click | 4 | 0.2% | Clicked links in emails |
| Reply | 1 | 0.1% | Part of exfiltration |

**Summary:** ~95% surveillance (read/view), ~5% housekeeping and exfiltration

---

## Recommendations

1. **Block all 5 attacker IPs** at firewall level
2. **Enable OAuth token IP binding** if supported by Google Workspace
3. **Alert on datacenter IP access** to Gmail
4. **Monitor for Delete events** from non-office IPs
5. **Review all viewed emails** for potential intelligence exposure

---

## Confidence Level

**HIGH confidence in 5 attacker IPs.**

Validation performed:
1. ✅ All IPs with Delete events checked → only attacker IPs
2. ✅ All IPs that sent to attacker domains checked → only attacker IPs
3. ✅ All unknown IPs with December activity investigated → AT&T mobile or AWS/Abnormal Security
4. ✅ Behavior-based analysis (not just volume-based)

---

## Analysis Scripts

| Script | Purpose |
|--------|---------|
| `src/comprehensive_ip_audit.py` | Behavior-based IP analysis |
| `src/validate_findings.py` | Validate attacker IP coverage |
| `src/check_attacker_sends.py` | Check for impersonation vs exfiltration |
| `src/attacker_timeline.py` | Canadian VPS activity timeline |
| `src/investigate_147.py` | Tier.Net IP investigation |
| `src/analyze_lori_all.py` | Full event log analysis |
