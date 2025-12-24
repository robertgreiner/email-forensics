# ADDENDUM: Active Attacker Operations Discovered

**Date:** December 23, 2025
**Status:** CRITICAL UPDATE - Revises Previous Findings
**Source:** Admin Email Log Search - All Events Export (lori-all.csv)

---

## Executive Summary

Analysis of comprehensive Gmail event logs reveals the attacker conducted **active operations** from Lori Maynard's account over a 12-day period (December 4-15, 2025) using a **different IP address** than the initial compromise.

**This revises our earlier conclusion that the attacker only had "read-only" access.**

---

## Key Finding: Fourth Attacker IP Identified

| IP Address | Provider | Location | Purpose |
|------------|----------|----------|---------|
| 172.120.137.37 | HOST TELECOM LTD | Secaucus, NJ | Initial login (Dec 1) |
| 45.87.125.150 | Clouvider | Los Angeles, CA | Initial login (Dec 1) |
| 46.232.34.229 | Clouvider | New York, NY | Initial login (Dec 1) |
| **158.51.123.14** | **GLOBALTELEHOST Corp** | **Canada** | **Active operations (Dec 4-15)** |

The Canadian VPS IP was used for the sustained attack campaign, while the initial 3 IPs were only used for the December 1st compromise.

---

## Attacker Activity Summary

| Metric | Count |
|--------|-------|
| **Total events** | 1,532 |
| **Active period** | December 4-15, 2025 (12 days) |
| **Emails viewed** | 1,267 |
| **Attachments previewed** | 69 |
| **Emails sent (to attacker domains)** | 2 |
| **Emails permanently deleted** | 7 |

---

## CRITICAL: Data Exfiltration Confirmed

The attacker sent **2 emails from Lori's account to attacker-controlled domains**:

### Email 1: Exfiltration to aksmoss.com
| Field | Value |
|-------|-------|
| **Date** | December 15, 2025 07:40:28 CST |
| **To** | lori.maynard@aksmoss.com |
| **Subject** | Re: Cintas Invoices/Payments |
| **Action** | Attacker forwarded Cintas invoice thread to their typosquat domain |

### Email 2: Exfiltration to ssdhvca.com
| Field | Value |
|-------|-------|
| **Date** | December 10, 2025 12:05:41 CST |
| **To** | jhalstead-wiggins@ssdhvca.com |
| **Subject** | (blank) |
| **Action** | Data sent to attacker's Standard Supply impersonation domain |

---

## Evidence Destruction: Deleted Emails

The attacker permanently deleted **7 emails** to cover their tracks:

| Date | Subject | Purpose |
|------|---------|---------|
| Dec 15, 07:40:43 | Re: Cintas Invoices/Payments | Delete sent exfiltration email |
| Dec 10, 12:05:50 | (blank) | Delete sent exfiltration email |
| Dec 4, 06:14:25 | REF-G1W9-QA52 The Good Contractors List | Unknown - possibly reconnaissance cleanup |
| Dec 4, 06:14:25 | Re: REF-G1W9-QA52 The Good Contractors List | (4 additional deletions same thread) |

---

## Attack Sequence Reconstruction

### December 15, 2025 - Cintas Invoice Exfiltration

Complete attack sequence captured in logs:

| Time (CST) | Event | Details |
|------------|-------|---------|
| 07:39:33 | View | Cintas Invoices/Payments |
| 07:40:04 | Draft | Re: Cintas Invoices/Payments |
| 07:40:22 | View | Re: Cintas Invoices/Payments |
| 07:40:26 | Move to Trash | (staging for deletion) |
| **07:40:28** | **Send** | **To: lori.maynard@aksmoss.com** |
| **07:40:43** | **Delete** | **Permanently destroyed** |

**Time from send to deletion: 15 seconds**

The attacker:
1. Read an invoice email thread
2. Created a draft forwarding it
3. Moved to trash (possibly auto-save behavior)
4. Sent the email to their typosquat domain
5. Immediately deleted to hide evidence

---

## Surveillance Activity

### Security Alerts Monitored

The attacker repeatedly viewed **"Security Alert: Valid Password"** emails to check if they had been detected:

- December 8, 10:31:24 - First check
- December 8, 16:25:59 - Multiple views
- December 8, 16:26:17 - Multiple views
- December 15, 07:50:43 - Check after exfiltration
- December 15, 09:31:31 - Multiple views (final check)

### Financial Intelligence Gathered

The attacker extensively viewed emails containing:
- **Invoice threads**: "Moss Mechnical - Invoices" (hundreds of views)
- **Payment information**: "Vendor Payments 12/11/25-12/12/25"
- **Bank details**: "New Bank Accounts", "Moss Mechanical New Operating Account"
- **ACH/Wire data**: "Duplicate ACH", "Payroll Nacha for approval"
- **Account changes**: "Account Update - IMPORTANT INFORMATION"

---

## Daily Activity Pattern

| Date | Events | Notable Activity |
|------|--------|------------------|
| Dec 4 | 146 | Initial reconnaissance, 5 deletions |
| Dec 5 | 308 | Heavy email viewing |
| Dec 6-7 | 16 | Minimal (weekend) |
| Dec 8 | 349 | Intensive surveillance |
| Dec 9 | 211 | Financial email focus |
| Dec 10 | 91 | **First exfiltration (ssdhvca.com)** |
| Dec 11 | 1 | Minimal |
| Dec 12 | 215 | Vendor payment review |
| Dec 13 | 28 | Light activity |
| Dec 14 | 26 | Light activity |
| Dec 15 | 141 | **Second exfiltration (aksmoss.com)** |

---

## Why This IP Wasn't Detected Earlier

1. **Different IP from initial compromise** - We searched for the login IPs (172.x, 45.x, 46.x) in email activity, but attacker used 158.51.123.14 for operations
2. **OAuth token portability** - Attacker obtained OAuth token on Dec 1, then used it from different IP
3. **No login events from Canadian IP** - Attacker used persistent session/token, avoiding new login alerts
4. **VPS provider** - GLOBALTELEHOST Corp is known for fraudulent activity (67/100 fraud score on Scamalytics)

---

## Implications

### What Was Exfiltrated

Based on the two confirmed exfiltration emails and extensive viewing activity:

1. **Cintas invoice details** - Sent to aksmoss.com
2. **Unknown content** - Sent to ssdhvca.com (blank subject)
3. **Financial intelligence** - Viewed but may have been memorized/screenshot:
   - Bank account numbers
   - Vendor payment schedules
   - ACH/wire transfer details
   - Invoice amounts and due dates

### Revised Attack Timeline

| Date | Phase | Activity |
|------|-------|----------|
| Dec 1 | Compromise | Login from 3 datacenter IPs, obtain OAuth token |
| Dec 1-3 | Setup | (unknown - possibly testing access) |
| **Dec 4** | **Operations begin** | Start using Canadian VPS, initial recon |
| Dec 4-9 | Intelligence | Read invoice threads, learn business context |
| **Dec 10** | **Exfiltration #1** | Send data to ssdhvca.com, delete |
| Dec 10-14 | Continued surveillance | Monitor for detection, gather more intel |
| **Dec 15** | **Exfiltration #2** | Send Cintas data to aksmoss.com, delete |
| Dec 15 | Detection check | View security alerts |
| Dec 17 | Remediation | Password reset, 2FA enabled |

---

## Recommendations

### Immediate

1. **Review Cintas relationship** - Determine if any payment instructions were altered
2. **Alert Cintas** - Inform them of potential BEC targeting
3. **Block Canadian VPS IP** - Add 158.51.123.14 to blocklist
4. **Review aksmoss.com inbox** - Domain may contain exfiltrated data (if accessible)

### Investigation

1. **Obtain full email content** - Request content of deleted emails from Google if possible
2. **Search for blank-subject emails** - The Dec 10 exfiltration had no subject - investigate what was sent
3. **Review all viewed emails** - 1,267 emails were viewed; determine sensitivity of each

### Technical Controls

1. **OAuth token monitoring** - Alert on token usage from new IPs
2. **Session binding** - Consider requiring re-authentication for IP changes
3. **VPS/datacenter IP blocking** - Block known VPS providers from login

---

## Conclusion

The attacker maintained **active operational access** to Lori Maynard's Gmail account for **12 days** (December 4-15), during which they:

1. **Read 1,267 emails** focusing on financial matters
2. **Exfiltrated data** via 2 emails to attacker-controlled domains
3. **Deleted 7 emails** to destroy evidence
4. **Monitored security alerts** to check for detection

This was a sophisticated, sustained attack - not a one-time compromise.

---

**Report Status:** Critical Update
**Distribution:** Executive team, IT, Legal, Insurance
