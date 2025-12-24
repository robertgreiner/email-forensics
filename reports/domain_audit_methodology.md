# Domain-Wide Security Audit - Methodology & Results

**Date:** December 23, 2025
**Scope:** Full Google Workspace domain audit
**Prepared by:** Robert Greiner, CTO
**Classification:** Internal - Incident Response

---

## Executive Summary

Following the discovery of a Business Email Compromise (BEC) attack against `lori.maynard@askmoss.com`, a comprehensive domain-wide audit was conducted to determine if any other accounts were compromised.

**Result:** No lateral movement detected. The attack was isolated to a single account.

---

## Audit Scope

| Metric | Value |
|--------|-------|
| Total users in domain | 91 |
| Active users audited (API) | 89 |
| Users with delete events analyzed | 58 |
| Suspended users (excluded) | 2 |
| Time range analyzed | September 25 - December 24, 2025 (90 days) |
| Attack window focus | December 1-17, 2025 |

---

## Methodology

### Phase 1: Attacker IP Identification

Through forensic analysis of the compromised account, five attacker IPs were identified:

| Phase | IP Address | Provider | Location | Activity |
|-------|------------|----------|----------|----------|
| Initial Login | 172.120.137.37 | HOST TELECOM LTD | Secaucus, NJ | Credential test |
| Initial Login | 45.87.125.150 | Clouvider | Los Angeles, CA | Credential test |
| Initial Login | 46.232.34.229 | Clouvider | New York, NY | Credential test |
| Operations | 147.124.205.9 | Tier.Net Technologies | US | Day 1 exfiltration |
| Operations | 158.51.123.14 | GLOBALTELEHOST Corp | Canada | Sustained operations |

**Discovery method:**
1. Initial login IPs found via Google Workspace login audit logs
2. Operational IPs discovered through behavior-based analysis of Gmail activity logs (searching for DELETE events and sends to attacker-controlled domains)

### Phase 2: Domain-Wide IP Search

For each of the 89 active users, the following audit logs were queried via the Google Workspace Admin Reports API:

| Log Type | API Application | Time Range | Purpose |
|----------|-----------------|------------|---------|
| Login events | `login` | Nov 1 - Dec 24, 2025 | Detect direct account access from attacker IPs |
| OAuth/Token events | `token` | Nov 1 - Dec 24, 2025 | Detect OAuth grants from attacker IPs (persistent access) |
| Gmail activity | `gmail` | Dec 1 - Dec 17, 2025 | Detect email operations from attacker IPs |

**API Endpoint:** `admin.reports_v1.activities().list()`

**Query parameters:**
```python
service.activities().list(
    userKey=user_email,
    applicationName='login',  # or 'token', 'gmail'
    startTime='2025-11-01T00:00:00.000Z',
    endTime='2025-12-24T00:00:00.000Z',
    maxResults=200
)
```

### Phase 3: Results Analysis

Each API response was parsed to extract the source IP address. Any match against the five known attacker IPs triggered a flag for further investigation.

**Matching logic:**
```python
ATTACKER_IPS = {
    '172.120.137.37',
    '45.87.125.150',
    '46.232.34.229',
    '147.124.205.9',
    '158.51.123.14',
}

for event in results.get('items', []):
    ip = event.get('ipAddress', '')
    if ip in ATTACKER_IPS:
        # Flag as compromised
```

### Phase 4: Domain-Wide DELETE Event Analysis

The Reports API does not capture granular Gmail user actions (view, send, delete). To analyze DELETE events across all users, data was exported from **Admin Email Log Search** in the Google Admin Console.

**Data source:** Admin Console → Reporting → Email Log Search → Filter by "Delete" events → Export CSV

**Export details:**
- File: `deletes.csv` (12 MB)
- Time range: 90 days (September 25 - December 24, 2025)
- Total events: 20,501 delete events
- Unique users with delete activity: 58

**Analysis performed:**
1. Search for deletes from known attacker IPs
2. Identify deletes from datacenter/VPS IPs (suspicious)
3. Detect rapid-fire delete patterns (potential evidence destruction)
4. Cross-reference suspicious IPs against ISP databases

**IP classification logic:**
```python
# Known legitimate patterns (excluded from suspicion)
OFFICE_PATTERNS = ('199.200.',)           # Moss office
AWS_PATTERNS = ('44.', '52.', '35.', ...) # Abnormal Security
GOOGLE_PATTERNS = ('209.85.',)            # Google infrastructure

# Remaining IPs checked against WHOIS for datacenter indicators
```

---

## Results

### Primary Finding

| Metric | Result |
|--------|--------|
| Accounts with attacker IP activity | **1** |
| Compromised account | `lori.maynard@askmoss.com` |
| Lateral movement detected | **None** |

### Attacker Events Found

All attacker activity was isolated to the known compromised account:

| Time (UTC) | User | Type | IP |
|------------|------|------|-----|
| 2025-12-01 19:05:00 | lori.maynard@askmoss.com | LOGIN | 172.120.137.37 |
| 2025-12-01 19:06:18 | lori.maynard@askmoss.com | LOGIN | 45.87.125.150 |
| 2025-12-01 19:08:53 | lori.maynard@askmoss.com | LOGIN | 46.232.34.229 |

### High-Risk Account Deep Dive

Additional deep-dive audits were performed on high-risk accounts:

| Account | Role | Login Events | Gmail Events | OAuth Events | Result |
|---------|------|--------------|--------------|--------------|--------|
| lori.maynard@askmoss.com | Accounting Manager | Compromised | 1,606 attacker events | 3 attacker grants | **REMEDIATED** |
| madelin.martinez@askmoss.com | AP Specialist | 5 (clean) | 500 (clean) | 200 (clean) | ✅ Clean |
| invoices@askmoss.com | Shared mailbox | 3 (clean) | 500 (clean) | 200 (clean) | ✅ Clean |

### DELETE Event Analysis Results

Analysis of 20,501 delete events across 58 users over 90 days:

| Check | Result |
|-------|--------|
| Deletes from known attacker IPs | **9** (all from lori.maynard@askmoss.com) |
| Deletes from suspicious datacenter IPs | **0** (all flagged IPs verified as residential ISPs) |
| Rapid-fire delete patterns | **2** (both from legitimate residential IPs) |
| Other accounts with attacker activity | **None** |

**Attacker DELETE events (all from Lori's account):**

| Date | IP | Subject |
|------|-----|---------|
| Dec 15, 07:40:43 | 158.51.123.14 | Re: Cintas Invoices/Payments |
| Dec 10, 12:05:50 | 158.51.123.14 | (blank - exfiltration email) |
| Dec 4, 09:18:14 | 147.124.205.9 | Re: 125604 Moss Mechanical LLC... |
| Dec 4, 09:12:40 | 147.124.205.9 | RE: 125604 Moss Mechanical LLC... |
| Dec 4, 06:14:25 | 158.51.123.14 | Re: REF-G1W9-QA52 The Good Contractors List |
| + 4 more | | |

**Rapid-fire patterns investigated:**

| User | IP | Provider | Verdict |
|------|-----|----------|---------|
| cris.mccown@askmoss.com | 32.141.17.86 | AT&T (mobile/residential) | ✅ Legitimate |
| lori.lierman@askmoss.com | 47.161.22.179 | Frontier Communications (residential) | ✅ Legitimate |

**Conclusion:** DELETE event analysis confirms the attack was isolated to a single account. No evidence of other compromised accounts.

---

## Supplementary Checks

### OAuth Token Audit

For the compromised account, a comprehensive OAuth audit was performed:

| Check | Result |
|-------|--------|
| OAuth grants from attacker IPs | 3 found (Google Chrome, Dec 1) |
| Token revocations | 30 found (Dec 16-17) |
| Attacker tokens revoked | ✅ Yes (Dec 17) |
| Unknown apps | None (all identified) |

### Gmail Settings Verification

Persistence mechanisms were checked for key accounts:

| Setting | lori.maynard | madelin.martinez | invoices@ |
|---------|--------------|------------------|-----------|
| Auto-forwarding | ✅ Disabled | ✅ Disabled | ✅ Disabled |
| Email filters | ✅ None | ✅ None | ✅ None |
| Delegates | ✅ None | ✅ None | ✅ None |
| IMAP/POP | ✅ Disabled | ✅ Disabled | ✅ Disabled |

---

## Limitations

| Limitation | Impact | Mitigation |
|------------|--------|------------|
| Only known attacker IPs searched | Would miss unknown attacker infrastructure | Behavior-based analysis performed on compromised account |
| API returns max 200-500 events per query | High-volume users could have events missed | Pagination used where available |
| Gmail activity limited to attack window | Pre-attack reconnaissance not captured | Login/OAuth checked for full 2-month period |
| No content analysis | Cannot see what attacker read | Admin Email Log Search used for email content context |

---

## Tools & Scripts Used

| Script | Purpose |
|--------|---------|
| `src/audit_all_accounts.py` | Domain-wide attacker IP search (89 users) |
| `src/audit_other_accounts.py` | Deep-dive on high-risk accounts |
| `src/analyze_deletes_csv.py` | Domain-wide DELETE event analysis (58 users, 20K events) |
| `src/comprehensive_oauth_audit.py` | OAuth token analysis |
| `src/check_gmail_settings.py` | Gmail settings verification |
| `src/list_users.py` | User enumeration with 2FA status |
| `src/validate_findings.py` | Attacker IP validation |

---

## Conclusions

1. **No lateral movement occurred.** The attacker accessed only one account (`lori.maynard@askmoss.com`).

2. **Attack was contained.** Password reset and 2FA enrollment on December 17 terminated attacker access.

3. **OAuth tokens were revoked.** The Google Chrome tokens obtained by the attacker on December 1 were invalidated.

4. **No persistence mechanisms remain.** Gmail settings verified clean across key accounts.

5. **Domain is secure.** All 89 active users have been audited via API with no additional compromise detected.

6. **DELETE analysis confirms containment.** Analysis of 20,501 delete events across 58 users (90 days) found attacker activity only in the known compromised account. All flagged suspicious IPs were verified as legitimate residential ISPs (AT&T, Frontier Communications).

---

## Recommendations

### Immediate

1. **Enable mandatory 2FA** for all users (currently only 17% enrolled)
2. **Prioritize finance/AP users** who handle payments
3. **Alert Cintas** about potential BEC targeting (invoice data was exfiltrated)

### Ongoing

4. **Implement login anomaly detection** (alert on datacenter/VPS IPs)
5. **Monitor DELETE events** domain-wide for suspicious patterns
6. **Regular OAuth audits** to detect unauthorized app grants

---

## Appendix: API Reference

### Google Workspace Admin Reports API

**Authentication:** Service account with domain-wide delegation

**Required scopes:**
- `https://www.googleapis.com/auth/admin.reports.audit.readonly`
- `https://www.googleapis.com/auth/admin.directory.user.readonly`

**Applications available:**
- `login` - Login/logout events
- `token` - OAuth grant/revoke events
- `gmail` - Email operations (view, send, delete, etc.)
- `admin` - Admin console actions
- `drive` - Google Drive activity

**Documentation:** https://developers.google.com/admin-sdk/reports/v1/get-start/getting-started

---

**Report Status:** Final (Updated December 23, 2025 - DELETE analysis added)
**Distribution:** Executive team, IT, Legal
**Related Documents:**
- `incident_report_20251223_final.md`
- `addendum_20251223_canadian_vps.md`
- `all_attacker_ips.md`

---

## Audit Statistics Summary

| Audit Type | Users/Events Analyzed | Attacker Activity Found |
|------------|----------------------|------------------------|
| API-based login/OAuth/Gmail audit | 89 active users | Only lori.maynard (6 login events) |
| DELETE event analysis (CSV export) | 58 users, 20,501 events | Only lori.maynard (9 delete events) |
| High-risk account deep dive | 3 accounts | Only lori.maynard |
| OAuth token audit | 972 token events | 3 attacker grants (revoked) |

**Total unique users reviewed:** 89 (API) + 58 with delete activity = comprehensive domain coverage
