# Q1 2026 Security & IT Strategy
## Moss Portfolio Companies

**Date:** December 25, 2025
**Prepared by:** Robert Greiner, CTO
**Scope:** Moss Utilities (mossutilities.com) and Moss HVAC (askmoss.com)
**Classification:** Internal - Strategic Planning

---

## Executive Summary

Q1 2026 represents a critical transformation period for Moss portfolio security and IT infrastructure. Following the December 2025 BEC incidents that targeted both companies, we are accelerating security improvements while executing a planned Google Drive migration.

**Q1 2026 Themes:**
1. **Secure the Foundation** - MFA enforcement, password management
2. **Improve Detection** - Contraforce monitoring, Abnormal.ai maturation
3. **Build Resilience** - Training, incident response planning
4. **Consolidate Infrastructure** - Google Drive migration

---

## Background: December 2025 Incidents

Two coordinated BEC attacks targeted Moss portfolio companies on consecutive days:

| Company | Account Compromised | Date | Duration | Financial Loss |
|---------|---------------------|------|----------|----------------|
| Moss HVAC | Lori Maynard | Dec 1, 2025 | 12 days | $0 (prevented) |
| Moss Utilities | Vaughn Muller | Dec 2, 2025 | 14 days | $0 (prevented) |

**Root Cause:** Both accounts lacked two-factor authentication. Password-only authentication allowed attackers to gain access using compromised credentials.

**What Saved Us:**
- Employee vigilance (Christina flagged suspicious email)
- Vendor verification (Standard Supply called to verify $300K payment request)

**Current State:**
- Both incidents fully remediated
- No active compromises
- Attackers locked out
- **83-97% of users still lack MFA** - systemic risk remains

---

## Security Stack

| Tool | Status | Function |
|------|--------|----------|
| **Google Workspace** | Active | Identity, email, collaboration |
| **Abnormal.ai** | Active (Nov 2025) | Email security, BEC detection |
| **Contraforce** | Starting Jan 2026 | Security monitoring, SOC |
| **1Password Business** | Q1 2026 | Password management |

### Partners

| Partner | Role |
|---------|------|
| **Alchemy Security** | Security strategy, assessments, policy |
| **Kinetic Technology Group** | MSP, execution, operations |

---

## Q1 2026 Initiatives

### 1. Mandatory MFA Enforcement

**Priority:** 🔴 Critical
**Owner:** Kinetic Technology Group
**Support:** Alchemy Security (policy)
**Timeline:** January 2026

**Objective:** 100% MFA adoption across both tenants

**Current State:**
| Tenant | Users | MFA Enabled | Target |
|--------|-------|-------------|--------|
| Moss HVAC | 89 | 15 (17%) | 89 (100%) |
| Moss Utilities | 217 | 6 (3%) | 217 (100%) |

**Approach:**
| Week | Action |
|------|--------|
| Week 1 | Finance/Accounting users enrolled (highest risk) |
| Week 1 | Executives enrolled (Garrett, Kelly, Sean) |
| Week 2 | All-hands communication, enrollment period opens |
| Week 3 | Enforcement enabled with 7-day grace period |
| Week 4 | Full enforcement, exceptions reviewed |

**MFA Methods Allowed:**
- Google Authenticator / Authenticator apps (recommended)
- Google Prompts (phone-based)
- Hardware security keys (executives, IT)
- Backup codes (emergency only)

**Exceptions Process:**
- No smartphone → Hardware security key or backup codes
- All exceptions documented and time-limited
- Quarterly review of exceptions

**Success Metrics:**
- 100% MFA enrollment
- Zero password-only logins
- <5 exception requests

---

### 2. 1Password Business Deployment

**Priority:** 🔴 Critical
**Owner:** Kinetic Technology Group
**Support:** Alchemy Security (policy)
**Timeline:** January-February 2026

**Objective:** Organization-wide password manager adoption

**Why:**
- Prevents password reuse (likely attack vector in Dec incidents)
- Enables strong unique passwords
- Watchtower alerts on breached credentials
- Phishing protection (won't autofill on fake sites)

**Approach:**
| Phase | Timeline | Scope |
|-------|----------|-------|
| Pilot | Week 1-2 | IT, Finance (20 users) |
| Rollout | Week 3-4 | All users |
| Training | Ongoing | Bundled with MFA training |

**Configuration:**
- SSO integration with Google Workspace
- Require 1Password for all work accounts
- Shared vaults for team credentials (IT, Finance)
- Watchtower monitoring enabled

**Cost:** ~$2,400/month for 300 users

**Success Metrics:**
- 90% adoption within 60 days
- Zero shared passwords outside 1Password
- Watchtower score improvement

---

### 3. Contraforce Security Monitoring

**Priority:** 🟠 High
**Owner:** Contraforce
**Timeline:** January 2026 (go-live)

**Objective:** 24/7 security monitoring and alerting

**Scope:**
- Google Workspace log monitoring
- Login anomaly detection
- Threat detection and alerting
- Incident escalation

**Integration Points:**
- Google Workspace audit logs
- Abnormal.ai alerts
- Endpoint telemetry (if applicable)

**Handoff:**
- Contraforce handles detection and triage
- Escalation to KineticTG / Robert for response
- Alchemy Security for strategic incidents

**Success Metrics:**
- <15 minute alert-to-acknowledgment
- Zero missed critical alerts
- Monthly threat reports

---

### 4. Abnormal.ai Optimization

**Priority:** 🟠 High
**Owner:** Alchemy Security
**Timeline:** January 2026

**Objective:** Maximize BEC detection effectiveness

**Current State:** Deployed November 2025, learning period ongoing

**Actions:**
- Review detection tuning after 60 days of baseline
- Enable account takeover detection
- Configure VIP protection for executives
- Integrate alerting with Contraforce

**Question for Alchemy:**
- Would Abnormal have detected the December attacks?
- What tuning is needed for BEC patterns we saw?

**Success Metrics:**
- BEC detection rate
- False positive rate <5%
- Alert-to-response time

---

### 5. Security Awareness Training

**Priority:** 🟠 High
**Owner:** Kinetic Technology Group
**Support:** Alchemy Security
**Timeline:** January-February 2026

**Objective:** Equip employees to recognize and report threats

**Components:**

| Component | Owner | Timeline |
|-----------|-------|----------|
| Phishing Simulation (Baseline) | KineticTG | January |
| BEC Training Module | KineticTG/Alchemy | January |
| MFA + 1Password Training | KineticTG | January |
| Phishing Simulation (Follow-up) | KineticTG | March |

**Training Topics:**
- BEC recognition (urgent requests, payment changes)
- Verification procedures (always call for payment changes)
- Reporting suspicious emails
- Password hygiene
- MFA importance

**Delivery:**
- Online modules (self-paced)
- Live session for finance team
- Quick reference guides

**Success Metrics:**
- 95% training completion
- 50% improvement in phishing simulation results
- Increase in reported suspicious emails

---

### 6. Google Drive Migration

**Priority:** 🟠 High
**Owner:** Kinetic Technology Group
**Timeline:** Q1 2026

**Objective:** Consolidate file storage on Google Drive, retire Dropbox and SharePoint

**Current State:**
| Platform | Status |
|----------|--------|
| Dropbox | Active, to be retired |
| SharePoint | Active, to be retired |
| Google Drive | Partial adoption |

**Approach:**
| Phase | Timeline | Scope |
|-------|----------|-------|
| Assessment | January | Inventory, permissions mapping |
| Pilot Migration | January | IT, one department |
| Full Migration | February | All departments |
| Decommission | March | Retire Dropbox/SharePoint |

**Security Considerations:**
- Consistent permissions model
- External sharing policies
- DLP (Data Loss Prevention) rules
- Backup/recovery procedures

**Dependencies:**
- MFA enforcement (must complete first)
- User training on Google Drive

**Success Metrics:**
- 100% data migrated
- Zero data loss
- Dropbox/SharePoint decommissioned
- External sharing policy enforced

---

### 7. Incident Response Planning

**Priority:** 🟡 Medium
**Owner:** Alchemy Security
**Support:** Robert Greiner
**Timeline:** February 2026

**Objective:** Document incident response procedures based on December 2025 lessons

**Deliverables:**
| Document | Purpose |
|----------|---------|
| Incident Response Playbook | Step-by-step procedures |
| BEC Response Checklist | Specific to email compromise |
| Contact/Escalation Matrix | Who to call, when |
| Communication Templates | Internal/external messaging |

**Based on December 2025 Learnings:**
- Account lockdown procedures
- Audit log analysis steps
- Persistence mechanism checks
- Partner notification process
- Documentation requirements

**Success Metrics:**
- Playbook documented and tested
- All stakeholders trained
- Tabletop exercise completed

---

### 8. Payment Verification Policy

**Priority:** 🟡 Medium
**Owner:** Finance (Sean)
**Support:** Alchemy Security
**Timeline:** January 2026

**Objective:** Formalize payment verification procedures that saved us from $300K loss

**Policy Elements:**
- Phone callback required for any banking changes
- Dual approval for payments over $X threshold
- No payment changes via email alone
- Vendor contact info verified independently (not from email)

**Training:**
- Finance team briefing
- Include in security awareness training

**Success Metrics:**
- Policy documented and signed
- 100% finance team trained
- Zero payments without verification

---

## Q1 2026 Timeline

```
JANUARY 2026
├── Week 1: MFA for Finance + Executives
├── Week 1: 1Password Pilot (IT, Finance)
├── Week 2: Contraforce Go-Live
├── Week 2: Phishing Simulation Baseline
├── Week 3: MFA Enforcement (grace period)
├── Week 3: 1Password Full Rollout
├── Week 4: MFA Full Enforcement
└── Week 4: Abnormal Review with Alchemy

FEBRUARY 2026
├── Week 1: Security Awareness Training
├── Week 2: Google Drive Migration (Full)
├── Week 3: Incident Response Playbook
└── Week 4: Payment Verification Policy

MARCH 2026
├── Week 1: Phishing Simulation Follow-up
├── Week 2: Dropbox/SharePoint Decommission
├── Week 3: Q1 Security Review
└── Week 4: Q2 Planning
```

---

## Resource Requirements

### Budget

| Item | Cost | Frequency |
|------|------|-----------|
| 1Password Business | ~$2,400 | Monthly |
| Contraforce | TBD | Monthly |
| Abnormal.ai | Existing | Monthly |
| Alchemy Security | Existing | Retainer |
| KineticTG | Existing | MSP contract |
| Security Training Platform | TBD | Annual |

### People

| Role | Responsibility |
|------|----------------|
| Robert Greiner (CTO) | Strategy, oversight, incident response |
| KineticTG | Execution, operations, user support |
| Alchemy Security | Policy, assessments, strategic guidance |
| Finance Team | Payment policy compliance |
| All Employees | Training completion, policy adherence |

---

## Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| MFA adoption resistance | Users locked out, productivity loss | Clear communication, support resources, grace period |
| Password manager adoption | Shadow IT, continued password reuse | Training, enforcement, easy UX |
| Migration data loss | Business disruption | Backup verification, phased approach |
| Alert fatigue | Missed real threats | Contraforce tuning, clear escalation |
| Change fatigue | User frustration | Bundle changes, clear messaging |

---

## Success Criteria

**By End of Q1 2026:**

| Metric | Target |
|--------|--------|
| MFA Adoption | 100% |
| 1Password Adoption | 90% |
| Phishing Simulation Improvement | 50% |
| Training Completion | 95% |
| Google Drive Migration | 100% |
| Incident Response Playbook | Complete |
| Payment Policy | Documented and trained |

---

## Communication Plan

| Audience | Message | Channel | When |
|----------|---------|---------|------|
| Executives | Q1 strategy overview, incident summary | Meeting | Week 1 Jan |
| All Employees | Security improvements announcement | Email + Meeting | Week 2 Jan |
| Finance Team | Payment policy, targeted training | Meeting | Week 2 Jan |
| IT/Tech Team | Technical details, incident readout | Meeting | Week 1 Jan |
| Partners | Coordination, expectations | Calls | Ongoing |

---

## Appendix: December 2025 Incident Summary

For partner briefings, see:
- `executive_summary_moss_portfolio_20251225.md`
- `security_assurance_report_20251225.md`
- `mossutilities_incident_report_20251225.md`
- `incident_report_20251223_final.md` (Moss HVAC)

---

## Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | Dec 25, 2025 | Robert Greiner | Initial draft |

**Distribution:** Garrett Moss, Kelly Roberts, Sean (CFO), Alchemy Security, Kinetic Technology Group
**Review Cycle:** Monthly during Q1 2026
