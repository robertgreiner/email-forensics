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

### Key Insight: Sophisticated Attackers, Basic Entry Point

**The attack pattern:**
- **Entry:** Basic and unsophisticated - compromised passwords, walked in the front door
- **Post-Access:** Highly sophisticated and intelligent once inside

**Sophisticated Tactics Used (After Access):**
- Waited 3-5 days before taking action (patience, reconnaissance)
- Set up email filters to hide responses from targets
- Registered lookalike domains for BEC emails
- Targeted specific finance employees by name
- Crafted contextually relevant payment requests
- Deleted sent emails to cover tracks

**The Lesson:** We don't need to defend against sophisticated initial attacks. A basic control (MFA) would have stopped both incidents completely. The attackers didn't hack their way in - they simply used stolen passwords against accounts with no second factor.

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
| **Asset Panda** | Active | Hardware/software asset inventory |

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

### 2. Payment Verification Policy Confirmation

**Priority:** 🔴 Critical
**Owner:** Finance (Sean)
**Support:** Robert Greiner
**Timeline:** January 2026

**Objective:** Confirm existing payment verification policy is understood and actively followed

**Current State:** Policy exists and is in place. This policy is what prevented the $300K loss during the December incident when Standard Supply called to verify the payment request.

**Actions:**
- [ ] Confirm policy documentation is current
- [ ] Brief finance team on December incident (real-world example)
- [ ] Verify all team members understand verification procedures
- [ ] Include in security awareness training as reinforcement
- [ ] Test with simulated payment change request (optional)

**Policy Elements (Existing):**
- Phone callback required for any banking changes
- Dual approval for payments over threshold
- No payment changes via email alone
- Vendor contact info verified independently (not from email)

**Success Metrics:**
- 100% finance team acknowledges policy
- December incident used as training example
- Continued zero payments without verification

---

### 3. 1Password Business Deployment

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

### 4. Contraforce Security Monitoring

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

### 5. Abnormal.ai Optimization + Login Monitoring

**Priority:** 🟠 High
**Owner:** Alchemy Security
**Timeline:** January 2026

**Objective:** Maximize BEC detection and establish centralized login monitoring

**Current State:** Deployed November 2025, learning period ongoing

#### BEC Detection
**Actions:**
- Review detection tuning after 60 days of baseline
- Enable account takeover detection
- Configure VIP protection for executives
- Integrate alerting with Contraforce

#### Login Monitoring (Single Pane of Glass)

**Objective:** Centralized view of login anomalies to catch compromises early

**Abnormal Account Takeover Protection** provides:
- Unusual geolocation alerts
- Impossible travel detection (login from TX, then Europe 10 mins later)
- Datacenter/VPS IP detection (attacker infrastructure)
- New device fingerprint alerts

**Actions:**
- [ ] Confirm Account Takeover Protection is enabled
- [ ] Verify alert destinations (email, dashboard, Slack?)
- [ ] Define escalation path when alerts fire
- [ ] Establish daily/weekly dashboard review cadence
- [ ] Integrate with Contraforce monitoring in January

**Questions for Alchemy:**
- Is Account Takeover Protection fully configured?
- Would Abnormal have detected the December attacks?
- What tuning is needed for BEC patterns we saw?
- Where should login alerts route to?

**Success Metrics:**
- BEC detection rate
- Account takeover detection enabled
- False positive rate <5%
- Alert-to-response time <1 hour
- Daily dashboard review established

---

### 6. Security Awareness Training

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

### 7. Google Drive Migration

**Priority:** 🟠 High
**Owner:** Moss IT
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

### 8. Incident Response Planning

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

### 9. CIS Controls Gap Assessment

**Priority:** 🟡 Medium
**Owner:** Alchemy Security
**Timeline:** Q1 2026 (February-March)

**Objective:** Assess current security posture against CIS Controls v8 (IG1) and create remediation roadmap

**What Are CIS Controls?**
Industry-standard prioritized security best practices. Implementation Group 1 (IG1) represents essential cyber hygiene for all organizations.

**Scope:** Assess against IG1 safeguards (56 controls), including:
- Asset inventory (hardware, software)
- Data protection
- Secure configuration
- Account/access management
- Vulnerability management
- Audit log management
- Email protections
- Malware defenses
- Data recovery
- Security awareness

**Deliverables:**
- Current state assessment
- Gap analysis report
- Prioritized remediation roadmap
- Q2-Q4 security improvement plan

**Why Now:**
December incidents revealed gaps. This assessment provides a structured framework to identify what else we may be missing and prioritize future investments.

**Success Metrics:**
- Assessment complete
- Gaps documented with severity ratings
- Remediation roadmap approved
- Q2 priorities identified

---

### 10. Asset Inventory (Asset Panda)

**Priority:** 🟡 Medium
**Owner:** Moss IT
**Tool:** Asset Panda
**Timeline:** Ongoing (Q1 verification)

**Objective:** Maintain comprehensive inventory of hardware and software assets

**Why This Matters for Security:**
You can't protect what you don't know you have. Asset inventory is foundational to security:

- **Incident Response:** When a compromise occurs, you need to know what devices/software the user has access to
- **Vulnerability Management:** Can't patch systems you don't know exist
- **Access Control:** Can't enforce policies on unknown devices
- **Offboarding:** When employees leave, you need to know what to recover
- **License Compliance:** Unauthorized software can introduce risk

**CIS Controls Alignment:**
- Control 1: Inventory and Control of Enterprise Assets (hardware)
- Control 2: Inventory and Control of Software Assets

**Current State:** Asset Panda deployed

**Q1 Actions:**
- [ ] Verify asset inventory is current
- [ ] Confirm all user devices are tracked
- [ ] Review software inventory for unauthorized applications
- [ ] Establish process for new device/software registration
- [ ] Integrate asset data into incident response procedures

**Success Metrics:**
- 100% of company devices inventoried
- Software inventory current
- Process documented for new assets

---

## Q1 2026 Timeline

```
JANUARY 2026
├── Week 1: MFA for Finance + Executives
├── Week 1: Payment Verification Policy Confirmation (Finance Team)
├── Week 1: 1Password Pilot (IT, Finance)
├── Week 2: Contraforce Go-Live
├── Week 2: Phishing Simulation Baseline
├── Week 2: Abnormal Login Monitoring Review with Alchemy
├── Week 3: MFA Enforcement (grace period)
├── Week 3: 1Password Full Rollout
├── Week 4: MFA Full Enforcement
└── Week 4: Google Drive Migration Assessment

FEBRUARY 2026
├── Week 1: Security Awareness Training
├── Week 2: Google Drive Migration (Full)
├── Week 3: Incident Response Playbook
└── Week 4: Q1 Checkpoint Review

MARCH 2026
├── Week 1: Phishing Simulation Follow-up
├── Week 2: Dropbox/SharePoint Decommission
├── Week 2: CIS Controls Gap Assessment (Alchemy)
├── Week 3: Q1 Security Review
└── Week 4: Q2 Planning (informed by CIS assessment)
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
| Payment Policy | Team trained and vigilant |
| CIS IG1 Assessment | Complete with roadmap |
| Asset Inventory | Verified current |

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
