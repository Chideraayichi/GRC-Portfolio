# AWS Security Baseline: Hardened Account with Control Mapping

## Summary

I built and hardened an AWS account from scratch, then assessed it the way an auditor would. The baseline covers identity, logging, continuous monitoring, threat detection and secure-by-default guardrails. Each setting is mapped to **NIST SP 800-53 Rev. 5**, the **CIS AWS Foundations Benchmark** and the **SOC 2 Trust Services Criteria**, and every control has screenshot evidence.

**Results**

- 16 controls implemented and mapped across three frameworks
- 8 AWS Config rules deployed, 100% compliant at final review
- 3 findings identified during the build, each triaged and resolved with documented reasoning
- Zero-cost operation, monitored by a zero-spend budget and cost anomaly detection

## Architecture

![Architecture diagram](Evidence/architecture.png)

- **Identity:** IAM Identity Center (single-Region instance, US East – Ohio) with two permission sets: `AdminAccess` and `AuditorReadOnly`
- **Logging:** multi-Region CloudTrail trail `org-audit-trail`, delivered to an encrypted, non-public S3 bucket with log file validation and a retention lifecycle
- **Monitoring:** AWS Config (continuous recording + 8 managed rules), Amazon GuardDuty, IAM Access Analyzer (external access)
- **Guardrails:** account-level S3 Block Public Access, EBS encryption by default, budgets and cost anomaly detection, tagging standard

## Scope and assumptions

- Single AWS account, home Region US East (Ohio); CloudTrail covers all Regions
- Lab environment with no production workloads or customer data
- One person playing two roles (administrator and auditor) to demonstrate separation of duties
- Account identifiers, email addresses and ARNs are redacted in all evidence

## Implementation

### Phase 1: Root user protection

- Confirmed MFA (virtual authenticator) is assigned to the root user
- Confirmed no root access keys exist
- Registered alternate contacts for Billing, Operations and Security
- Activated IAM access to billing so day-to-day users never need root
- Root is now reserved for break-glass tasks only

### Phase 2: Identity and least privilege

- Enabled IAM Identity Center and created two users, `chidera-admin` and `chidera-auditor`
- Created two permission sets:
  - `AdminAccess`: AWS managed `AdministratorAccess`, 1-hour session
  - `AuditorReadOnly`: AWS managed `SecurityAudit` + `ReadOnlyAccess`
- Required MFA at every sign-in and forced device registration at first sign-in
- **Tested least privilege:** signed in as `chidera-auditor` and attempted to create an S3 bucket. The request was denied, confirming the auditor can view but not change resources.

### Phase 3: Audit logging

- Created CloudTrail trail `org-audit-trail`: multi-Region, management events (read + write)
- Log bucket encrypted with SSE-S3, Block Public Access on
- Log file validation enabled, so tampering or deletion is detectable
- Retention lifecycle: transition to Glacier Flexible Retrieval at 90 days, expire at 365 days
- Verified logging: Event history shows `CreateTrail`, `StartLogging` and `PutBucketEncryption` attributed to `chidera-admin`, not root

### Phase 4: Detection and continuous monitoring

**AWS Config:** continuous recording with these managed rules:

| Rule | Purpose |
| --- | --- |
| `root-account-mfa-enabled` | Root user protected by MFA |
| `cloudtrail-enabled` | Audit logging active |
| `multi-region-cloudtrail-enabled` | Logging covers all Regions |
| `cloud-trail-log-file-validation-enabled` | Log integrity protected |
| `s3-bucket-public-read-prohibited` | No publicly readable buckets |
| `s3-bucket-public-write-prohibited` | No publicly writable buckets |
| `s3-bucket-server-side-encryption-enabled` | Buckets encrypted at rest |
| `restricted-ssh` | No security groups open SSH to the internet |

`iam-user-mfa-enabled` and `iam-password-policy` were intentionally excluded because identities are managed in IAM Identity Center, not IAM users.

**Amazon GuardDuty:** enabled and validated with sample findings (see Findings below).

**IAM Access Analyzer:** external access analyzer with the current account as the zone of trust.

### Phase 5: Secure-by-default guardrails

- Account-level S3 Block Public Access (all four settings)
- EBS encryption by default in US East (Ohio)
- Zero-spend budget and a $10 monthly cost budget with email alerts
- Cost Anomaly Detection monitor with an individual-alert subscription
- Tagging standard: `Project=baseline`, `Owner=chidera`

## Control mapping

NIST IDs are SP 800-53 Rev. 5. "CIS AWS section" refers to the section of the CIS AWS Foundations Benchmark. SOC 2 refers to the 2017 Trust Services Criteria.

| # | Control | AWS implementation | NIST 800-53 | CIS AWS section | SOC 2 | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | Privileged account protection | Root MFA on, no root access keys, root unused | IA-2(1), AC-6(5), AC-2 | IAM | CC6.1 | [P1-01](Evidence/P1-01-root-mfa-enabled.png), [P1-02](Evidence/P1-02-root-no-access-keys.png) |
| 2 | Security contact registered | Alternate contacts for Billing, Ops, Security | IR-6 | IAM | CC2.3 | [P1-03](Evidence/P1-03-alternate-contacts.png) |
| 3 | Centralized identity | IAM Identity Center users | AC-2, IA-2 | IAM | CC6.2 | [P2-04](Evidence/P2-04-auditor-access-denied.png), [P3-04](Evidence/P3-04-cloudtrail-event-history.png) |
| 4 | Role-based least privilege | AdminAccess and AuditorReadOnly permission sets; access-denied test | AC-3, AC-6 | IAM | CC6.3 | [P2-02](Evidence/P2-02-permission-sets.png), [P2-04](Evidence/P2-04-auditor-access-denied.png) |
| 5 | Multi-factor authentication | MFA required at every sign-in | IA-2(1), IA-2(2) | IAM | CC6.1 | [P2-03](Evidence/P2-03-mfa-required-settings.png) |
| 6 | Session limits | 1-hour admin session duration | AC-12 | Not covered | CC6.1 | [P2-02](Evidence/P2-02-permission-sets.png) |
| 7 | Audit logging | Multi-Region CloudTrail, management events | AU-2, AU-3, AU-12 | Logging | CC7.2 | [P3-01](Evidence/P3-01b-trail-multiregion-validation-AFTER.png) |
| 8 | Log integrity | Log file validation on | AU-9 | Logging | CC7.2 | [P3-01](Evidence/P3-01b-trail-multiregion-validation-AFTER.png) |
| 9 | Log protection | Encrypted log bucket, Block Public Access | AU-9, SC-28 | Logging | CC6.1 | [P3-02a](Evidence/P3-02a-log-bucket-encryption.png), [P3-02b](Evidence/P3-02b-log-bucket-block-public-access.png) |
| 10 | Log retention | Glacier at 90 days, expire at 365 days | AU-11 | Not covered | CC7.2 | [P3-03](Evidence/P3-03-log-bucket-lifecycle-rule.png) |
| 11 | Configuration monitoring | AWS Config recorder and 8 managed rules | CM-2, CM-6, CA-7 | Logging | CC7.1 | [P4-01](Evidence/P4-01-config-rules-compliance.png) |
| 12 | Threat detection | GuardDuty enabled, sample findings reviewed | SI-4, IR-4 | Not covered | CC7.2, CC7.3 | [P4-02](Evidence/P4-02-guardduty-sample-finding.png) |
| 13 | External access review | Access Analyzer, findings triaged, scoped archive rule | AC-3, CA-7 | IAM | CC6.1 | [P4-03a](Evidence/P4-03a-access-analyzer-finding-detail.png), [P4-03b](Evidence/P4-03b-access-analyzer-zero-active.png), [P4-03c](Evidence/P4-03c-archive-rule.png) |
| 14 | Public storage prevention | Account-level S3 Block Public Access | AC-3, SC-7 | Storage | CC6.1, CC6.6 | [P5-02](Evidence/P5-02-s3-account-block-public-access.png) |
| 15 | Encryption at rest | EBS encryption by default; S3 SSE | SC-28 | Storage | CC6.1 | [P5-03](Evidence/P5-03-ebs-default-encryption.png), [P3-02a](Evidence/P3-02a-log-bucket-encryption.png) |
| 16 | Asset inventory | Tagging standard; Config resource inventory | CM-8 | Not covered | CC6.1 | [P5-04](Evidence/P5-04-tagging-standard.png) |

## Findings and remediation

### Finding 1: CloudTrail log file validation disabled

| | |
| --- | --- |
| **Severity** | Medium |
| **Control** | AU-9 Protection of Audit Information; SOC 2 CC7.2 |
| **Observation** | After creating `org-audit-trail`, a post-deployment review showed log file validation was **disabled**. Without it, changes to or deletion of log files could go undetected. |
| **Remediation** | Edited the trail and enabled log file validation. |
| **Verification** | Trail details now show *Log file validation: Enabled* ([P3-01](Evidence/P3-01b-trail-multiregion-validation-AFTER.png)). The Config rule `cloud-trail-log-file-validation-enabled` now monitors this continuously, so a future regression would be flagged automatically. |
| **Status** | Closed |

### Finding 2: IAM Access Analyzer reported external access on two IAM roles

| | |
| --- | --- |
| **Severity** | Informational (intended access) |
| **Control** | AC-3 Access Enforcement, CA-7 Continuous Monitoring; SOC 2 CC6.1 |
| **Observation** | Access Analyzer reported 2 active findings for roles under `aws-reserved/sso.amazonaws.com/`, trusted by a federated principal. |
| **Analysis** | Reviewed each finding. Both roles were created by IAM Identity Center for the `AdminAccess` and `AuditorReadOnly` permission sets, and the external principal is the account's own Identity Center SAML provider. This is the intended sign-in path, not unintended exposure. |
| **Action** | Archived both findings as intended access. Created a narrowly scoped archive rule (`archive-identity-center-roles`) matching only Identity Center–managed IAM roles, **with "Public access is false" added** so the rule can never hide a publicly assumable role. |
| **Verification** | Active findings: 0 ([P4-03b](Evidence/P4-03b-access-analyzer-zero-active.png)); archive rule ([P4-03c](Evidence/P4-03c-archive-rule.png)). |
| **Status** | Closed, accepted as intended access |

### Finding 3: GuardDuty sample finding (detection validation)

| | |
| --- | --- |
| **Type** | `Backdoor:EC2/DenialOfService.Udp` |
| **Severity** | High |
| **Control** | SI-4 System Monitoring, IR-4 Incident Handling; SOC 2 CC7.2, CC7.3 |
| **Observation** | GuardDuty sample findings were generated to confirm detection and alerting work. The selected finding reports that EC2 instance `i-99999999` (a fictitious sample resource) is behaving in a way that suggests it is being used to launch a UDP denial-of-service attack. |
| **What it means** | If real, the instance is likely compromised and being used to attack others. This is a sign of attacker control of the host, not just a misconfiguration, and it creates legal and reputational risk because the attack traffic comes from our IP addresses. |
| **Response if real** | 1. **Contain:** isolate the instance by replacing its security group with one that allows no traffic, and remove it from any load balancer or Auto Scaling group. 2. **Preserve evidence:** snapshot its EBS volumes before making changes. 3. **Investigate:** review CloudTrail and VPC Flow Logs to find how it was compromised and whether the instance role's credentials were used elsewhere. 4. **Eradicate and recover:** terminate the instance, rebuild from a known-good, patched image, and rotate any credentials it could access. 5. **Lessons learned:** fix the root cause (for example, an exposed port or unpatched software) and document the incident. |
| **Status** | Detection validated; sample findings archived after review |

## Design decisions

- **Single-Region Identity Center instance.** The multi-Region option encrypts Identity Center with a customer managed, multi-Region KMS key, which adds a monthly cost. For a single-person lab I chose a single-Region instance. In production I would use the multi-Region instance with a customer managed key for resilience (CP-6/CP-7) and key control (SC-12).
- **SSE-S3 instead of SSE-KMS for CloudTrail logs.** SSE-S3 is free and meets the encryption requirement here. A production log archive would use SSE-KMS with a dedicated key so access to logs can be restricted separately from access to the bucket.
- **Narrowly scoped suppression.** Archive rules can hide real risk if they're too broad, so the Access Analyzer rule matches only Identity Center–managed roles and never public findings.

## Operational guardrails

- **Zero-spend budget:** alerts on the first cent of spend
- **Monthly cost budget:** $10 with email alerts
- **Cost Anomaly Detection:** AWS services monitor with individual email alerts
- **Tagging standard:** `Project` and `Owner` tags on project resources

These are cost-governance controls rather than security controls, so they're kept out of the control mapping.

## Lessons learned

- **Defaults aren't always secure.** Log file validation was off after trail creation, which shows why post-deployment verification and continuous monitoring matter.
- **Not every finding is a risk.** Access Analyzer flagged the Identity Center roles. The right response was to investigate, document why the access is intended, and suppress narrowly, not just dismiss it.
- **Evidence beats assertions.** The auditor's access-denied error and CloudTrail events attributed to named users prove the controls work. Configuration screenshots alone only prove they exist.
- **AWS account setup has changed.** New sign-ups may land in a simplified "projects" experience without a root user or fine-grained IAM. A classic account was needed to build this baseline as designed.

## What I'd do differently in production

- Use AWS Organizations with separate accounts for security tooling and log archive, plus service control policies to prevent disabling CloudTrail, Config or GuardDuty
- Centralize CloudTrail logs in a dedicated log archive account that workload administrators can't modify, with S3 Object Lock for immutability
- Enable Security Hub to aggregate findings and score against CIS and AWS Foundational Security Best Practices
- Route GuardDuty and Config alerts to a ticketing or chat channel with an on-call owner

## Next steps

- **Project 2:** CIS AWS Foundations Benchmark audit with Security Hub, including before/after scoring and an exceptions register

## Evidence

All screenshots are in [`Evidence/`](Evidence/). Account IDs, email addresses and ARNs are redacted.
