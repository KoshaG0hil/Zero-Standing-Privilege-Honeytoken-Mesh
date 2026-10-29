# Comprehensive Project Guide: Zero-Standing-Privilege Honeytoken Defense Mesh

This guide explains the architectural decisions, design patterns, and engineering rationale underpinning the **Zero-Standing-Privilege (ZSP) Dynamic Access & Honeytoken Defense Mesh on AWS**.

---

## 1. Problem Statement & Motivation

Standing IAM privileges (static access keys and long-lived admin credentials) are the leading vector for cloud account takeovers:
- Stolen developer credentials from workstations, GitHub leaks, or compromised CI/CD pipelines grant unbounded access.
- Attackers dwell undetected inside cloud environments using valid credentials (MITRE ATT&CK T1078).
- Manual incident response takes hours or days to revoke sessions and rotate compromised keys.

The **ZSP Honeytoken Mesh** addresses these challenges by eliminating standing privileges altogether and planting tripwire canary credentials that trigger sub-second automated neutralization.

---

## 2. Engineering Architecture & Design Patterns

### Zero-Standing-Privilege (ZSP) Elevation Pattern
- Privileged access is granted purely just-in-time (JIT) via an ephemeral STS token broker.
- Credentials expire in 15 minutes by default (maximum 60 minutes).
- Requests require multi-factor authentication (MFA) and approved change ticket IDs.

### Canary Decoy Defense Pattern
- Decoy canary credentials with zero operational rights are placed across high-risk surfaces (code repositories, S3 backups, private keys).
- Because these credentials serve no legitimate purpose, any interaction signals confirmed hostile intrusion (0% false positives).

### Sub-Second Automated Revocation Engine
- AWS EventBridge intercepts CloudTrail API calls from the canary principal.
- An event-driven Lambda function immediately terminates active STS sessions and attaches an inline `DenyAll` quarantine policy.
- A cryptographic SHA-256 forensic report is signed and preserved in Amazon S3 with Object Lock.
