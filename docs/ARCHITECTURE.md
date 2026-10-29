# Architecture: Zero-Standing-Privilege (ZSP) Dynamic Access & Honeytoken Defense Mesh

This specification details the Zero-Standing-Privilege (ZSP) access architecture and the high-fidelity Canary Honeytoken defense mesh on AWS.

---

## 1. High-Level Architectural Topology

```
+---------------------------------------------------------------------------------------------------+
|                                 Zero-Standing-Privilege (ZSP) Workflow                            |
|                                                                                                   |
|  [ Cloud Engineer / SecOps ]                                                                      |
|               |                                                                                   |
|               v  (MFA Verified + Approved Change Ticket ID)                                        |
|  [ Ephemeral STS Token Broker ] -------------------------------------------------------------+    |
|               |                                                                              |    |
|               v                                                                              |    |
|  [ AssumeRole (Max 15-60m TTL) ] ---> [ Ephemeral Privileged Session (Session ID / ASIA...) ]    |
|                                                                                              |    |
+----------------------------------------------------------------------------------------------|----+
                                                                                               |
                                                                                               v
+---------------------------------------------------------------------------------------------------+
|                              Canary Honeytoken Tripwire Trap Layer                                |
|                                                                                                   |
|  [ Decoy IAM Access Key (AKIA...) ] planted in:                                                   |
|   - Git Repositories (.env.production.local)                                                      |
|   - CI/CD Environment Variables & Build Caches                                                    |
|   - S3 Bucket / Private Backups                                                                   |
+---------------------------------------------------------------------------------------------------+
                                                  |
                                                  v  (Attacker executes GetCallerIdentity / S3 list)
+---------------------------------------------------------------------------------------------------+
|                                Event-Driven Detection & Neutralization                            |
|                                                                                                   |
|  [ AWS CloudTrail ] ---> [ Amazon EventBridge Rule ] ---> [ Session Revocation Engine (Lambda) ]  |
|                                                                      |                            |
|                     +------------------------------------------------+                            |
|                     v                                                v                            |
|     [ 1. Emergency inline DenyAll ]                 [ 2. Drop all active STS sessions ]           |
|     [ Attached to Caller Principal ]                [ aws:CurrentTime < RevocationTime ]          |
|                     |                                                |                            |
|                     +-----------------------+------------------------+                            |
|                                             |                                                     |
|                                             v                                                     |
|                     [ 3. SHA-256 Tamper-Evident Forensic Incident Manifest ]                     |
|                     [ Archived to Encrypted S3 Bucket with Object Lock ]                          |
+---------------------------------------------------------------------------------------------------+
```

---

## 2. Zero-Standing-Privilege Security Principles

1. **No Permanent IAM User Keys:** Zero static developer credentials exist in AWS IAM.
2. **Ephemeral Elevation with Maximum 15-Minute TTL:** Privileged actions occur only through short-lived STS assumed-role sessions.
3. **Decoy Canaries as High-Fidelity Tripwires:** Any interaction with a canary principal indicates hostile intent with 0% false positives.
4. **Sub-Second Containment:** Automated AWS Lambda hooks quarantine compromised identities and revoke standing privileges within milliseconds.
