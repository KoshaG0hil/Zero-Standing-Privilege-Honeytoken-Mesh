# SecOps Incident Response Runbook: Canary Honeytoken Tripped

This operational runbook provides instructions for security analysts investigating and responding to canary tripwire activations.

---

## 1. Triage & Incident Verification

1. **Verify Alert Authenticity:**
   - Canary honeytokens have zero legitimate operational use. Any API call to a honeytoken key represents confirmed adversarial activity.
2. **Review Forensic Manifest:**
   - Retrieve the SHA-256 incident report from Amazon S3:
   ```bash
   aws s3 cp s3://zsp-honeytoken-mesh-prod-forensics-<ACCOUNT_ID>/reports/ . --recursive
   ```
3. **Inspect Attacker Source IP & User Agent:**
   - Review CloudTrail logs:
   ```bash
   aws cloudtrail lookup-events \
     --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=<CANARY_KEY_ID>
   ```

---

## 2. Automated Containment Verification

Verify that the `HoneytokenRevocationEngine` performed all automated containment actions:
1. **Inline Deny Policy Check:**
   ```bash
   aws iam get-user-policy --user-name <CALLER_USER> --policy-name EmergencyQuarantineDenyAll
   ```
2. **Active STS Revocation:**
   Verify the revocation condition `aws:CurrentTime < [Timestamp]` was applied to target privileged roles.

---

## 3. Post-Incident Eradication

1. **Rotate Leaked Repository Secrets:**
   If the canary token was located in a Git repository, audit all neighboring secrets in that repository and trigger credential rotation.
2. **Archive Forensic Evidence:**
   Verify the cryptographic SHA-256 manifest is locked under AWS S3 Object Lock for legal non-repudiation.
