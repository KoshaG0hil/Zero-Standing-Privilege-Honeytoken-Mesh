# Honeytoken Placement & Tripwire Strategy Matrix

This matrix describes the decoy honeytoken types, placement locations, and automated tripwire triggers implemented across the mesh.

---

### Placement & Trigger Taxonomy

| Honeytoken Type | Deployment Vector | Decoy Asset | Trigger Condition | Automated Containment |
| :--- | :--- | :--- | :--- | :--- |
| **IAM Access Key** | Git Repositories (`.env.production`) | Decoy `AKIA...` key with zero permissions | `sts:GetCallerIdentity` via CloudTrail | Immediate emergency `DenyAll` policy attached, active sessions revoked. |
| **S3 Canary Bucket** | Internal documentation & wikis | Decoy `s3://internal-dev-assets/` object | `s3:GetObject` / `s3:ListBucket` | Source IP isolated in AWS WAF, security advisory dispatched. |
| **Secrets Manager** | Kubernetes ConfigMap / Helm chart | Decoy secret `prod/rds/master-credentials` | `secretsmanager:GetSecretValue` | Offending IAM principal quarantined, RDS credential rotation triggered. |
| **STS Canary Role** | AWS CLI credential profiles | Decoy cross-account assume role ARN | `sts:AssumeRole` from untrusted CIDR | Principal role trust revoked, active sessions dropped. |

---

### MITRE ATT&CK Mapping

- **T1078 (Valid Accounts):** Zero-standing privilege prevents attackers from leveraging dormant user credentials.
- **T1552 (Unsecured Credentials):** Honeytokens planted in repositories act as tripwires when threat actors search for secrets.
- **T1530 (Data from Cloud Storage Object):** Decoy canary S3 buckets expose unauthorized enumeration attempts immediately.
