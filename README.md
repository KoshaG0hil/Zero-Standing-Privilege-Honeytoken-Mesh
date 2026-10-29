# Zero-Standing-Privilege (ZSP) Dynamic Access & Honeytoken Defense Mesh

[![CI - ZSP Honeytoken Mesh](https://github.com/KoshaG0hil/Zero-Standing-Privilege-Honeytoken-Mesh/actions/workflows/ci.yml/badge.svg)](https://github.com/KoshaG0hil/Zero-Standing-Privilege-Honeytoken-Mesh/actions/workflows/ci.yml)
[![Cyber SOC Dashboard](https://img.shields.io/badge/Live_SOC_Console-GitHub_Pages-f59e0b?logo=github)](https://koshag0hil.github.io/Zero-Standing-Privilege-Honeytoken-Mesh/)
[![Security Architecture](https://img.shields.io/badge/AWS-Zero--Standing--Privilege-orange?logo=amazon-aws)](https://aws.amazon.com/iam/)
[![Threat Defense](https://img.shields.io/badge/MITRE_ATT%26CK-T1078_Valid_Accounts-rose)](https://attack.mitre.org/techniques/T1078/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

An enterprise **Zero-Standing-Privilege (ZSP) Dynamic Access & Canary Honeytoken Defense Mesh** on AWS that eliminates static administrative credentials through ephemeral Just-In-Time (JIT) STS assume-role elevation and deploys high-fidelity decoy honeytokens to neutralize compromised credentials in sub-seconds.

Architected by **[Kosha Gohil](https://www.linkedin.com/in/kosha-gohil/)**, AWS Cloud Security & DevSecOps Engineer.

---

## 🛡️ Core Security Capabilities

- **Zero Standing Privilege (ZSP) Access Broker:** Replaces permanent IAM admin access keys with ephemeral, just-in-time STS credentials bounded by 15-minute default TTLs, verified MFA, and mandatory change ticket validation (`CHG-`, `SEC-`).
- **High-Fidelity Canary Honeytokens:** Generates and distributes decoy IAM access keys, S3 canary objects, and fake secrets across Git repositories and dev environments with zero false positives.
- **Sub-Second Automated Containment:** Event-driven AWS Lambda engine triggered by CloudTrail and Amazon EventBridge that attaches emergency `DenyAll` inline IAM boundaries and revokes active STS sessions in < 5ms upon any canary interaction.
- **Tamper-Evident Forensic Incident Manifests:** Generates SHA-256 cryptographically signed JSON forensic incident reports committed to Amazon S3 with Object Lock for legal non-repudiation and SecOps attribution.
- **Production-Ready Terraform IaC:** Infrastructure as Code provisioning ephemeral privileged IAM roles, decoy canary principals, EventBridge tripwire rules, automated revocation Lambdas, DynamoDB session trackers, and encrypted forensic S3 storage.

---

## 📊 Live Interactive Cyber SOC Console

Experience the interactive ZSP & Honeytoken simulation console on GitHub Pages:  
👉 **[https://koshag0hil.github.io/Zero-Standing-Privilege-Honeytoken-Mesh/](https://koshag0hil.github.io/Zero-Standing-Privilege-Honeytoken-Mesh/)**

Simulate JIT role elevation countdowns and trigger decoy honeytoken tripwires to observe real-time automated session revocation and containment timelines.

---

## 🏗️ Architecture Overview

```
                      +---------------------------------------+
                      |       Ephemeral STS Token Broker      |
                      |  (MFA Enforced · Max 15-60m TTL)      |
                      +---------------------------------------+
                                          |
                                          v
                      +---------------------------------------+
                      |    Ephemeral Privileged STS Session   |
                      |  (Session ID / Temporary ASIA... Key) |
                      +---------------------------------------+

                      +---------------------------------------+
                      |       Decoy Canary Honeytoken         |
                      | (Planted in Git Repo / .env / Secrets)|
                      +---------------------------------------+
                                          |
                                          v (Adversary touches Canary Key)
                      +---------------------------------------+
                      |    AWS CloudTrail + Amazon EventBridge |
                      +---------------------------------------+
                                          |
                                          v
    +-------------------------------------------------------------------------+
    |               Automated Honeytoken Revocation Engine (Lambda)            |
    |                                                                         |
    |  [1. Attach Inline DenyAll] -> [2. Terminate Active STS] -> [3. SHA-256]|
    +-------------------------------------------------------------------------+
                                          |
                                          v
                      +---------------------------------------+
                      |   Encrypted S3 Forensic Manifest      |
                      |       (Signed SHA-256 Hash)           |
                      +---------------------------------------+
```

---

## ⚡ Quick Start

### 1. Installation
```bash
git clone https://github.com/KoshaG0hil/Zero-Standing-Privilege-Honeytoken-Mesh.git
cd Zero-Standing-Privilege-Honeytoken-Mesh

# Install dependencies
pip install -r requirements.txt
```

### 2. Run Simulation CLI
```bash
python -m src.cli simulate
```

### 3. Run Pytest Suite
```bash
pytest -v
```

---

## 📁 Repository Structure

```
Zero-Standing-Privilege-Honeytoken-Mesh/
├── .github/workflows/
│   ├── ci.yml                     # Pytest, Ruff linting & Terraform validation
│   └── pages.yml                  # GitHub Pages deployment workflow
├── docs/
│   ├── ARCHITECTURE.md            # Topology and ZSP security boundaries
│   ├── HONEYTOKEN_MATRIX.md       # Decoy honeytoken placement strategy
│   └── RUNBOOKS.md                # SecOps incident response procedures
├── reports/
│   └── zsp_forensic_incident_report.json # Signed SHA-256 forensic report
├── src/
│   ├── broker/                    # Ephemeral STS token broker
│   ├── core/                      # Pydantic schemas and enums
│   ├── honeytokens/               # Canary generation and tripwire matching
│   ├── remediators/               # Sub-second automated session revoker
│   ├── reporters/                 # SHA-256 forensic manifest generator
│   ├── cli.py                     # Operator command-line interface
│   └── lambda_honeytoken_remediator.py # EventBridge Lambda handler
├── terraform/
│   ├── main.tf                    # Provider configuration & locals
│   ├── variables.tf               # Input parameters
│   ├── zsp_honeytoken_mesh.tf     # Roles, decoy keys, EventBridge, Lambda, S3
│   ├── outputs.tf                 # Resource ARNs and identifiers
│   └── terraform.tfvars.example   # Sample variable definitions
├── tests/                         # Pytest test suite (100% passing)
├── index.html                     # Interactive Cyber SOC Console
├── Dockerfile                     # Containerized simulation image
├── run.ps1 / run.sh / run.bat     # One-click execution scripts
└── pyproject.toml / requirements.txt
```

---

## 👩‍💻 Author

**Kosha Gohil**  
Cloud Security & DevSecOps Engineer  
- 💼 LinkedIn: [linkedin.com/in/kosha-gohil](https://www.linkedin.com/in/kosha-gohil/)  
- 🐙 GitHub: [@KoshaG0hil](https://github.com/KoshaG0hil)  
