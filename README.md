# Azure Compliance as Code

Automated evidence collection and gap reporting for Azure environments across
PCI-DSS, SOC 2, ISO 27001, and ISO 42001 — powered by Python, GitHub Actions,
and the Azure SDK.

This project is the Azure equivalent of the AWS compliance-as-code project
and follows the exact same pattern: collect evidence once per week, map it to
framework control IDs, generate CSV reports, and open GitHub Issues for gaps.

---

## What this project does

Every week, a GitHub Actions workflow:

1. Authenticates to Azure using Workload Identity Federation / OIDC
   (no stored access keys or client secrets anywhere)
2. Runs four Python collectors against your Azure subscription
3. Maps the evidence to control IDs across all four frameworks simultaneously
4. Generates three CSV reports covering signal health, control coverage,
   and individual findings
5. Commits everything to this repository, creating a timestamped audit trail
6. Opens a GitHub Issue for every failing control with affected resources and
   remediation guidance

---

## Azure service to framework mapping

| Azure Service | AWS Equivalent | What it checks |
|---|---|---|
| **Azure Monitor Activity Logs** | CloudTrail | Diagnostic settings, retention, alert rules, log flow |
| **Entra ID (Azure Active Directory)** | IAM | MFA status, Conditional Access, privileged roles, stale SP credentials |
| **Azure Policy** | AWS Config | Policy compliance rate, non-compliant resources, initiative assignment |
| **Microsoft Defender for Cloud** | Security Hub | Plans enabled, Secure Score, active alerts, security recommendations |

---

## Frameworks covered

| Framework | Focus |
|---|---|
| **PCI-DSS v4** | Payment card data security |
| **SOC 2 Type II** | Security, availability, and confidentiality trust principles |
| **ISO 27001:2022** | Information security management system |
| **ISO 42001:2023** | AI management system |

---

## Repository structure

```
├── .github/
│   └── workflows/
│       └── azure_compliance.yml      # weekly automation
├── collectors/
│   ├── base.py                       # shared output format
│   ├── collect_activity_logs.py      # Azure Monitor Activity Logs
│   ├── collect_entra_id.py           # Entra ID / Azure Active Directory
│   ├── collect_azure_policy.py       # Azure Policy compliance
│   ├── collect_defender.py           # Microsoft Defender for Cloud
│   └── run_all.py                    # runs all four collectors
├── docs/
│   └── azure_setup.md               # full setup instructions
├── evidence/                         # auto-committed JSON artifacts
├── reports/                          # auto-committed CSV reports
├── controls.yaml                     # evidence → framework control ID mapping
├── generate_report.py               # reads evidence + controls.yaml → CSVs
├── setup_dummy_data.py              # creates test resources with intentional findings
└── requirements.txt
```

---

## Authentication

The workflow uses **Workload Identity Federation** (Azure's name for OIDC)
to assume an Azure identity. The GitHub Actions workflow exchanges a short-lived
GitHub token for a short-lived Azure access token scoped to this repository.

No client secrets are stored anywhere. This satisfies PCI-DSS 8.2.1, SOC 2 CC6.1,
and ISO 27001 A.5.16.

---

## Reports

Three CSV files are generated into `reports/` on every run.

**`01_summary.csv`** — one row per compliance signal showing PASS, FAIL, or ERROR
plus the framework control IDs that signal satisfies.

**`02_control_coverage.csv`** — one row per framework control ID showing whether
all signals covering that control are passing. This is the auditor view.

**`03_findings_detail.csv`** — one row per individual finding: specific users
without MFA, specific non-compliant resource IDs, specific Defender alerts.
This is the remediation worklist.

---

## Running locally

```bash
# Log in to Azure CLI
az login
az account set --subscription "<your-subscription-id>"

# Set up Python environment
python -m venv .venv
source .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Run collectors
python collectors/run_all.py \
    --subscription-id "<your-subscription-id>" \
    --tenant-id "<your-tenant-id>"

# Generate reports
python generate_report.py \
    --evidence-dir evidence \
    --controls controls.yaml \
    --output-dir reports
```

---

## Setup

See [docs/azure_setup.md](docs/azure_setup.md) for full instructions covering
App Registration, Workload Identity Federation, RBAC role assignments, Graph API
permissions, and GitHub secrets setup.
