# Azure Compliance as Code

Automated compliance evidence collection for Microsoft Azure, mapped to four
frameworks simultaneously: PCI-DSS v4, SOC 2 Type II, ISO 27001:2022, and
ISO 42001:2023.

Instead of collecting evidence manually before an audit, this runs every week
on a schedule. It queries your Azure subscription via direct REST API calls,
evaluates each control, commits the results to git as a timestamped audit
trail, and opens a GitHub Issue for every failing control with the affected
resource and a remediation step.

Uses Workload Identity Federation for keyless authentication -- no client
secrets stored anywhere.

---
## Compliance documents

| Document | Description |
|---|---|
| [NIST CSF 2.0 Crosswalk](docs/NIST_CSF2_Crosswalk_GCP.docx) | Maps all evidence signals to NIST CSF 2.0 subcategories |
