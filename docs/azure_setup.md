# Azure Compliance Automation — Setup Guide

This document covers the one-time Azure and GitHub configuration needed before
the compliance workflow can run. It is the Azure equivalent of `docs/setup.md`
from the AWS project.

The goal is the same as the AWS setup: no stored secrets, no credentials to
rotate, and a read-only identity that cannot do damage if something goes wrong.

---

## How authentication works (plain English)

In the AWS project, the workflow used OIDC to get a short-lived AWS role token.
Azure uses the exact same concept but calls it **Workload Identity Federation**.

When the GitHub Actions workflow runs:

1. GitHub generates a one-time signed token that says "this is a run from
   workflow X in repo Y, triggered by event Z".
2. Azure has been configured to trust tokens from GitHub's token issuer,
   but ONLY for your specific repository.
3. The `azure/login` action in the workflow presents that token to Azure and
   gets back a short-lived access token scoped to your subscription.
4. `DefaultAzureCredential` in the Python collectors automatically picks up
   that token — you write no authentication code at all.

No client secret is ever created. No password is ever stored in GitHub.

---

## Step 1 — Create an App Registration in Entra ID

An App Registration is Azure's way of representing an application (in this case
your GitHub Actions workflow) as an identity in Entra ID.

1. Go to **Azure Portal > Entra ID > App registrations > New registration**.
2. Give it a name: `github-compliance-collector` (or similar).
3. Leave the redirect URI blank. Click **Register**.
4. Note the **Application (client) ID** and **Directory (tenant) ID** from the
   overview page. You will need both.

**Important:** Do NOT create a client secret. We will use federated credentials
instead, which means there is no secret to manage.

---

## Step 2 — Add a Federated Credential

This is the step that trusts GitHub without a password.

1. In your App Registration, go to **Certificates & secrets > Federated credentials**.
2. Click **Add credential**.
3. Select **GitHub Actions deploying Azure resources** as the scenario.
4. Fill in:
   - **Organization**: your GitHub org or username
   - **Repository**: your repo name
   - **Entity type**: Branch
   - **Branch**: `main`
   - **Name**: `github-actions-main`
5. Click **Add**.

This tells Azure: "Trust GitHub tokens from the `main` branch of `your-org/your-repo`
and exchange them for credentials on behalf of this app registration."

If you also want manual workflow dispatch runs from other branches to work, add
additional federated credentials for those branches, or use **Entity type: Pull request**.

---

## Step 3 — Assign Azure RBAC roles to the App Registration

The App Registration needs read-only access to collect evidence. Assign these
roles at the **subscription scope**:

| Role | Why it is needed |
|---|---|
| **Reader** | Read all resources, Policy compliance, Activity Logs |
| **Security Reader** | Read Defender for Cloud plans, alerts, and recommendations |

To assign roles:

1. Go to **Azure Portal > Subscriptions > [your subscription] > Access control (IAM)**.
2. Click **Add > Add role assignment**.
3. Select **Reader**, then on the Members tab add your App Registration as the principal.
4. Repeat for **Security Reader**.

**Note:** Security Reader is a built-in role. If you cannot find it, check that
Microsoft Defender for Cloud is enabled on the subscription.

---

## Step 4 — Grant Microsoft Graph API permissions

The Entra ID collector (`collect_entra_id.py`) uses the Microsoft Graph API
to read user MFA status, Conditional Access policies, and directory roles.
Graph API access requires explicit admin consent — it does not flow from
the Azure RBAC roles above.

1. In your App Registration, go to **API permissions > Add a permission**.
2. Select **Microsoft Graph > Application permissions** (not Delegated).
3. Add these permissions:

| Permission | Why it is needed |
|---|---|
| `User.Read.All` | Read all users and their properties |
| `Directory.Read.All` | Read directory roles and members (Global Admin count) |
| `Policy.Read.All` | Read Conditional Access policies |
| `AuditLog.Read.All` | Read user sign-in activity |
| `Application.Read.All` | Read service principal credentials (stale key detection) |

4. Click **Grant admin consent for [your tenant]** at the top of the permissions
   page. This requires a Global Administrator to approve.

If you do not have Global Admin, ask your Entra ID administrator to grant consent.
The collectors will still run without Graph permissions — the Entra ID collector
will produce an error artifact instead of crashing the whole workflow.

---

## Step 5 — Configure GitHub repository secrets

Go to **Settings > Secrets and variables > Actions > New repository secret** and
add these three secrets:

| Secret name | Value |
|---|---|
| `AZURE_CLIENT_ID` | Application (client) ID from Step 1 |
| `AZURE_TENANT_ID` | Directory (tenant) ID from Step 1 |
| `AZURE_SUBSCRIPTION_ID` | Your Azure subscription ID |

These are technically IDs not passwords, but storing them as secrets keeps
your tenant topology out of public logs.

---

## Step 6 — Create GitHub issue labels

The workflow tags issues with `azure-compliance`, `automated`, and a per-source
label. Create these in **Issues > Labels**:

| Label | Suggested colour |
|---|---|
| `azure-compliance` | `#0075ca` |
| `automated` | `#e4e669` |
| `azure-activity-logs` | `#d93f0b` |
| `azure-entra-id-posture` | `#d93f0b` |
| `azure-policy-compliance` | `#d93f0b` |
| `azure-defender-findings` | `#d93f0b` |

---

## Step 7 — Run it manually the first time

1. Go to **Actions > Azure Compliance — collect and report > Run workflow**.
2. Leave the subscription ID override blank (it uses the secret).
3. Click **Run workflow**.
4. After it completes, check the job summary tab for fail counts.
5. Check **Issues** for any automatically opened compliance gaps.

---

## Running locally

For local development and testing, the collectors use `DefaultAzureCredential`
which automatically picks up your Azure CLI login.

```bash
# Log in with the Azure CLI
az login
az account set --subscription "<your-subscription-id>"

# Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Run all collectors
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

## Setting up test data

To create a set of intentionally misconfigured resources that let you verify
the collectors are working correctly:

```bash
python setup_dummy_data.py \
    --subscription-id "<your-subscription-id>" \
    --tenant-id "<your-tenant-id>" \
    --resource-group compliance-dummy-rg \
    --location eastus
```

To clean up everything the script created:

```bash
python setup_dummy_data.py \
    --subscription-id "<your-subscription-id>" \
    --tenant-id "<your-tenant-id>" \
    --resource-group compliance-dummy-rg \
    --destroy
```

---

## RBAC summary (least-privilege principle)

The App Registration has exactly these permissions and nothing more:

| Scope | Role / Permission | Collector that uses it |
|---|---|---|
| Subscription | Reader | All collectors |
| Subscription | Security Reader | `collect_defender.py` |
| Graph API | User.Read.All | `collect_entra_id.py` |
| Graph API | Directory.Read.All | `collect_entra_id.py` |
| Graph API | Policy.Read.All | `collect_entra_id.py` |
| Graph API | AuditLog.Read.All | `collect_entra_id.py` |
| Graph API | Application.Read.All | `collect_entra_id.py` |

The identity cannot write, delete, or modify any resources. It cannot create
users, change policies, or alter security configurations. This satisfies the
principle of least privilege required by PCI-DSS 7.1.1, SOC 2 CC6.1, and
ISO 27001 A.5.15.

---

## Troubleshooting

**"AADSTS700016: Application not found in directory"**
The client ID in your GitHub secret does not match an App Registration in the
specified tenant. Double-check `AZURE_CLIENT_ID` and `AZURE_TENANT_ID`.

**"Insufficient privileges to complete the operation" on Graph calls**
The Graph API permissions have not been granted admin consent. Ask your
Entra ID administrator to grant consent (Step 4 above).

**"AuthorizationFailed" on Azure resource calls**
The App Registration does not have Reader or Security Reader assigned on the
subscription. Repeat Step 3.

**Collector runs but evidence shows status: error**
Check the error field in `evidence/<evidence_id>/latest.json`. Each collector
catches its own exceptions and records them there rather than crashing the
whole workflow.
