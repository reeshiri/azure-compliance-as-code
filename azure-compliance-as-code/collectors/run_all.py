"""
run_all.py — run all four Azure compliance collectors and print a summary

Usage:
    python run_all.py --subscription-id <SUB_ID> --tenant-id <TENANT_ID>

The EVIDENCE_DIR environment variable controls where artifacts are written.
Defaults to ./evidence relative to the working directory.

How it works:
  This script is the entry point for both local runs and the GitHub Actions
  workflow. It creates one credential object (DefaultAzureCredential) and
  passes it to each collector. DefaultAzureCredential is smart — it
  automatically selects the right authentication method:

    - In GitHub Actions: uses the OIDC token from the workflow
    - On your local machine: uses your Azure CLI login (run 'az login' first)
    - In Azure VMs / Cloud Shell: uses the managed identity

  This means you never write auth code specific to one environment — the
  same script works everywhere.
"""

import argparse
import sys

from azure.identity import DefaultAzureCredential

from collect_activity_logs import ActivityLogsCollector
from collect_entra_id import EntraIDCollector
from collect_azure_policy import AzurePolicyCollector
from collect_defender import DefenderCollector

# Each tuple is (evidence_id, CollectorClass)
# The evidence_id must match the folder name used in controls.yaml
COLLECTORS = [
    ("azure_activity_logs",      ActivityLogsCollector),
    ("azure_entra_id_posture",   EntraIDCollector),
    ("azure_policy_compliance",  AzurePolicyCollector),
    ("azure_defender_findings",  DefenderCollector),
]


def main():
    parser = argparse.ArgumentParser(description="Run all Azure compliance collectors")
    parser.add_argument("--subscription-id", required=True, help="Azure subscription ID")
    parser.add_argument("--tenant-id", required=True, help="Azure tenant / directory ID")
    args = parser.parse_args()

    # DefaultAzureCredential tries multiple auth methods in order.
    # In GitHub Actions the AZURE_CLIENT_ID, AZURE_TENANT_ID, and
    # AZURE_SUBSCRIPTION_ID environment variables set by the OIDC action
    # make the WorkloadIdentityCredential path succeed automatically.
    credential = DefaultAzureCredential()

    print(f"\n{'='*56}")
    print(f"  Azure Compliance Collectors")
    print(f"  subscription : {args.subscription_id}")
    print(f"  tenant       : {args.tenant_id}")
    print(f"{'='*56}\n")

    results = {}
    errors = []

    for evidence_id, CollectorClass in COLLECTORS:
        print(f"── {evidence_id}")
        try:
            collector = CollectorClass(
                evidence_id,
                credential,
                args.subscription_id,
                args.tenant_id,
            )
            artifact = collector.run()
            results[evidence_id] = artifact

            signals = (artifact.get("data") or {}).get("compliance_signals", {})
            for k, v in signals.items():
                if isinstance(v, list):
                    tag = "ℹ" if not v else "⚠"
                    label = "(none)" if not v else ", ".join(str(x) for x in v[:3])
                    print(f"     {tag}  {k}: {label}")
                elif isinstance(v, (int, float)):
                    print(f"     ℹ  {k}: {v}")
                else:
                    icon = "✓" if v else "✗"
                    print(f"     {icon}  {k}")

            if artifact["status"] == "error":
                errors.append(evidence_id)

        except Exception as exc:
            print(f"     ✗  COLLECTOR CRASHED: {exc}")
            errors.append(evidence_id)

        print()

    total = len(COLLECTORS)
    ok = total - len(errors)
    print(f"{'='*56}")
    print(f"  {ok}/{total} collectors succeeded")
    if errors:
        print(f"  Failed: {', '.join(errors)}")
    print(f"  Evidence written to: ./evidence/")
    print(f"{'='*56}\n")

    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
