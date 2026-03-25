"""
collect_azure_policy.py — Azure Policy compliance evidence collector

Evidence ID : azure_policy_compliance
SDK needed  : azure-mgmt-policyinsights, azure-mgmt-resource
RBAC needed : Reader on the subscription (built-in)
              Policy Insights Read (included in Reader)

What Azure Policy does and why it matters:
  Azure Policy continuously evaluates your resources against rules you define
  (or use from Microsoft's built-in library). When a resource violates a rule
  it is marked Non-compliant. This is the direct Azure equivalent of AWS Config
  rules — both give you a continuous configuration compliance baseline.

  For compliance frameworks, Policy gives you:
    - Evidence that specific security rules exist and are being evaluated
    - A count of compliant vs non-compliant resources per rule
    - The specific resource IDs that are failing (your remediation list)

Azure equivalent mapping:
  AWS Config rules              →  Azure Policy initiative / policy definitions
  Config compliance %           →  Policy compliance state percentage
  High-value Config rule list   →  HIGH_VALUE_POLICIES set below
  Config NON_COMPLIANT resource →  Policy non-compliant resource details

Controls satisfied:
  PCI-DSS   2.2.1, 6.3.3
  SOC 2     CC6.6, CC7.1
  ISO 27001 A.8.9
  ISO 42001 6.6.1
"""

import argparse
from azure.identity import DefaultAzureCredential
from azure.mgmt.policyinsights import PolicyInsightsClient
from azure.mgmt.resource.policy import PolicyClient

from base import BaseCollector

# Policy definition names that carry significant compliance weight.
# When any of these show non-compliant resources we escalate the finding.
# These names match Microsoft's built-in policy display names.
HIGH_VALUE_POLICIES = {
    "mfa should be enabled on accounts with owner permissions on your subscription",
    "mfa should be enabled on accounts with write permissions on your subscription",
    "mfa should be enabled on accounts with read permissions on your subscription",
    "there should be more than one owner assigned to your subscription",
    "external accounts with owner permissions should be removed from your subscription",
    "external accounts with write permissions should be removed from your subscription",
    "auditing on sql server should be enabled",
    "secure transfer to storage accounts should be enabled",
    "storage accounts should restrict network access",
    "storage accounts should use customer-managed key for encryption",
    "public network access on azure sql database should be disabled",
    "virtual machines should encrypt temp disks, caches, and data flows between compute and storage resources",
    "system updates should be installed on your machines",
    "vulnerabilities in security configuration on your machines should be remediated",
    "endpoint protection solution should be installed on virtual machine scale sets",
    "monitor missing endpoint protection in azure security center",
    "internet-facing virtual machines should be protected with network security groups",
    "ssh access from the internet should be blocked",
    "rdp access from the internet should be blocked",
    "network security group flow logs should be enabled",
}


class AzurePolicyCollector(BaseCollector):

    def collect(self) -> dict:
        insights = PolicyInsightsClient(self.credential, self.subscription_id)
        policy_client = PolicyClient(self.credential, self.subscription_id)

        # ── 1. Summarise policy compliance state at subscription scope ───────
        # This gives us aggregate compliant / non-compliant counts quickly
        # without having to page through every single resource evaluation.
        summary_pages = list(
            insights.policy_states.summarize_for_subscription(
                subscription_id=self.subscription_id,
                query_options=type("Q", (), {"top": 1000, "filter": None})(),
            )
        )

        compliant_count = 0
        non_compliant_count = 0
        policy_summaries = []
        high_value_failures = []

        for summary in summary_pages:
            for policy_summary in (summary.policy_assignments or []):
                for policy_def in (policy_summary.policy_definitions or []):
                    display_name = (
                        (policy_def.policy_definition_id or "").split("/")[-1]
                    ).lower()

                    results = policy_def.results
                    if not results:
                        continue

                    nc = results.non_compliant_resources or 0
                    c = results.compliant_resources or 0

                    compliant_count += c
                    non_compliant_count += nc

                    is_high_value = any(
                        hvp in display_name for hvp in HIGH_VALUE_POLICIES
                    )

                    if nc > 0:
                        if is_high_value:
                            high_value_failures.append(display_name)

                        policy_summaries.append({
                            "policy_id": policy_def.policy_definition_id,
                            "compliant_resources": c,
                            "non_compliant_resources": nc,
                            "is_high_value": is_high_value,
                        })

        # ── 2. Non-compliant resource details ────────────────────────────────
        # For each non-compliant policy, pull up to 10 specific resource IDs.
        # These become the rows in 03_findings_detail.csv — the remediation list.
        non_compliant_resources = []
        try:
            nc_states = insights.policy_states.list_query_results_for_subscription(
                policy_states_resource="latest",
                subscription_id=self.subscription_id,
                query_options=type(
                    "Q", (), {
                        "top": 500,
                        "filter": "complianceState eq 'NonCompliant'",
                        "select": (
                            "resourceId,policyDefinitionName,"
                            "policyAssignmentName,complianceState"
                        ),
                    }
                )(),
            )

            for state in nc_states:
                non_compliant_resources.append({
                    "resource_id": state.resource_id,
                    "policy_definition": state.policy_definition_name,
                    "policy_assignment": state.policy_assignment_name,
                    "compliance_state": state.compliance_state,
                })

                # Cap at 200 for artifact size
                if len(non_compliant_resources) >= 200:
                    break
        except Exception as exc:
            print(f"  [WARN] Could not list non-compliant resources: {exc}")

        # ── 3. Policy initiative (assignment) list ──────────────────────────
        # This proves which security benchmarks are actively being assessed.
        # Equivalent to checking which Config conformance packs are deployed.
        # Microsoft Defender for Cloud automatically assigns built-in initiatives
        # like Azure Security Benchmark when it is enabled.
        initiatives = []
        try:
            for assignment in policy_client.policy_assignments.list():
                initiatives.append({
                    "name": assignment.display_name or assignment.name,
                    "policy_definition_id": assignment.policy_definition_id,
                    "enforcement_mode": str(assignment.enforcement_mode),
                    "scope": assignment.scope,
                })
        except Exception:
            pass

        # ── Compliance signals ──────────────────────────────────────────────
        total_evaluated = compliant_count + non_compliant_count
        compliance_pct = (
            round(compliant_count / total_evaluated * 100, 1)
            if total_evaluated > 0 else 0
        )

        # Azure Security Benchmark initiative is assigned by Defender for Cloud
        asb_assigned = any(
            "azure security benchmark" in (i.get("name") or "").lower()
            for i in initiatives
        )
        pci_policy_assigned = any(
            "pci" in (i.get("name") or "").lower()
            for i in initiatives
        )

        return {
            "total_policies_evaluated": len(policy_summaries),
            "compliant_resources": compliant_count,
            "non_compliant_resources": non_compliant_count,
            "compliance_percentage": compliance_pct,
            "policy_summaries_with_failures": policy_summaries,
            "non_compliant_resource_sample": non_compliant_resources[:50],
            "initiatives_assigned": initiatives,
            "compliance_signals": {
                "all_policies_compliant": non_compliant_count == 0,
                "compliance_rate_above_90pct": compliance_pct >= 90,
                "no_high_value_policy_failures": len(high_value_failures) == 0,
                "azure_security_benchmark_assigned": asb_assigned,
                "pci_policy_initiative_assigned": pci_policy_assigned,
                # Used for detail row generation — list = FAIL signal
                "high_value_failures": high_value_failures,
                "non_compliant_resource_count": non_compliant_count,
            },
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Collect Azure Policy compliance evidence")
    parser.add_argument("--subscription-id", required=True)
    parser.add_argument("--tenant-id", required=True)
    args = parser.parse_args()

    credential = DefaultAzureCredential()
    result = AzurePolicyCollector(
        "azure_policy_compliance", credential, args.subscription_id, args.tenant_id
    ).run()

    signals = (result.get("data") or {}).get("compliance_signals", {})
    for k, v in signals.items():
        if isinstance(v, list):
            tag = "ℹ" if not v else "⚠"
            label = "(none)" if not v else ", ".join(str(x) for x in v[:3])
            print(f"  {tag}  {k}: {label}")
        elif isinstance(v, int):
            print(f"  ℹ  {k}: {v}")
        else:
            icon = "✓" if v else "✗"
            print(f"  {icon}  {k}")
