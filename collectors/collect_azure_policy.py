"""
collect_azure_policy.py — Azure Policy compliance evidence collector

Evidence ID : azure_policy_compliance
Auth needed : Bearer token via DefaultAzureCredential (Reader on subscription)

Uses direct REST API calls rather than azure-mgmt-policyinsights SDK to
avoid version compatibility issues with that package.

Controls satisfied:
  PCI-DSS   2.2.1, 6.3.3
  SOC 2     CC6.6, CC7.1
  ISO 27001 A.8.9
  ISO 42001 6.6.1
"""

import argparse
import requests
from azure.identity import DefaultAzureCredential

from base import BaseCollector

ARM = "https://management.azure.com"

HIGH_VALUE_POLICIES = {
    "mfa should be enabled on accounts with owner permissions on your subscription",
    "mfa should be enabled on accounts with write permissions on your subscription",
    "mfa should be enabled on accounts with read permissions on your subscription",
    "there should be more than one owner assigned to your subscription",
    "external accounts with owner permissions should be removed from your subscription",
    "external accounts with write permissions should be removed from your subscription",
    "secure transfer to storage accounts should be enabled",
    "storage accounts should restrict network access",
    "internet-facing virtual machines should be protected with network security groups",
    "ssh access from the internet should be blocked",
    "rdp access from the internet should be blocked",
    "system updates should be installed on your machines",
    "vulnerabilities in security configuration on your machines should be remediated",
}


class AzurePolicyCollector(BaseCollector):

    def _headers(self):
        token = self.credential.get_token(f"{ARM}/.default").token
        return {"Authorization": f"Bearer {token}"}

    def _get(self, url, params=None):
        """GET with pagination support."""
        h = self._headers()
        results = []
        while url:
            resp = requests.get(url, headers=h, params=params)
            if resp.status_code != 200:
                break
            data = resp.json()
            results.extend(data.get("value", []))
            url = data.get("nextLink") or data.get("@odata.nextLink")
            params = None
        return results

    def collect(self) -> dict:
        sub = self.subscription_id

        # ── 1. Policy compliance summary via Policy Insights REST API ────────
        # This endpoint returns one row per (policy, resource) evaluation.
        # We summarise into compliant / non-compliant counts.
        summary_url = (
            f"{ARM}/subscriptions/{sub}/providers/Microsoft.PolicyInsights"
            f"/policyStates/latest/summarize?api-version=2019-10-01"
        )
        summary_resp = requests.post(summary_url, headers=self._headers())
        summary_data = summary_resp.json() if summary_resp.status_code == 200 else {}

        compliant_count = 0
        non_compliant_count = 0
        high_value_failures = []
        policy_summaries = []

        for item in summary_data.get("value", []):
            for policy_summary in item.get("policyAssignments", []):
                for policy_def in policy_summary.get("policyDefinitions", []):
                    results = policy_def.get("results", {})
                    nc = results.get("nonCompliantResources", 0)
                    c = results.get("compliantResources", 0)
                    compliant_count += c
                    non_compliant_count += nc

                    def_id = policy_def.get("policyDefinitionId", "").lower()
                    display = def_id.split("/")[-1].lower().replace("-", " ")
                    is_high_value = any(hvp in display for hvp in HIGH_VALUE_POLICIES)

                    if nc > 0:
                        if is_high_value:
                            high_value_failures.append(display)
                        policy_summaries.append({
                            "policy_id": policy_def.get("policyDefinitionId"),
                            "compliant_resources": c,
                            "non_compliant_resources": nc,
                            "is_high_value": is_high_value,
                        })

        # ── 2. Non-compliant resource details ────────────────────────────────
        nc_url = (
            f"{ARM}/subscriptions/{sub}/providers/Microsoft.PolicyInsights"
            f"/policyStates/latest/queryResults?api-version=2019-10-01"
            f"&$filter=complianceState eq 'NonCompliant'&$top=100"
        )
        nc_resp = requests.post(nc_url, headers=self._headers())
        nc_resources = []
        if nc_resp.status_code == 200:
            for state in nc_resp.json().get("value", []):
                nc_resources.append({
                    "resource_id": state.get("resourceId"),
                    "policy_definition": state.get("policyDefinitionName"),
                    "policy_assignment": state.get("policyAssignmentName"),
                    "compliance_state": state.get("complianceState"),
                })

        # ── 3. Policy assignments (initiatives) ──────────────────────────────
        assignments_url = (
            f"{ARM}/subscriptions/{sub}/providers/Microsoft.Authorization"
            f"/policyAssignments?api-version=2022-06-01"
        )
        raw_assignments = self._get(assignments_url)
        initiatives = []
        for assignment in raw_assignments:
            props = assignment.get("properties", {})
            initiatives.append({
                "name": props.get("displayName") or assignment.get("name"),
                "policy_definition_id": props.get("policyDefinitionId", ""),
                "enforcement_mode": props.get("enforcementMode", ""),
                "scope": props.get("scope", ""),
            })

        # ── Compliance signals ────────────────────────────────────────────────
        total_evaluated = compliant_count + non_compliant_count
        compliance_pct = (
            round(compliant_count / total_evaluated * 100, 1)
            if total_evaluated > 0 else 0
        )

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
            "non_compliant_resource_sample": nc_resources[:50],
            "initiatives_assigned": initiatives,
            "compliance_signals": {
                "all_policies_compliant": non_compliant_count == 0,
                "compliance_rate_above_90pct": compliance_pct >= 90,
                "no_high_value_policy_failures": len(high_value_failures) == 0,
                "azure_security_benchmark_assigned": asb_assigned,
                "pci_policy_initiative_assigned": pci_policy_assigned,
                "high_value_failures": high_value_failures,
                "non_compliant_resource_count": non_compliant_count,
            },
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
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
