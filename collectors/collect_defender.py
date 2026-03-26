"""
collect_defender.py — Microsoft Defender for Cloud evidence collector

Evidence ID : azure_defender_findings
Auth needed : Bearer token via DefaultAzureCredential (Security Reader on subscription)

Uses direct REST API calls rather than azure-mgmt-security SDK to avoid
the PricingsOperations.list() signature change in v7.

Controls satisfied:
  PCI-DSS   6.3.3, 11.3.1, 11.3.2
  SOC 2     CC7.1, CC7.2
  ISO 27001 A.8.8
  ISO 42001 6.6.2
"""

import argparse
import requests
from collections import defaultdict

from azure.identity import DefaultAzureCredential

from base import BaseCollector

ARM = "https://management.azure.com"

EXPECTED_PLANS = {
    "VirtualMachines",
    "SqlServers",
    "AppServices",
    "StorageAccounts",
    "KeyVaults",
    "Containers",
    "Arm",
}


class DefenderCollector(BaseCollector):

    def _headers(self):
        token = self.credential.get_token(f"{ARM}/.default").token
        return {"Authorization": f"Bearer {token}"}

    def _get(self, url, params=None):
        h = self._headers()
        results = []
        while url:
            resp = requests.get(url, headers=h, params=params)
            if resp.status_code != 200:
                break
            data = resp.json()
            # Some endpoints return a single object, others return value list
            if "value" in data:
                results.extend(data["value"])
            else:
                return data  # single object response
            url = data.get("nextLink")
            params = None
        return results

    def collect(self) -> dict:
        sub = self.subscription_id

        # ── 1. Defender plan status ─────────────────────────────────────────
        # Each resource type has its own pricing tier (Free vs Standard).
        # Standard = Defender fully enabled for that resource type.
        pricings_url = (
            f"{ARM}/subscriptions/{sub}/providers/Microsoft.Security"
            f"/pricings?api-version=2024-01-01"
        )
        raw_pricings = self._get(pricings_url)

        plan_status = {}
        if isinstance(raw_pricings, list):
            for plan in raw_pricings:
                props = plan.get("properties", {})
                name = plan.get("name", "")
                plan_status[name] = {
                    "pricing_tier": props.get("pricingTier", "Free"),
                    "enabled": props.get("pricingTier") == "Standard",
                }

        plans_enabled = [p for p in EXPECTED_PLANS if plan_status.get(p, {}).get("enabled", False)]
        plans_disabled = [p for p in EXPECTED_PLANS if not plan_status.get(p, {}).get("enabled", False)]

        # ── 2. Secure Score ─────────────────────────────────────────────────
        score_url = (
            f"{ARM}/subscriptions/{sub}/providers/Microsoft.Security"
            f"/secureScores?api-version=2020-01-01"
        )
        raw_scores = self._get(score_url)
        secure_score = None

        if isinstance(raw_scores, list):
            for score in raw_scores:
                if score.get("name") == "ascScore":
                    props = score.get("properties", {})
                    score_val = props.get("score", {})
                    current = score_val.get("current")
                    maximum = score_val.get("max") or 1
                    if current is not None:
                        secure_score = round(current / maximum * 100, 1)
                    break

        # ── 3. Active security assessments (recommendations) ────────────────
        assessments_url = (
            f"{ARM}/subscriptions/{sub}/providers/Microsoft.Security"
            f"/assessments?api-version=2021-06-01"
        )
        raw_assessments = self._get(assessments_url)

        rec_counts = defaultdict(int)
        critical_recs = []
        high_recs = []

        if isinstance(raw_assessments, list):
            for assessment in raw_assessments:
                props = assessment.get("properties", {})
                status = props.get("status", {}).get("code", "")
                if status != "Unhealthy":
                    continue

                metadata = props.get("metadata", {}) or {}
                sev = metadata.get("severity", "UNKNOWN").upper()
                rec_counts[sev] += 1

                summary = {
                    "recommendation_name": (
                        props.get("displayName")
                        or assessment.get("name", "")
                    ),
                    "resource_id": (
                        props.get("resourceDetails", {}).get("Id")
                        or assessment.get("id", "")
                    ),
                    "severity": sev,
                    "description": (metadata.get("description") or "")[:200],
                    "remediation": (metadata.get("remediationDescription") or
                                   "See Defender for Cloud portal for remediation steps.")[:300],
                }

                if sev == "CRITICAL" and len(critical_recs) < 10:
                    critical_recs.append(summary)
                elif sev == "HIGH" and len(high_recs) < 10:
                    high_recs.append(summary)

        # ── 4. Active security alerts ───────────────────────────────────────
        alerts_url = (
            f"{ARM}/subscriptions/{sub}/providers/Microsoft.Security"
            f"/alerts?api-version=2022-01-01"
        )
        raw_alerts = self._get(alerts_url)

        alert_counts = defaultdict(int)
        critical_alerts = []
        high_alerts = []

        if isinstance(raw_alerts, list):
            for alert in raw_alerts:
                props = alert.get("properties", {})
                if props.get("status") in ("Dismissed", "Resolved"):
                    continue

                sev = props.get("severity", "UNKNOWN").upper()
                alert_counts[sev] += 1

                alert_summary = {
                    "alert_name": props.get("alertDisplayName") or alert.get("name"),
                    "severity": sev,
                    "status": props.get("status"),
                    "resource_id": props.get("compromisedEntity", "N/A"),
                    "description": (props.get("description") or "")[:200],
                    "remediation": (
                        props.get("remediationSteps", [""])[0]
                        if props.get("remediationSteps")
                        else "See Defender for Cloud portal."
                    ),
                }

                if sev == "CRITICAL" and len(critical_alerts) < 10:
                    critical_alerts.append(alert_summary)
                elif sev == "HIGH" and len(high_alerts) < 10:
                    high_alerts.append(alert_summary)

        # ── 5. Security contacts ─────────────────────────────────────────────
        contacts_url = (
            f"{ARM}/subscriptions/{sub}/providers/Microsoft.Security"
            f"/securityContacts?api-version=2020-01-01-preview"
        )
        raw_contacts = self._get(contacts_url)
        security_contacts = []

        if isinstance(raw_contacts, list):
            for contact in raw_contacts:
                props = contact.get("properties", {})
                security_contacts.append({
                    "email": props.get("email"),
                    "phone": props.get("phone"),
                    "alert_notifications": props.get("alertNotifications"),
                })

        # ── Compliance signals ──────────────────────────────────────────────
        return {
            "plan_status": plan_status,
            "plans_enabled": plans_enabled,
            "plans_disabled": plans_disabled,
            "secure_score_pct": secure_score,
            "recommendations_by_severity": dict(rec_counts),
            "alerts_by_severity": dict(alert_counts),
            "critical_recommendations_sample": critical_recs,
            "high_recommendations_sample": high_recs,
            "critical_alerts_sample": critical_alerts,
            "high_alerts_sample": high_alerts,
            "security_contacts": security_contacts,
            "compliance_signals": {
                "defender_cspm_enabled": plan_status.get("CloudPosture", {}).get("enabled", False),
                "defender_servers_enabled": plan_status.get("VirtualMachines", {}).get("enabled", False),
                "defender_storage_enabled": plan_status.get("StorageAccounts", {}).get("enabled", False),
                "all_expected_plans_enabled": len(plans_disabled) == 0,
                "secure_score_above_70pct": (secure_score or 0) >= 70,
                "no_critical_alerts": alert_counts.get("CRITICAL", 0) == 0,
                "no_high_alerts": alert_counts.get("HIGH", 0) == 0,
                "security_contact_configured": len(security_contacts) > 0,
                "critical_alert_count": alert_counts.get("CRITICAL", 0),
                "high_alert_count": alert_counts.get("HIGH", 0),
            },
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--subscription-id", required=True)
    parser.add_argument("--tenant-id", required=True)
    args = parser.parse_args()

    credential = DefaultAzureCredential()
    result = DefenderCollector(
        "azure_defender_findings", credential, args.subscription_id, args.tenant_id
    ).run()

    signals = (result.get("data") or {}).get("compliance_signals", {})
    for k, v in signals.items():
        if isinstance(v, (int, float)):
            print(f"  ℹ  {k}: {v}")
        else:
            icon = "✓" if v else "✗"
            print(f"  {icon}  {k}")
