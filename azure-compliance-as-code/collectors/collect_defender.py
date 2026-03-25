"""
collect_defender.py — Microsoft Defender for Cloud evidence collector

Evidence ID : azure_defender_findings
SDK needed  : azure-mgmt-security
RBAC needed : Security Reader (built-in) on the subscription

What Defender for Cloud is and why it matters:
  Microsoft Defender for Cloud is Azure's unified security posture management
  and threat protection platform. It is the direct equivalent of AWS Security Hub.

  It does two things:
    1. Secure Score  — gives you a percentage score based on how many
                       security recommendations you have implemented
    2. Alerts        — generates threat detection alerts (like GuardDuty)

  For compliance, we care about:
    - Whether Defender plans are enabled (proves active monitoring)
    - Secure Score (a single number representing your overall posture)
    - Active recommendations at High/Critical severity (your gap list)
    - Active security alerts at High/Critical severity (active threats)

Azure equivalent mapping:
  Security Hub enabled          →  Defender for Cloud enabled per plan
  Security Hub standards        →  Defender plans (CSPM, Servers, Storage, etc.)
  Critical/High findings sample →  High/Critical recommendations + alerts
  No critical findings signal   →  no_critical_alerts signal

Controls satisfied:
  PCI-DSS   6.3.3, 11.3.1, 11.3.2
  SOC 2     CC7.1, CC7.2
  ISO 27001 A.8.8
  ISO 42001 6.6.2
"""

import argparse
from collections import defaultdict

from azure.identity import DefaultAzureCredential
from azure.mgmt.security import SecurityCenter
from azure.mgmt.security.models import SecurityContact

from base import BaseCollector

# Defender plans we expect to be enabled.
# "Free" tier = basic recommendations only.
# "Standard" (now called "Defender for X") = full threat detection + compliance.
EXPECTED_PLANS = {
    "VirtualMachines",   # Defender for Servers
    "SqlServers",        # Defender for SQL
    "AppServices",       # Defender for App Service
    "StorageAccounts",   # Defender for Storage
    "KeyVaults",         # Defender for Key Vault
    "Containers",        # Defender for Containers (replaces AKS)
    "Arm",               # Defender for Resource Manager
}


class DefenderCollector(BaseCollector):

    def collect(self) -> dict:
        security = SecurityCenter(self.credential, self.subscription_id)

        # ── 1. Defender plan status ─────────────────────────────────────────
        # Each resource type has its own Defender plan that can be toggled on/off.
        # A plan in "Standard" pricing tier means full Defender is enabled for
        # that resource type. "Free" means only basic posture management.
        pricings = list(security.pricings.list())
        plan_status = {}
        for plan in pricings:
            plan_status[plan.name] = {
                "pricing_tier": plan.pricing_tier,
                "enabled": plan.pricing_tier == "Standard",
            }

        plans_enabled = [
            p for p in EXPECTED_PLANS
            if plan_status.get(p, {}).get("enabled", False)
        ]
        plans_disabled = [
            p for p in EXPECTED_PLANS
            if not plan_status.get(p, {}).get("enabled", False)
        ]

        # ── 2. Secure Score ─────────────────────────────────────────────────
        # The Secure Score is a single number (0-100%) that tells you what
        # percentage of security controls you have satisfied. Auditors often
        # ask for this as a snapshot of overall posture.
        try:
            scores = list(security.secure_scores.list())
            secure_score = None
            for score in scores:
                if score.name == "ascScore":
                    if score.score and score.score.current is not None:
                        max_score = score.score.max or 1
                        secure_score = round(
                            score.score.current / max_score * 100, 1
                        )
                    break
        except Exception:
            secure_score = None

        # ── 3. Active security recommendations ─────────────────────────────
        # Recommendations are suggestions to improve your posture.
        # Unlike alerts (which are active threats), recommendations are
        # configuration gaps. Think of them like Config rule findings.
        # We pull High and Critical ones as these map to your framework gaps.
        rec_counts = defaultdict(int)
        critical_recs = []
        high_recs = []

        try:
            tasks = list(security.tasks.list())
            for task in tasks:
                sev = (
                    task.security_task_parameters.additional_properties.get(
                        "severity", "UNKNOWN"
                    )
                    if task.security_task_parameters else "UNKNOWN"
                ).upper()

                rec_counts[sev] += 1

                rec_summary = {
                    "recommendation_name": task.name,
                    "state": task.state,
                    "severity": sev,
                    "resource_id": getattr(task, "resource_id", None),
                }

                if sev == "HIGH" and len(high_recs) < 10:
                    high_recs.append(rec_summary)
                elif sev == "CRITICAL" and len(critical_recs) < 10:
                    critical_recs.append(rec_summary)
        except Exception:
            pass

        # Also check assessments (the newer Defender for Cloud API surface)
        try:
            assessments = list(security.assessments.list(scope=f"/subscriptions/{self.subscription_id}"))
            for assessment in assessments:
                status_code = (
                    assessment.status.code if assessment.status else "Unknown"
                )
                if status_code != "Unhealthy":
                    continue

                sev = "UNKNOWN"
                if assessment.metadata and assessment.metadata.severity:
                    sev = assessment.metadata.severity.upper()

                rec_counts[sev] += 1

                summary = {
                    "recommendation_name": (
                        assessment.display_name or assessment.name
                    ),
                    "resource_id": (
                        assessment.resource_details.id
                        if assessment.resource_details else None
                    ),
                    "severity": sev,
                    "description": (
                        assessment.metadata.description[:200]
                        if assessment.metadata and assessment.metadata.description
                        else None
                    ),
                    "remediation": (
                        assessment.metadata.remediation_description[:300]
                        if assessment.metadata and assessment.metadata.remediation_description
                        else "See Defender for Cloud portal for remediation steps."
                    ),
                }

                if sev == "CRITICAL" and len(critical_recs) < 10:
                    critical_recs.append(summary)
                elif sev == "HIGH" and len(high_recs) < 10:
                    high_recs.append(summary)
        except Exception:
            pass

        # ── 4. Active security alerts ───────────────────────────────────────
        # Alerts are active threat detections (anomalous logins, crypto miners,
        # lateral movement attempts, etc.). Unlike recommendations they mean
        # something is happening NOW, not just that a setting is misconfigured.
        alert_counts = defaultdict(int)
        critical_alerts = []
        high_alerts = []

        try:
            alerts = list(security.alerts.list())
            for alert in alerts:
                # Only look at active alerts — dismissed / resolved ones are historical
                if alert.status in ("Dismissed", "Resolved"):
                    continue

                sev = (alert.alert_severity or "UNKNOWN").upper()
                alert_counts[sev] += 1

                alert_summary = {
                    "alert_name": alert.alert_display_name or alert.name,
                    "severity": sev,
                    "status": alert.status,
                    "resource_id": (
                        alert.compromised_entity or
                        (alert.entities[0].additional_properties.get("$id") if alert.entities else None)
                    ),
                    "description": (alert.description or "")[:200],
                    "remediation": alert.remediation_steps[0] if alert.remediation_steps else None,
                }

                if sev == "CRITICAL" and len(critical_alerts) < 10:
                    critical_alerts.append(alert_summary)
                elif sev == "HIGH" and len(high_alerts) < 10:
                    high_alerts.append(alert_summary)
        except Exception:
            pass

        # ── 5. Security contacts ─────────────────────────────────────────────
        # Defender for Cloud should have a security contact email configured
        # so alerts actually reach a human. A missing contact is a process gap.
        security_contacts = []
        try:
            for contact in security.security_contacts.list():
                security_contacts.append({
                    "email": contact.email,
                    "phone": contact.phone,
                    "alert_notifications": contact.alert_notifications,
                    "alerts_to_admins": contact.alerts_to_admins,
                })
        except Exception:
            pass

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
                # Core plans should all be enabled
                "defender_cspm_enabled": plan_status.get("CloudPosture", {}).get("enabled", False),
                "defender_servers_enabled": plan_status.get("VirtualMachines", {}).get("enabled", False),
                "defender_storage_enabled": plan_status.get("StorageAccounts", {}).get("enabled", False),
                "all_expected_plans_enabled": len(plans_disabled) == 0,
                # Posture health
                "secure_score_above_70pct": (secure_score or 0) >= 70,
                # Alert hygiene
                "no_critical_alerts": alert_counts.get("CRITICAL", 0) == 0,
                "no_high_alerts": alert_counts.get("HIGH", 0) == 0,
                # Operational process
                "security_contact_configured": len(security_contacts) > 0,
                # For detail rows
                "critical_alert_count": alert_counts.get("CRITICAL", 0),
                "high_alert_count": alert_counts.get("HIGH", 0),
            },
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Collect Defender for Cloud evidence")
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
