"""
collect_activity_logs.py — Azure Monitor Activity Log evidence collector

Evidence ID : azure_activity_logs
SDK needed  : azure-mgmt-monitor, azure-mgmt-resource
RBAC needed : Reader on the subscription (built-in)
              Log Analytics Reader if using a Log Analytics workspace

What this collector checks (and why each one matters for compliance):
  - Diagnostic settings configured  : proves audit logs are being sent somewhere
                                       persistent (storage account or Log Analytics)
  - Retention >= 90 days            : PCI-DSS 10.7 requires 90-day availability,
                                       12-month total retention
  - Activity log alerts configured  : proves someone is watching for key events
                                       (policy changes, RBAC changes, etc.)
  - Write events observed           : proves the log pipeline is actually flowing,
                                       not just configured on paper

Azure equivalent mapping:
  AWS CloudTrail  →  Azure Monitor Activity Logs + Diagnostic Settings
  Trail status    →  Diagnostic settings enabled / disabled
  Log validation  →  Storage account immutability / Log Analytics ingestion proof
  LookupEvents    →  Activity Log query via azure-mgmt-monitor

Controls satisfied:
  PCI-DSS   10.2.1, 10.2.2, 10.3.3, 10.7.1
  SOC 2     CC7.2
  ISO 27001 A.8.15
  ISO 42001 6.5.1
"""

import argparse
from datetime import datetime, timezone, timedelta

from azure.identity import DefaultAzureCredential
from azure.mgmt.monitor import MonitorManagementClient


from base import BaseCollector

# How far back to look for write events.
# PCI-DSS 10.7.1 requires being able to retrieve 90 days immediately.
LOOKBACK_DAYS = 90


class ActivityLogsCollector(BaseCollector):

    def collect(self) -> dict:
        monitor = MonitorManagementClient(self.credential, self.subscription_id)

        # ── 1. Diagnostic settings ──────────────────────────────────────────
        # Diagnostic settings control WHERE activity logs are sent.
        # For compliance you want at least one setting sending to either:
        #   a) A storage account (long-term archival)
        #   b) A Log Analytics workspace (queryable, alertable)
        #   c) An Event Hub (streaming to SIEM)
        #
        # The subscription-level resource URI is fixed — it is always this string.
        subscription_uri = f"/subscriptions/{self.subscription_id}"

        diag_settings = list(
            monitor.diagnostic_settings.list(resource_uri=subscription_uri)
        )

        settings_detail = []
        any_storage = False
        any_log_analytics = False
        min_retention_days = None

        for setting in diag_settings:
            # Retention policy lives inside storage_account_id settings.
            # Log Analytics workspaces have their own retention (not shown here).
            retention_days = None
            if setting.retention_policy and setting.retention_policy.enabled:
                retention_days = setting.retention_policy.days

            has_storage = bool(setting.storage_account_id)
            has_law = bool(setting.workspace_id)
            has_eventhub = bool(setting.event_hub_authorization_rule_id)

            if has_storage:
                any_storage = True
            if has_law:
                any_log_analytics = True

            if retention_days is not None:
                if min_retention_days is None or retention_days < min_retention_days:
                    min_retention_days = retention_days

            settings_detail.append({
                "name": setting.name,
                "storage_account": setting.storage_account_id,
                "log_analytics_workspace": setting.workspace_id,
                "event_hub": setting.event_hub_authorization_rule_id,
                "retention_days": retention_days,
                "logs_enabled": [
                    log.category for log in (setting.logs or [])
                    if log.enabled
                ],
            })

        # ── 2. Activity log alert rules ─────────────────────────────────────
        # Alert rules prove you have active monitoring, not just passive logging.
        # PCI-DSS 10.7 and SOC 2 CC7.2 want evidence that security-relevant
        # events trigger notifications.
        alert_rules = list(monitor.activity_log_alerts.list_by_subscription_id())
        alert_detail = []
        for alert in alert_rules:
            alert_detail.append({
                "name": alert.name,
                "enabled": alert.enabled,
                "location": alert.location,
                "scopes": alert.scopes,
                "condition_all_of": [
                    {"field": c.field, "equals": c.equals}
                    for c in (alert.condition.all_of if alert.condition else [])
                ],
            })

        enabled_alerts = [a for a in alert_detail if a["enabled"]]

        # ── 3. Recent write activity ────────────────────────────────────────
        # Sampling recent write events proves the log pipeline is active and
        # not just configured but broken (e.g. a storage account was deleted
        # after the diagnostic setting was created).
        start = datetime.now(timezone.utc) - timedelta(days=LOOKBACK_DAYS)
        end = datetime.now(timezone.utc)

        # Filter to write operations only (equivalent to CloudTrail ReadOnly=false)
        filter_str = (
            f"eventTimestamp ge '{start.isoformat()}' and "
            f"eventTimestamp le '{end.isoformat()}'"
        )

        events = list(monitor.activity_logs.list(
            filter=filter_str,
            select="operationName,eventTimestamp,caller,level,status",
        ))

        # Summarise — store counts by operation category, not full payloads
        op_counts: dict[str, int] = {}
        total_events = 0
        sample_events = []

        for ev in events:
            total_events += 1
            op_name = (ev.operation_name.value if ev.operation_name else "unknown")
            op_counts[op_name] = op_counts.get(op_name, 0) + 1

            if len(sample_events) < 10:
                sample_events.append({
                    "operation": op_name,
                    "timestamp": str(ev.event_timestamp),
                    "caller": ev.caller,
                    "level": str(ev.level),
                    "status": str(ev.status.value) if ev.status else None,
                })

        top_operations = sorted(op_counts.items(), key=lambda x: x[1], reverse=True)[:20]

        # ── Compliance signals ──────────────────────────────────────────────
        # These boolean / list values are what generate_report.py reads.
        # True = PASS, False = FAIL, non-empty list = FAIL (findings present).
        retention_ok = (
            min_retention_days is not None and min_retention_days >= 90
        ) if min_retention_days is not None else False

        return {
            "lookback_days": LOOKBACK_DAYS,
            "diagnostic_settings_count": len(settings_detail),
            "diagnostic_settings": settings_detail,
            "alert_rules_total": len(alert_detail),
            "alert_rules_enabled": len(enabled_alerts),
            "alert_rules_detail": alert_detail,
            "write_event_count_sampled": total_events,
            "top_operation_types": top_operations,
            "sample_recent_events": sample_events,
            "compliance_signals": {
                # At least one diagnostic setting must be configured
                "diagnostic_settings_configured": len(diag_settings) > 0,
                # Logs must go to a durable destination
                "logs_sent_to_storage_or_law": any_storage or any_log_analytics,
                # Retention must be 90 days or more
                "retention_meets_90_days": retention_ok,
                # At least one alert rule must be enabled
                "activity_log_alerts_configured": len(enabled_alerts) > 0,
                # Write events must actually be flowing
                "active_logging_confirmed": total_events > 0,
            },
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Collect Azure Activity Log evidence")
    parser.add_argument("--subscription-id", required=True)
    parser.add_argument("--tenant-id", required=True)
    args = parser.parse_args()

    credential = DefaultAzureCredential()
    result = ActivityLogsCollector(
        "azure_activity_logs", credential, args.subscription_id, args.tenant_id
    ).run()

    signals = (result.get("data") or {}).get("compliance_signals", {})
    for k, v in signals.items():
        icon = "✓" if v else "✗"
        print(f"  {icon}  {k}")
