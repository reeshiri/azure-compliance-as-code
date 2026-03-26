"""
collect_activity_logs.py — Azure Monitor Activity Log evidence collector

Evidence ID : azure_activity_logs
Auth needed : Bearer token via DefaultAzureCredential (Reader on subscription)

All Azure REST calls use requests + a bearer token rather than the
azure-mgmt-monitor SDK. This avoids SDK version breakages — the REST API
surface is stable and versioned independently of the Python packages.

Controls satisfied:
  PCI-DSS   10.2.1, 10.2.2, 10.3.3, 10.7.1
  SOC 2     CC7.2
  ISO 27001 A.8.15
  ISO 42001 6.5.1
"""

import argparse
import requests
from datetime import datetime, timezone, timedelta

from azure.identity import DefaultAzureCredential

from base import BaseCollector

LOOKBACK_DAYS = 90
ARM = "https://management.azure.com"


class ActivityLogsCollector(BaseCollector):

    def _headers(self):
        token = self.credential.get_token(f"{ARM}/.default").token
        return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    def collect(self) -> dict:
        h = self._headers()
        sub = self.subscription_id

        # ── 1. Diagnostic settings ──────────────────────────────────────────
        diag_url = (
            f"{ARM}/subscriptions/{sub}/providers/microsoft.insights"
            f"/diagnosticSettings?api-version=2021-05-01-preview"
        )
        diag_resp = requests.get(diag_url, headers=h)
        raw_settings = diag_resp.json().get("value", []) if diag_resp.status_code == 200 else []

        settings_detail = []
        any_storage = False
        any_log_analytics = False
        min_retention_days = None

        for setting in raw_settings:
            props = setting.get("properties", {})
            has_storage = bool(props.get("storageAccountId"))
            has_law = bool(props.get("workspaceId"))

            if has_storage:
                any_storage = True
            if has_law:
                any_log_analytics = True

            retention_days = None
            rp = props.get("retentionPolicy", {})
            if rp.get("enabled") and rp.get("days"):
                retention_days = rp["days"]
                if min_retention_days is None or retention_days < min_retention_days:
                    min_retention_days = retention_days

            settings_detail.append({
                "name": setting.get("name"),
                "storage_account": props.get("storageAccountId"),
                "log_analytics_workspace": props.get("workspaceId"),
                "event_hub": props.get("eventHubAuthorizationRuleId"),
                "retention_days": retention_days,
                "logs_enabled": [
                    log.get("category") or log.get("categoryGroup")
                    for log in props.get("logs", [])
                    if log.get("enabled")
                ],
            })

        # ── 2. Activity log alert rules ─────────────────────────────────────
        alert_url = (
            f"{ARM}/subscriptions/{sub}/providers/microsoft.insights"
            f"/activityLogAlerts?api-version=2020-10-01"
        )
        alert_resp = requests.get(alert_url, headers=h)
        raw_alerts = alert_resp.json().get("value", []) if alert_resp.status_code == 200 else []

        alert_detail = []
        for alert in raw_alerts:
            props = alert.get("properties", {})
            alert_detail.append({
                "name": alert.get("name"),
                "enabled": props.get("enabled", False),
                "scopes": props.get("scopes", []),
            })

        enabled_alerts = [a for a in alert_detail if a["enabled"]]

        # ── 3. Recent activity log events ───────────────────────────────────
        start = (datetime.now(timezone.utc) - timedelta(days=LOOKBACK_DAYS)).isoformat()
        end = datetime.now(timezone.utc).isoformat()

        events_url = (
            f"{ARM}/subscriptions/{sub}/providers/microsoft.insights/eventtypes"
            f"/management/values?api-version=2015-04-01"
            f"&$filter=eventTimestamp ge '{start}' and eventTimestamp le '{end}'"
            f"&$select=operationName,eventTimestamp,caller,level,status"
        )
        events_resp = requests.get(events_url, headers=h)
        raw_events = events_resp.json().get("value", []) if events_resp.status_code == 200 else []

        op_counts: dict[str, int] = {}
        total_events = len(raw_events)
        sample_events = []

        for ev in raw_events:
            op_name = ev.get("operationName", {}).get("value", "unknown")
            op_counts[op_name] = op_counts.get(op_name, 0) + 1
            if len(sample_events) < 10:
                sample_events.append({
                    "operation": op_name,
                    "timestamp": ev.get("eventTimestamp"),
                    "caller": ev.get("caller"),
                    "level": ev.get("level", {}).get("value"),
                })

        top_operations = sorted(op_counts.items(), key=lambda x: x[1], reverse=True)[:20]

        retention_ok = (min_retention_days is not None and min_retention_days >= 90)

        return {
            "lookback_days": LOOKBACK_DAYS,
            "diagnostic_settings_count": len(settings_detail),
            "diagnostic_settings": settings_detail,
            "alert_rules_total": len(alert_detail),
            "alert_rules_enabled": len(enabled_alerts),
            "write_event_count_sampled": total_events,
            "top_operation_types": top_operations,
            "sample_recent_events": sample_events,
            "compliance_signals": {
                "diagnostic_settings_configured": len(raw_settings) > 0,
                "logs_sent_to_storage_or_law": any_storage or any_log_analytics,
                "retention_meets_90_days": retention_ok,
                "activity_log_alerts_configured": len(enabled_alerts) > 0,
                "active_logging_confirmed": total_events > 0,
            },
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
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
