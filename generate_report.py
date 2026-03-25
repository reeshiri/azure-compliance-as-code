"""
generate_report.py — Azure compliance gap report generator

Reads evidence/*/latest.json and controls.yaml, then writes three CSVs:

  reports/
  ├── 01_summary.csv          — one row per signal, PASS/FAIL, with framework IDs
  ├── 02_control_coverage.csv — one row per framework control, evidence status
  └── 03_findings_detail.csv  — individual findings (users without MFA, stale creds, etc.)

This file is intentionally very close to the AWS version so the same
audit team can read both with minimal context switching. The only
differences are:
  - Field names use azure_tenant / azure_sub instead of aws_account
  - Detail signal keys match the Azure collector output
  - Defender findings replace Security Hub findings

Usage:
    python generate_report.py [--evidence-dir EVIDENCE_DIR] [--controls CONTROLS_YAML]

How this script works (plain English):
  1. Load every evidence/*/latest.json file into a dict keyed by evidence_id
  2. Load controls.yaml which maps (evidence_id + signal) → framework control IDs
  3. For each entry in controls.yaml, look up the signal value in the evidence
     and decide if it is PASS, FAIL, or ERROR
  4. Write 01_summary.csv  — one row per signal
  5. Write 02_control_coverage.csv — pivot by (framework, control_id)
  6. Write 03_findings_detail.csv — expand list-valued signals into individual rows
"""

import argparse
import csv
import json
import os
from datetime import datetime, timezone
from pathlib import Path

import yaml


FRAMEWORKS = ["pci_dss", "soc2", "iso_27001", "iso_42001"]
FRAMEWORK_LABELS = {
    "pci_dss":   "PCI-DSS",
    "soc2":      "SOC 2",
    "iso_27001": "ISO 27001",
    "iso_42001": "ISO 42001",
}

# Signals that contain lists of specific affected resources.
# Each item in the list becomes a separate row in 03_findings_detail.csv.
# Format: signal_key → metadata about what the finding means and how to fix it.
DETAIL_SIGNALS = {
    "mfa_disabled_users": {
        "title": "Entra ID user without MFA registered",
        "evidence_id": "azure_entra_id_posture",
        "severity": "HIGH",
        "remediation": (
            "Require the user to register MFA in "
            "https://aka.ms/mfasetup or enforce via Conditional Access policy."
        ),
    },
    "stale_credentials": {
        "title": "Expired or stale service principal credential",
        "evidence_id": "azure_entra_id_posture",
        "severity": "HIGH",
        "remediation": (
            "Rotate or remove the credential in Azure portal > "
            "App registrations > Certificates & secrets."
        ),
    },
    "high_value_failures": {
        "title": "High-value Azure Policy failure",
        "evidence_id": "azure_policy_compliance",
        "severity": "HIGH",
        "remediation": (
            "Remediate the non-compliant resources shown in "
            "Azure Portal > Policy > Compliance."
        ),
    },
}


def load_evidence(evidence_dir: Path) -> dict:
    """Load all latest.json artifacts keyed by evidence_id."""
    evidence = {}
    for latest in evidence_dir.glob("*/latest.json"):
        evidence_id = latest.parent.name
        try:
            artifact = json.loads(latest.read_text())
            evidence[evidence_id] = artifact
        except json.JSONDecodeError as exc:
            print(f"  [WARN] Could not parse {latest}: {exc}")
    return evidence


def load_controls(controls_path: Path) -> list[dict]:
    with open(controls_path) as f:
        return yaml.safe_load(f)["controls"]


def get_signal_value(artifact: dict, signal: str):
    """Return the raw value of a compliance_signal from an artifact."""
    if artifact.get("status") == "error":
        return None
    return (artifact.get("data") or {}).get("compliance_signals", {}).get(signal)


def signal_status(value) -> str:
    """
    Convert a raw signal value to PASS / FAIL / ERROR.

    Rules:
      None           → ERROR  (evidence missing or collector failed)
      True           → PASS
      False          → FAIL
      Empty list []  → PASS   (no findings = good)
      Non-empty list → FAIL   (findings exist)
      Integer 0      → PASS   (zero bad things)
      Integer > 0    → INFO   (count, not a direct pass/fail)
    """
    if value is None:
        return "ERROR"
    if isinstance(value, bool):
        return "PASS" if value else "FAIL"
    if isinstance(value, list):
        return "PASS" if len(value) == 0 else "FAIL"
    if isinstance(value, (int, float)):
        return "PASS" if value == 0 else "INFO"
    return "UNKNOWN"


def account_id_from_artifact(artifact: dict) -> str:
    """Return the Azure subscription ID from an artifact, falling back gracefully."""
    return artifact.get("azure_sub") or artifact.get("aws_account") or "N/A"


def write_summary(controls: list, evidence: dict, out_path: Path, run_at: str):
    """
    01_summary.csv
    One row per control entry in controls.yaml.
    Each row shows PASS/FAIL for the signal and all the framework IDs it satisfies.

    This is the first thing an auditor sees — it answers "what did you check
    and did it pass?"
    """
    fieldnames = [
        "evidence_id",
        "signal",
        "description",
        "status",
        "collected_at",
        "azure_sub",
    ] + [FRAMEWORK_LABELS[f] for f in FRAMEWORKS]

    rows = []
    for ctrl in controls:
        eid = ctrl["evidence_id"]
        signal = ctrl["signal"]
        artifact = evidence.get(eid, {})
        value = get_signal_value(artifact, signal)
        status = signal_status(value)

        row = {
            "evidence_id": eid,
            "signal": signal,
            "description": ctrl["description"],
            "status": status,
            "collected_at": artifact.get("collected_at", "N/A"),
            "azure_sub": account_id_from_artifact(artifact),
        }

        for fw in FRAMEWORKS:
            control_ids = ctrl.get("frameworks", {}).get(fw, [])
            row[FRAMEWORK_LABELS[fw]] = "; ".join(control_ids) if control_ids else ""

        rows.append(row)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    fail_count = sum(1 for r in rows if r["status"] == "FAIL")
    print(f"  ✓  {out_path}  ({len(rows)} rows, {fail_count} failing)")


def write_control_coverage(controls: list, evidence: dict, out_path: Path, run_at: str):
    """
    02_control_coverage.csv
    One row per (framework, control_id).

    This answers the auditor's question: "Show me your evidence for PCI-DSS 8.4.2."
    They can look up any control ID and see exactly which signals cover it and
    whether they are all passing.
    """
    coverage: dict[tuple, list] = {}

    for ctrl in controls:
        eid = ctrl["evidence_id"]
        signal = ctrl["signal"]
        artifact = evidence.get(eid, {})
        value = get_signal_value(artifact, signal)
        status = signal_status(value)

        for fw in FRAMEWORKS:
            for ctrl_id in ctrl.get("frameworks", {}).get(fw, []):
                key = (FRAMEWORK_LABELS[fw], ctrl_id)
                coverage.setdefault(key, [])
                coverage[key].append({
                    "signal": signal,
                    "status": status,
                    "description": ctrl["description"],
                    "evidence_id": eid,
                })

    fieldnames = [
        "framework",
        "control_id",
        "overall_status",
        "evidence_count",
        "passing_signals",
        "failing_signals",
        "evidence_ids",
        "signal_descriptions",
    ]

    rows = []
    for (framework, ctrl_id), entries in sorted(coverage.items()):
        passing = [e for e in entries if e["status"] == "PASS"]
        failing = [e for e in entries if e["status"] in ("FAIL", "ERROR")]

        overall = "FAIL" if failing else ("PASS" if passing else "UNKNOWN")

        rows.append({
            "framework": framework,
            "control_id": ctrl_id,
            "overall_status": overall,
            "evidence_count": len(entries),
            "passing_signals": len(passing),
            "failing_signals": len(failing),
            "evidence_ids": "; ".join(sorted({e["evidence_id"] for e in entries})),
            "signal_descriptions": " | ".join(e["description"] for e in entries),
        })

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    pass_count = sum(1 for r in rows if r["overall_status"] == "PASS")
    fail_count = sum(1 for r in rows if r["overall_status"] == "FAIL")
    print(f"  ✓  {out_path}  ({len(rows)} controls: {pass_count} pass, {fail_count} fail)")


def write_findings_detail(evidence: dict, out_path: Path, run_at: str):
    """
    03_findings_detail.csv
    One row per individual finding.

    This is the remediation worklist. Each row names a specific resource
    (a user UPN, a service principal name, a resource ID) and says what
    is wrong with it and how to fix it.

    Sources:
      1. DETAIL_SIGNALS above  — list-valued signals from each collector
      2. Defender for Cloud    — critical and high alerts and recommendations
      3. Azure Policy          — non-compliant resource details
    """
    fieldnames = [
        "evidence_id",
        "finding_type",
        "severity",
        "resource",
        "detail",
        "remediation",
        "collected_at",
        "azure_sub",
    ]

    rows = []

    # ── Expand list-valued signals ──────────────────────────────────────────
    for signal_key, meta in DETAIL_SIGNALS.items():
        eid = meta["evidence_id"]
        artifact = evidence.get(eid, {})
        if not artifact or artifact.get("status") == "error":
            continue

        collected_at = artifact.get("collected_at", "N/A")
        azure_sub = account_id_from_artifact(artifact)
        signals = (artifact.get("data") or {}).get("compliance_signals", {})
        items = signals.get(signal_key, [])

        for item in items:
            if isinstance(item, dict):
                # stale_credentials is a list of dicts with 'service_principal', etc.
                resource = (
                    item.get("service_principal")
                    or item.get("user")
                    or item.get("resource_id")
                    or str(item)
                )
                detail = "; ".join(
                    f"{k}={v}" for k, v in item.items()
                    if k not in ("service_principal", "user")
                )
            else:
                resource = str(item)
                detail = ""

            rows.append({
                "evidence_id": eid,
                "finding_type": meta["title"],
                "severity": meta["severity"],
                "resource": resource,
                "detail": detail,
                "remediation": meta["remediation"],
                "collected_at": collected_at,
                "azure_sub": azure_sub,
            })

    # ── Defender for Cloud alerts ────────────────────────────────────────────
    defender_artifact = evidence.get("azure_defender_findings", {})
    if defender_artifact and defender_artifact.get("status") != "error":
        defender_data = defender_artifact.get("data") or {}
        collected_at = defender_artifact.get("collected_at", "N/A")
        azure_sub = account_id_from_artifact(defender_artifact)

        for sev_key in ("critical_alerts_sample", "high_alerts_sample"):
            for alert in defender_data.get(sev_key, []):
                rows.append({
                    "evidence_id": "azure_defender_findings",
                    "finding_type": f"Defender for Cloud {alert.get('severity', '')} alert",
                    "severity": alert.get("severity", "UNKNOWN"),
                    "resource": alert.get("resource_id", "N/A"),
                    "detail": alert.get("description", ""),
                    "remediation": (
                        alert.get("remediation")
                        or "See Defender for Cloud portal for remediation guidance."
                    ),
                    "collected_at": collected_at,
                    "azure_sub": azure_sub,
                })

        # Defender recommendations (High and Critical)
        for sev_key in ("critical_recommendations_sample", "high_recommendations_sample"):
            for rec in defender_data.get(sev_key, []):
                rows.append({
                    "evidence_id": "azure_defender_findings",
                    "finding_type": f"Defender recommendation: {rec.get('recommendation_name', 'unknown')}",
                    "severity": rec.get("severity", "UNKNOWN"),
                    "resource": rec.get("resource_id", "N/A"),
                    "detail": rec.get("description", ""),
                    "remediation": (
                        rec.get("remediation")
                        or "See Defender for Cloud Recommendations blade for remediation steps."
                    ),
                    "collected_at": collected_at,
                    "azure_sub": azure_sub,
                })

    # ── Azure Policy non-compliant resources ────────────────────────────────
    policy_artifact = evidence.get("azure_policy_compliance", {})
    if policy_artifact and policy_artifact.get("status") != "error":
        policy_data = policy_artifact.get("data") or {}
        collected_at = policy_artifact.get("collected_at", "N/A")
        azure_sub = account_id_from_artifact(policy_artifact)

        high_value_failure_names = set(
            (policy_data.get("compliance_signals") or {}).get("high_value_failures", [])
        )

        for resource in policy_data.get("non_compliant_resource_sample", []):
            policy_def = resource.get("policy_definition", "")
            is_high = policy_def.lower() in high_value_failure_names

            rows.append({
                "evidence_id": "azure_policy_compliance",
                "finding_type": f"Policy non-compliance: {policy_def}",
                "severity": "HIGH" if is_high else "MEDIUM",
                "resource": resource.get("resource_id", "N/A"),
                "detail": f"assignment={resource.get('policy_assignment')}",
                "remediation": (
                    "Remediate in Azure Portal > Policy > Compliance or "
                    "correct the resource configuration via IaC."
                ),
                "collected_at": collected_at,
                "azure_sub": azure_sub,
            })

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    high = sum(1 for r in rows if r["severity"] in ("CRITICAL", "HIGH"))
    print(f"  ✓  {out_path}  ({len(rows)} findings, {high} high/critical)")


def main():
    parser = argparse.ArgumentParser(description="Generate Azure compliance CSV reports")
    parser.add_argument("--evidence-dir", default="evidence")
    parser.add_argument("--controls", default="controls.yaml")
    parser.add_argument("--output-dir", default="reports")
    args = parser.parse_args()

    evidence_dir = Path(args.evidence_dir)
    controls_path = Path(args.controls)
    output_dir = Path(args.output_dir)
    run_at = datetime.now(timezone.utc).isoformat()

    print(f"\n{'='*56}")
    print(f"  Azure Compliance Report Generator")
    print(f"  run at  : {run_at}")
    print(f"  evidence: {evidence_dir}")
    print(f"  controls: {controls_path}")
    print(f"{'='*56}\n")

    if not evidence_dir.exists():
        print(f"[ERROR] Evidence directory not found: {evidence_dir}")
        print("  Run run_all.py first.")
        raise SystemExit(1)

    if not controls_path.exists():
        print(f"[ERROR] controls.yaml not found: {controls_path}")
        raise SystemExit(1)

    evidence = load_evidence(evidence_dir)
    controls = load_controls(controls_path)

    print(f"  Loaded {len(evidence)} evidence artifact(s)")
    print(f"  Loaded {len(controls)} control mapping(s)\n")

    write_summary(controls, evidence, output_dir / "01_summary.csv", run_at)
    write_control_coverage(controls, evidence, output_dir / "02_control_coverage.csv", run_at)
    write_findings_detail(evidence, output_dir / "03_findings_detail.csv", run_at)

    print(f"\n  Reports written to {output_dir}/")
    print(f"{'='*56}\n")


if __name__ == "__main__":
    main()
