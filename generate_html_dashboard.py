"""
generate_html_dashboard.py — builds a standalone compliance risk dashboard HTML
from the three CSV reports produced by generate_report.py.

Reads:
  reports/01_summary.csv          — signal pass/fail per framework
  reports/02_control_coverage.csv — control-level status
  reports/03_findings_detail.csv  — individual findings

Writes:
  reports/dashboard.html          — self-contained, no server required

Usage:
    python generate_html_dashboard.py
    python generate_html_dashboard.py --reports-dir reports --output reports/dashboard.html
    python generate_html_dashboard.py --account-id 123456789012 --region us-east-1

How it works:
  1. Reads the three CSVs and builds JSON data structures identical to what
     the dashboard template expects.
  2. Replaces the DATA block in the HTML template with live values.
  3. Writes the final file — a single HTML you can open in any browser,
     email to a stakeholder, or host on GitHub Pages with zero dependencies.

Adding this to your GitHub Actions workflow (after generate_report.py):
    - name: Generate HTML dashboard
      run: python generate_html_dashboard.py --reports-dir reports

Then add reports/dashboard.html to your git add step.
"""

import argparse
import csv
import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path


# ── Helpers ────────────────────────────────────────────────────────────────

def read_csv(path: Path) -> list[dict]:
    """Read a CSV file and return a list of row dicts. Returns [] if missing."""
    if not path.exists():
        print(f"  [WARN] {path} not found — skipping")
        return []
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def pct_class(pct: int) -> str:
    """Return a CSS class name based on pass percentage."""
    if pct >= 80:
        return "pass"
    if pct >= 60:
        return "warn"
    return "fail"


def pct_color(pct: int) -> str:
    """Return a hex color based on pass percentage."""
    if pct >= 80:
        return "#1D9E75"
    if pct >= 60:
        return "#BA7517"
    return "#D85A30"


# ── Data builders ──────────────────────────────────────────────────────────

def build_run_date() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def build_frameworks(summary_rows: list[dict]) -> list[dict]:
    """
    Derive per-framework pass rates from 01_summary.csv.

    01_summary.csv has one row per signal. The framework columns
    (PCI-DSS, SOC 2, ISO 27001, ISO 42001) contain semicolon-separated
    control IDs when the signal covers that framework, or an empty string.

    We count: for each framework, how many signals that cover it are PASS
    vs FAIL. That gives us a signal-level pass rate to show on the scorecards.
    """
    fw_labels = {
        "PCI-DSS":   "PCI-DSS v4",
        "SOC 2":     "SOC 2 Type II",
        "ISO 27001": "ISO 27001:2022",
        "ISO 42001": "ISO 42001:2023",
    }
    fw_order = ["PCI-DSS", "SOC 2", "ISO 27001", "ISO 42001"]

    counts = {fw: {"pass": 0, "total": 0} for fw in fw_order}

    for row in summary_rows:
        status = row.get("status", "")
        for fw in fw_order:
            if row.get(fw, "").strip():          # signal covers this framework
                counts[fw]["total"] += 1
                if status == "PASS":
                    counts[fw]["pass"] += 1

    result = []
    for fw in fw_order:
        c = counts[fw]
        total = c["total"] or 1                 # avoid div-by-zero
        result.append({
            "id":         fw,
            "label":      fw_labels[fw],
            "pass":       c["pass"],
            "total":      c["total"],
            "trend":      "flat",               # static for now; extend with
            "trendLabel": "this run",           # historical data when available
        })
    return result


def build_signals(summary_rows: list[dict]) -> list[dict]:
    """
    Build the signal health grid from 01_summary.csv.

    Columns used: evidence_id, signal, description, status
    """
    # Map evidence_id to a short human label
    src_labels = {
        "aws_cloudtrail_logs":      "cloudtrail",
        "aws_config_rules":         "config",
        "aws_iam_posture":          "iam",
        "aws_securityhub_findings": "securityhub",
    }

    signals = []
    for row in summary_rows:
        raw_status = row.get("status", "ERROR").upper()
        # Normalise to pass / fail / error for the dot colours
        if raw_status == "PASS":
            status = "pass"
        elif raw_status == "FAIL":
            status = "fail"
        else:
            status = "error"

        signals.append({
            "id":     row.get("signal", ""),
            "src":    src_labels.get(row.get("evidence_id", ""), row.get("evidence_id", "")),
            "label":  row.get("description", row.get("signal", "")),
            "status": status,
        })
    return signals


def build_controls(coverage_rows: list[dict]) -> list[dict]:
    """
    Build the control coverage table from 02_control_coverage.csv.

    Columns used: framework, control_id, overall_status,
                  evidence_ids, evidence_count, signal_descriptions
    """
    controls = []
    for row in coverage_rows:
        # evidence_ids is semicolon-separated in the CSV
        raw_sources = row.get("evidence_ids", "")
        sources = [s.strip() for s in raw_sources.split(";") if s.strip()]

        try:
            n_signals = int(row.get("evidence_count", 1))
        except ValueError:
            n_signals = 1

        status = row.get("overall_status", "UNKNOWN").upper()

        controls.append({
            "fw":      row.get("framework", ""),
            "id":      row.get("control_id", ""),
            "status":  status if status in ("PASS", "FAIL") else "FAIL",
            "sources": sources,
            "signals": n_signals,
            "desc":    _first_description(row.get("signal_descriptions", "")),
        })
    return controls


def _first_description(raw: str) -> str:
    """Return the first signal description from a pipe-separated string."""
    parts = [p.strip() for p in raw.split("|") if p.strip()]
    if not parts:
        return ""
    desc = parts[0]
    # Truncate long descriptions for the table
    return desc[:60] + ("..." if len(desc) > 60 else "")


def build_findings(findings_rows: list[dict]) -> list[dict]:
    """
    Build the active findings worklist from 03_findings_detail.csv.

    Columns used: evidence_id, finding_type, severity, resource,
                  detail, remediation, collected_at, aws_account
    """
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    css_map   = {"CRITICAL": "high", "HIGH": "high", "MEDIUM": "med", "LOW": "low"}

    findings = []
    for row in findings_rows:
        sev = row.get("severity", "MEDIUM").upper()
        findings.append({
            "sev":      sev,
            "cls":      css_map.get(sev, "med"),
            "type":     row.get("finding_type", ""),
            "resource": row.get("resource", ""),
            "detail":   row.get("detail", ""),
            "src":      row.get("evidence_id", ""),
            "rem":      row.get("remediation", ""),
        })

    # Sort: CRITICAL first, then HIGH, then MEDIUM, then LOW
    findings.sort(key=lambda f: sev_order.get(f["sev"], 99))
    return findings


def build_sources(summary_rows: list[dict]) -> list[dict]:
    """
    Derive per-source pass rates from 01_summary.csv for the
    evidence source health panel.
    """
    label_map = {
        "aws_cloudtrail_logs":      "CloudTrail",
        "aws_config_rules":         "Config",
        "aws_iam_posture":          "IAM",
        "aws_securityhub_findings": "Security Hub",
    }
    order = list(label_map.keys())

    counts = {eid: {"pass": 0, "total": 0} for eid in order}

    for row in summary_rows:
        eid = row.get("evidence_id", "")
        if eid not in counts:
            counts[eid] = {"pass": 0, "total": 0}
        counts[eid]["total"] += 1
        if row.get("status", "") == "PASS":
            counts[eid]["pass"] += 1

    result = []
    for eid in order:
        if counts[eid]["total"] == 0:
            continue
        result.append({
            "id":    eid,
            "label": label_map.get(eid, eid),
            "pass":  counts[eid]["pass"],
            "total": counts[eid]["total"],
        })
    return result


def extract_meta(summary_rows: list[dict]) -> dict:
    """Pull aws_account and region from the first summary row that has them."""
    for row in summary_rows:
        account = row.get("aws_account", "")
        if account and account != "N/A":
            return {"account": account, "region": "us-east-1"}  # region not in CSV
    return {"account": "unknown", "region": "us-east-1"}


# ── HTML template ──────────────────────────────────────────────────────────
# This is exactly the dashboard we built, with one change:
# the DATA block is a Python format string so we can inject values.

DASHBOARD_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Compliance Risk Dashboard</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=Sora:wght@400;500;600&display=swap" rel="stylesheet">
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  :root {
    --ff: 'Sora', system-ui, sans-serif;
    --mono: 'IBM Plex Mono', 'Courier New', monospace;
    --bg: #F8F7F4; --surface: #FFFFFF; --surface2: #F2F0EC;
    --border: rgba(0,0,0,0.10); --border2: rgba(0,0,0,0.18);
    --text: #1A1918; --text2: #5F5E5A; --text3: #888780;
    --pass: #1D9E75; --pass-bg: #E1F5EE; --pass-text: #085041;
    --fail: #D85A30; --fail-bg: #FAECE7; --fail-text: #993C1D;
    --warn: #BA7517; --warn-bg: #FAEEDA; --warn-text: #854F0B;
    --info: #185FA5; --info-bg: #E6F1FB; --info-text: #0C447C;
    --radius: 12px; --radius-sm: 8px;
    --shadow: 0 1px 3px rgba(0,0,0,0.07), 0 0 0 0.5px rgba(0,0,0,0.08);
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #1C1B19; --surface: #242320; --surface2: #2C2C2A;
      --border: rgba(255,255,255,0.10); --border2: rgba(255,255,255,0.18);
      --text: #E8E6DF; --text2: #A8A69E; --text3: #6B6A63;
      --pass-bg: #04342C; --pass-text: #9FE1CB;
      --fail-bg: #4A1B0C; --fail-text: #F0997B;
      --warn-bg: #412402; --warn-text: #FAC775;
      --info-bg: #042C53; --info-text: #85B7EB;
      --shadow: 0 1px 3px rgba(0,0,0,0.4), 0 0 0 0.5px rgba(255,255,255,0.07);
    }
  }
  body { font-family: var(--ff); background: var(--bg); color: var(--text); min-height: 100vh; }
  .dash { max-width: 1200px; margin: 0 auto; padding: 28px 24px 48px; }
  .header { display: flex; align-items: flex-start; justify-content: space-between; margin-bottom: 28px; gap: 16px; flex-wrap: wrap; }
  .header-left h1 { font-size: 20px; font-weight: 600; letter-spacing: -0.01em; margin-bottom: 4px; }
  .header-left .meta { font-size: 13px; color: var(--text2); display: flex; align-items: center; gap: 8px; }
  .meta .dot { width: 6px; height: 6px; border-radius: 50%; background: var(--pass); display: inline-block; }
  .run-badge { font-family: var(--mono); font-size: 11.5px; color: var(--text2); background: var(--surface); border: 0.5px solid var(--border); padding: 6px 14px; border-radius: 20px; }
  .section-label { font-size: 10.5px; font-weight: 600; letter-spacing: 0.09em; text-transform: uppercase; color: var(--text3); margin-bottom: 12px; }
  .fw-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; margin-bottom: 24px; }
  @media (max-width: 720px) { .fw-grid { grid-template-columns: repeat(2, 1fr); } }
  .fw-card { background: var(--surface); border: 0.5px solid var(--border); border-radius: var(--radius); padding: 16px; cursor: pointer; transition: border-color 0.15s, box-shadow 0.15s; }
  .fw-card:hover { border-color: var(--border2); box-shadow: var(--shadow); }
  .fw-card.active { border: 1.5px solid var(--info); }
  .fw-label { font-size: 10.5px; font-weight: 600; letter-spacing: 0.06em; text-transform: uppercase; color: var(--text3); margin-bottom: 10px; }
  .fw-pct { font-family: var(--mono); font-size: 32px; font-weight: 500; line-height: 1; margin-bottom: 4px; }
  .fw-pct.pass { color: var(--pass); } .fw-pct.warn { color: var(--warn); } .fw-pct.fail { color: var(--fail); }
  .fw-sub { font-size: 12px; color: var(--text2); margin-bottom: 10px; }
  .fw-bar-bg { height: 4px; background: var(--surface2); border-radius: 2px; margin-bottom: 8px; overflow: hidden; }
  .fw-bar { height: 4px; border-radius: 2px; transition: width 0.8s cubic-bezier(.4,0,.2,1); }
  .trend-chip { font-size: 10.5px; font-weight: 500; padding: 2px 8px; border-radius: 4px; display: inline-block; }
  .trend-chip.up { background: var(--pass-bg); color: var(--pass-text); }
  .trend-chip.down { background: var(--fail-bg); color: var(--fail-text); }
  .trend-chip.flat { background: var(--surface2); color: var(--text3); }
  .two-col { display: grid; grid-template-columns: 1.5fr 1fr; gap: 12px; margin-bottom: 24px; }
  @media (max-width: 820px) { .two-col { grid-template-columns: 1fr; } }
  .panel { background: var(--surface); border: 0.5px solid var(--border); border-radius: var(--radius); padding: 16px; }
  .signal-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 6px; }
  .sig { display: flex; align-items: flex-start; gap: 8px; padding: 8px 10px; border-radius: var(--radius-sm); border: 0.5px solid var(--border); cursor: default; }
  .sig-dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; margin-top: 4px; }
  .sig-dot.pass { background: var(--pass); } .sig-dot.fail { background: var(--fail); } .sig-dot.error { background: var(--warn); }
  .sig-label { font-size: 12px; font-weight: 500; color: var(--text); line-height: 1.35; display: block; }
  .sig-src { font-size: 10.5px; color: var(--text3); display: block; margin-top: 1px; }
  .sev-list { display: flex; flex-direction: column; gap: 10px; }
  .sev-row { display: flex; align-items: center; gap: 10px; }
  .sev-tag { font-family: var(--mono); font-size: 10px; font-weight: 500; width: 68px; flex-shrink: 0; padding: 3px 0; border-radius: 4px; text-align: center; }
  .sev-tag.crit { background: var(--fail-bg); color: var(--fail-text); }
  .sev-tag.high { background: var(--fail-bg); color: var(--fail-text); opacity: 0.8; }
  .sev-tag.med  { background: var(--warn-bg); color: var(--warn-text); }
  .sev-bar-wrap { flex: 1; background: var(--surface2); border-radius: 2px; height: 6px; overflow: hidden; }
  .sev-bar { height: 6px; border-radius: 2px; transition: width 0.8s 0.3s cubic-bezier(.4,0,.2,1); }
  .sev-count { font-family: var(--mono); font-size: 13px; font-weight: 500; min-width: 28px; text-align: right; color: var(--text); }
  .divider { border: none; border-top: 0.5px solid var(--border); margin: 14px 0; }
  .source-row { display: flex; align-items: center; gap: 10px; margin-bottom: 6px; }
  .source-label { font-size: 12px; color: var(--text2); width: 100px; flex-shrink: 0; }
  .source-bar-wrap { flex: 1; background: var(--surface2); border-radius: 2px; height: 4px; overflow: hidden; }
  .source-bar { height: 4px; border-radius: 2px; transition: width 0.8s 0.4s; }
  .source-count { font-family: var(--mono); font-size: 11px; color: var(--text3); min-width: 36px; text-align: right; }
  .coverage-wrap { margin-bottom: 24px; }
  .filter-row { display: flex; gap: 6px; margin-bottom: 12px; flex-wrap: wrap; }
  .pill { font-size: 12px; padding: 5px 14px; border-radius: 20px; border: 0.5px solid var(--border); cursor: pointer; background: var(--surface); color: var(--text2); transition: all 0.15s; user-select: none; }
  .pill:hover { border-color: var(--border2); color: var(--text); }
  .pill.active { background: var(--info-bg); color: var(--info-text); border-color: var(--info); }
  .table-wrap { background: var(--surface); border: 0.5px solid var(--border); border-radius: var(--radius); overflow: hidden; overflow-x: auto; }
  .cov-table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
  .cov-table th { font-size: 10.5px; font-weight: 600; letter-spacing: 0.06em; text-transform: uppercase; color: var(--text3); text-align: left; padding: 10px 14px; border-bottom: 0.5px solid var(--border); white-space: nowrap; }
  .cov-table td { padding: 10px 14px; border-bottom: 0.5px solid var(--border); vertical-align: middle; }
  .cov-table tr:last-child td { border-bottom: none; }
  .cov-table tbody tr:hover td { background: var(--surface2); cursor: pointer; }
  .status-badge { font-family: var(--mono); font-size: 10.5px; font-weight: 500; padding: 3px 10px; border-radius: 4px; display: inline-block; white-space: nowrap; }
  .status-badge.pass { background: var(--pass-bg); color: var(--pass-text); }
  .status-badge.fail { background: var(--fail-bg); color: var(--fail-text); }
  .ctrl-id { font-family: var(--mono); font-size: 12px; font-weight: 500; }
  .src-chip { display: inline-block; background: var(--surface2); border-radius: 3px; padding: 1px 6px; margin: 2px 2px 2px 0; font-size: 10.5px; font-family: var(--mono); color: var(--text2); }
  .fw-label-sm { font-size: 11.5px; color: var(--text2); }
  .findings-section { margin-bottom: 24px; }
  .findings-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 8px; }
  .finding-card { padding: 12px 14px; border-left: 3px solid; border-radius: 0 var(--radius-sm) var(--radius-sm) 0; background: var(--surface); border-top: 0.5px solid var(--border); border-right: 0.5px solid var(--border); border-bottom: 0.5px solid var(--border); }
  .finding-card.high { border-left-color: var(--fail); }
  .finding-card.med  { border-left-color: var(--warn); }
  .finding-card.low  { border-left-color: var(--info); }
  .fc-top { display: flex; align-items: center; gap: 8px; margin-bottom: 4px; }
  .fc-sev { font-family: var(--mono); font-size: 10px; font-weight: 600; letter-spacing: 0.04em; }
  .finding-card.high .fc-sev { color: var(--fail); }
  .finding-card.med  .fc-sev { color: var(--warn); }
  .finding-card.low  .fc-sev { color: var(--info); }
  .fc-title { font-size: 12.5px; font-weight: 500; color: var(--text); }
  .fc-res { font-family: var(--mono); font-size: 11px; color: var(--text3); margin: 3px 0 2px; }
  .fc-detail { font-size: 11.5px; color: var(--text2); line-height: 1.4; }
  .fc-rem { margin-top: 6px; font-size: 11px; color: var(--text3); }
  .footer { border-top: 0.5px solid var(--border); padding-top: 20px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px; }
  .footer-note { font-size: 11.5px; color: var(--text3); line-height: 1.5; }
  .footer-btns { display: flex; gap: 8px; }
  .btn { font-family: var(--ff); font-size: 12.5px; padding: 8px 18px; border-radius: var(--radius-sm); border: 0.5px solid var(--border2); background: var(--surface); color: var(--text); cursor: pointer; transition: background 0.15s; }
  .btn:hover { background: var(--surface2); }
  .empty-state { text-align: center; padding: 32px 16px; color: var(--text3); font-size: 13px; }
</style>
</head>
<body>
<div class="dash">

  <div class="header">
    <div class="header-left">
      <h1>Compliance risk dashboard</h1>
      <div class="meta">
        <span class="dot"></span>
        <span id="meta-line">Loading...</span>
      </div>
    </div>
    <div class="run-badge" id="run-badge">Loading...</div>
  </div>

  <div class="section-label">Framework pass rate</div>
  <div class="fw-grid" id="fw-grid"></div>

  <div class="two-col">
    <div class="panel">
      <div class="section-label">Signal health</div>
      <div class="signal-grid" id="signal-grid"></div>
    </div>
    <div class="panel">
      <div class="section-label">Findings by severity</div>
      <div class="sev-list" id="sev-list"></div>
      <hr class="divider">
      <div class="section-label">Evidence source health</div>
      <div id="source-list"></div>
    </div>
  </div>

  <div class="coverage-wrap">
    <div class="section-label">Control coverage</div>
    <div class="filter-row" id="filter-row">
      <span class="pill active" data-fw="all">All frameworks</span>
      <span class="pill" data-fw="PCI-DSS">PCI-DSS</span>
      <span class="pill" data-fw="SOC 2">SOC 2</span>
      <span class="pill" data-fw="ISO 27001">ISO 27001</span>
      <span class="pill" data-fw="ISO 42001">ISO 42001</span>
      <span class="pill" data-fw="FAIL">Gaps only</span>
    </div>
    <div class="table-wrap">
      <table class="cov-table">
        <thead>
          <tr>
            <th>Framework</th><th>Control ID</th><th>Status</th>
            <th>Evidence sources</th><th>Signals</th><th>Description</th>
          </tr>
        </thead>
        <tbody id="cov-body"></tbody>
      </table>
    </div>
  </div>

  <div class="findings-section">
    <div class="section-label">Active findings — remediation worklist</div>
    <div class="findings-grid" id="findings-grid"></div>
  </div>

  <div class="footer">
    <div class="footer-note" id="footer-note">Loading...</div>
    <div class="footer-btns">
      <button class="btn" onclick="window.print()">Export PDF</button>
    </div>
  </div>
</div>

<script>
/* ── INJECTED DATA (replaced on each run by generate_html_dashboard.py) ── */
const DASHBOARD_DATA = __DASHBOARD_DATA__;
/* ── END INJECTED DATA ── */

const { runDate, account, region, frameworks, signals, controls, findings, sources } = DASHBOARD_DATA;

let currentFilter = 'all';

function pctClass(p) { return p >= 80 ? 'pass' : p >= 60 ? 'warn' : 'fail'; }
function pctColor(p) { return p >= 80 ? '#1D9E75' : p >= 60 ? '#BA7517' : '#D85A30'; }

function renderHeader() {
  document.getElementById('run-badge').textContent = 'Last run: ' + runDate;
  document.getElementById('meta-line').textContent =
    'AWS ' + region + '  \u00b7  Account ' + account +
    '  \u00b7  PCI-DSS \u00b7 SOC\u00a02 \u00b7 ISO\u00a027001 \u00b7 ISO\u00a042001';
  document.getElementById('footer-note').innerHTML =
    'Evidence auto-committed to git on each run &nbsp;\u00b7&nbsp; ' +
    'Collectors: CloudTrail \u00b7 Config \u00b7 IAM \u00b7 Security Hub<br>' +
    'Generated by compliance-as-code automation \u00b7 NIST CSF 2.0 crosswalk available';
}

function renderFrameworks() {
  const grid = document.getElementById('fw-grid');
  grid.innerHTML = frameworks.map((fw, i) => {
    const pct = fw.total > 0 ? Math.round(fw.pass / fw.total * 100) : 0;
    const cls = pctClass(pct);
    return `<div class="fw-card${i===0?' active':''}" data-fw="${fw.id}" onclick="clickFwCard(this)">
      <div class="fw-label">${fw.label}</div>
      <div class="fw-pct ${cls}">${pct}%</div>
      <div class="fw-sub">${fw.pass} of ${fw.total} signals passing</div>
      <div class="fw-bar-bg"><div class="fw-bar" id="fwbar-${i}" style="width:0%;background:${pctColor(pct)}"></div></div>
      <div style="margin-top:6px"><span class="trend-chip ${fw.trend}">${fw.trendLabel}</span></div>
    </div>`;
  }).join('');
  setTimeout(() => {
    frameworks.forEach((fw, i) => {
      const pct = fw.total > 0 ? Math.round(fw.pass / fw.total * 100) : 0;
      const bar = document.getElementById('fwbar-' + i);
      if (bar) bar.style.width = pct + '%';
    });
  }, 80);
}

function clickFwCard(el) {
  document.querySelectorAll('.fw-card').forEach(c => c.classList.remove('active'));
  el.classList.add('active');
  setFilter(el.getAttribute('data-fw'), null, true);
  document.querySelector('.coverage-wrap').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function renderSignals() {
  document.getElementById('signal-grid').innerHTML = signals.map(s =>
    `<div class="sig">
      <span class="sig-dot ${s.status}"></span>
      <span>
        <span class="sig-label">${s.label}</span>
        <span class="sig-src">${s.src}</span>
      </span>
    </div>`
  ).join('');
}

function renderSeverity() {
  const counts = { crit: 0, high: 0, med: 0 };
  findings.forEach(f => {
    if (f.sev === 'CRITICAL') counts.crit++;
    else if (f.sev === 'HIGH') counts.high++;
    else counts.med++;
  });
  const max = Math.max(counts.crit, counts.high, counts.med, 1);
  document.getElementById('sev-list').innerHTML = [
    { key:'crit', label:'CRITICAL', color:'#D85A30', count: counts.crit },
    { key:'high', label:'HIGH',     color:'#C04828', count: counts.high },
    { key:'med',  label:'MEDIUM',   color:'#BA7517', count: counts.med  },
  ].map(r =>
    `<div class="sev-row">
      <span class="sev-tag ${r.key}">${r.label}</span>
      <div class="sev-bar-wrap">
        <div class="sev-bar" id="bar-${r.key}" style="width:0%;background:${r.color}"></div>
      </div>
      <span class="sev-count">${r.count}</span>
    </div>`
  ).join('');
  setTimeout(() => {
    ['crit','high','med'].forEach(k => {
      const bar = document.getElementById('bar-' + k);
      if (bar) bar.style.width = Math.round(counts[k] / max * 100) + '%';
    });
  }, 120);
}

function renderSources() {
  document.getElementById('source-list').innerHTML = sources.map(s => {
    const pct = s.total > 0 ? Math.round(s.pass / s.total * 100) : 0;
    return `<div class="source-row">
      <span class="source-label">${s.label}</span>
      <div class="source-bar-wrap">
        <div class="source-bar" style="width:${pct}%;background:${pctColor(pct)}"></div>
      </div>
      <span class="source-count">${s.pass}/${s.total}</span>
    </div>`;
  }).join('');
}

function renderCoverage() {
  const body = document.getElementById('cov-body');
  let rows = controls;
  if (currentFilter !== 'all' && currentFilter !== 'FAIL') rows = rows.filter(r => r.fw === currentFilter);
  if (currentFilter === 'FAIL') rows = rows.filter(r => r.status === 'FAIL');
  if (rows.length === 0) {
    body.innerHTML = '<tr><td colspan="6"><div class="empty-state">No controls match the current filter.</div></td></tr>';
    return;
  }
  body.innerHTML = rows.map(r => {
    const chips = r.sources.map(s => `<span class="src-chip">${s.replace('aws_','').replace(/_/g,' ')}</span>`).join('');
    return `<tr>
      <td class="fw-label-sm">${r.fw}</td>
      <td><span class="ctrl-id">${r.id}</span></td>
      <td><span class="status-badge ${r.status.toLowerCase()}">${r.status}</span></td>
      <td>${chips}</td>
      <td style="font-family:var(--mono);font-size:12px;color:var(--text2)">${r.signals}</td>
      <td style="font-size:12px;color:var(--text2)">${r.desc}</td>
    </tr>`;
  }).join('');
}

function setFilter(fw, el, fromCard) {
  currentFilter = fw;
  document.querySelectorAll('.filter-row .pill').forEach(p => p.classList.remove('active'));
  if (el) {
    el.classList.add('active');
  } else {
    const match = document.querySelector(`.filter-row .pill[data-fw="${fw}"]`);
    if (match) match.classList.add('active');
    else document.querySelector('.filter-row .pill[data-fw="all"]').classList.add('active');
  }
  renderCoverage();
}

function renderFindings() {
  const grid = document.getElementById('findings-grid');
  if (findings.length === 0) {
    grid.innerHTML = '<div class="empty-state">No active findings. All controls passing.</div>';
    return;
  }
  grid.innerHTML = findings.map(f =>
    `<div class="finding-card ${f.cls}">
      <div class="fc-top">
        <span class="fc-sev">${f.sev}</span>
        <span class="fc-title">${f.type}</span>
      </div>
      <div class="fc-res">${f.resource}</div>
      <div class="fc-detail">${f.detail}</div>
      <div class="fc-rem">Remediation: ${f.rem}</div>
    </div>`
  ).join('');
}

document.getElementById('filter-row').addEventListener('click', e => {
  const pill = e.target.closest('.pill');
  if (pill) setFilter(pill.getAttribute('data-fw'), pill);
});

renderHeader();
renderFrameworks();
renderSignals();
renderSeverity();
renderSources();
renderCoverage();
renderFindings();
</script>
</body>
</html>
"""


# ── Main ───────────────────────────────────────────────────────────────────

def build_dashboard_data(reports_dir: Path, account_id: str, region: str) -> dict:
    """Read all three CSVs and return the complete data dict the dashboard needs."""
    summary_rows  = read_csv(reports_dir / "01_summary.csv")
    coverage_rows = read_csv(reports_dir / "02_control_coverage.csv")
    findings_rows = read_csv(reports_dir / "03_findings_detail.csv")

    meta = extract_meta(summary_rows)

    return {
        "runDate":    build_run_date(),
        "account":    account_id or meta["account"],
        "region":     region or meta["region"],
        "frameworks": build_frameworks(summary_rows),
        "signals":    build_signals(summary_rows),
        "controls":   build_controls(coverage_rows),
        "findings":   build_findings(findings_rows),
        "sources":    build_sources(summary_rows),
    }


def generate(reports_dir: Path, output_path: Path, account_id: str, region: str):
    print(f"\n{'='*56}")
    print(f"  Compliance HTML Dashboard Generator")
    print(f"  reports : {reports_dir}")
    print(f"  output  : {output_path}")
    print(f"{'='*56}\n")

    data = build_dashboard_data(reports_dir, account_id, region)

    # Pretty-print the JSON so it is readable if someone inspects the HTML source
    data_json = json.dumps(data, indent=2, ensure_ascii=False)

    # Inject data into the template
    html = DASHBOARD_TEMPLATE.replace("__DASHBOARD_DATA__", data_json)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")

    n_signals  = len(data["signals"])
    n_controls = len(data["controls"])
    n_findings = len(data["findings"])
    n_fail     = sum(1 for c in data["controls"] if c["status"] == "FAIL")

    print(f"  Signals  : {n_signals}")
    print(f"  Controls : {n_controls}  ({n_fail} failing)")
    print(f"  Findings : {n_findings}")
    print(f"\n  Dashboard written to: {output_path}")
    print(f"{'='*56}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Generate a standalone compliance risk dashboard HTML from CSV reports",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python generate_html_dashboard.py
  python generate_html_dashboard.py --reports-dir reports --output reports/dashboard.html
  python generate_html_dashboard.py --account-id 123456789012 --region eu-west-1

GitHub Actions usage (add after generate_report.py step):
  - name: Generate HTML dashboard
    run: python generate_html_dashboard.py --reports-dir reports
        """
    )
    parser.add_argument(
        "--reports-dir", default="reports",
        help="Directory containing the three CSV reports (default: reports)"
    )
    parser.add_argument(
        "--output", default=None,
        help="Output path for the HTML file (default: <reports-dir>/dashboard.html)"
    )
    parser.add_argument(
        "--account-id", default="",
        help="AWS account ID to display in the header (optional; auto-detected from CSV if omitted)"
    )
    parser.add_argument(
        "--region", default="us-east-1",
        help="AWS region to display in the header (default: us-east-1)"
    )
    args = parser.parse_args()

    reports_dir = Path(args.reports_dir)
    output_path = Path(args.output) if args.output else reports_dir / "dashboard.html"

    generate(reports_dir, output_path, args.account_id, args.region)


if __name__ == "__main__":
    main()
