"""
monitor_frameworks.py
=====================
Checks official compliance framework sources for version changes.
When a change is detected, opens a GitHub Issue to prompt human review.

HOW IT WORKS (plain English):
  1. Read framework_versions.yaml to get the current confirmed version
     and detection settings for each framework.
  2. For each framework, check its official source using one of two methods:
       - RSS:  Fetch the framework's news RSS feed and look for keywords
               that suggest a new version was announced.
       - Hash: Download the official page and compute a SHA-256 hash.
               Compare against the stored hash. If they differ, something
               changed on the page.
  3. If a change is detected, open a GitHub Issue with details.
  4. Save a detection results file to evidence/framework_versions/latest.json
     so the weekly run is recorded in git history.

DETECTION METHODS EXPLAINED:
  RSS-based (PCI-DSS, NIST CSF):
    These bodies publish public RSS news feeds. We fetch the feed and search
    recent items for keywords like "v4.1" or "version 2.1". A keyword hit
    does not mean the framework changed -- it means a human should check.
    This avoids false negatives (missing a change) at the cost of occasional
    false positives (news articles that mention version numbers in passing).

  Hash-based (ISO 27001, SOC 2, ISO 42001):
    These bodies do not publish RSS feeds. Instead, we download the official
    catalogue or announcement page and compute a SHA-256 fingerprint of its
    content. If the fingerprint differs from the stored value, something on
    the page changed. Could be a new standard, or could be a page redesign.
    Either way, it warrants a human review.

    IMPORTANT: The first time you run this script on a new environment, it
    will not have any stored hashes. It will store the current hash and mark
    the framework as "baseline established" without raising an alert.

USAGE:
  # Normal run (used by GitHub Actions)
  python monitor_frameworks.py

  # Dry run -- checks everything but does not open GitHub Issues
  python monitor_frameworks.py --dry-run

  # Force update hashes without alerting (use after confirming a page change
  # is cosmetic and not a new framework version)
  python monitor_frameworks.py --update-hashes

ENVIRONMENT VARIABLES REQUIRED (set as GitHub Actions secrets):
  GITHUB_TOKEN  : Personal access token or Actions token with issues:write scope
  GITHUB_REPO   : Repository in owner/repo format, e.g. reeshiri/aws-compliance-as-code

OUTPUT:
  evidence/framework_versions/latest.json  -- detection results this run
  evidence/framework_versions/YYYYMMDD_HHMMSS.json  -- timestamped snapshot
"""

import argparse
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
import yaml


# ── Constants ─────────────────────────────────────────────────────────────────

SCRIPT_DIR   = Path(__file__).parent
VERSIONS_FILE = SCRIPT_DIR / "framework_versions.yaml"
EVIDENCE_DIR  = SCRIPT_DIR / "evidence" / "framework_versions"
HASHES_FILE   = SCRIPT_DIR / "evidence" / "framework_versions" / "stored_hashes.json"

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
GITHUB_REPO  = os.environ.get("GITHUB_REPO", "")
GITHUB_API   = "https://api.github.com"

# How long to wait between HTTP requests (seconds).
# This is polite behaviour -- we are not hammering anyone's servers.
REQUEST_DELAY_SECONDS = 3

# HTTP timeout for all requests
REQUEST_TIMEOUT = 30


# ── Helpers ───────────────────────────────────────────────────────────────────

def log(msg: str) -> None:
    """Print a timestamped log line."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"[{ts}] {msg}")


def load_versions_file() -> dict:
    """Load and parse framework_versions.yaml."""
    if not VERSIONS_FILE.exists():
        log(f"ERROR: {VERSIONS_FILE} not found. Did you commit it to the repo?")
        sys.exit(1)
    with open(VERSIONS_FILE, "r") as f:
        return yaml.safe_load(f)


def load_stored_hashes() -> dict:
    """
    Load previously stored page hashes from disk.
    Returns an empty dict if the file does not exist yet.
    This is normal on the first run.
    """
    if not HASHES_FILE.exists():
        return {}
    with open(HASHES_FILE, "r") as f:
        return json.load(f)


def save_stored_hashes(hashes: dict) -> None:
    """Save the current page hashes to disk."""
    HASHES_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(HASHES_FILE, "w") as f:
        json.dump(hashes, f, indent=2)


def fetch_url(url: str) -> str | None:
    """
    Fetch a URL and return its text content.
    Returns None if the request fails.
    We set a user-agent so servers know we are a compliance monitoring script.
    """
    headers = {
        "User-Agent": "compliance-framework-monitor/1.0 (GRC portfolio automation)"
    }
    try:
        resp = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        return resp.text
    except requests.RequestException as e:
        log(f"  WARNING: Could not fetch {url}: {e}")
        return None


def sha256_of_text(text: str) -> str:
    """Compute a SHA-256 hash of a string. Used for hash-based change detection."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ── Detection methods ─────────────────────────────────────────────────────────

def check_rss(framework: dict) -> dict:
    """
    Fetch an RSS feed and look for keyword matches in recent items.

    RSS feeds are XML documents that list recent news articles. Each item
    has a title and description. We search both fields for keywords that
    suggest a new framework version was announced.

    Returns a result dict with:
      - change_detected: bool
      - reason: human-readable explanation
      - matched_keywords: list of keywords that triggered the alert
    """
    url      = framework["source_url"]
    keywords = [kw.lower() for kw in framework.get("rss_keywords", [])]

    log(f"  Fetching RSS feed: {url}")
    content = fetch_url(url)

    if content is None:
        return {
            "change_detected": False,
            "reason": "Could not fetch RSS feed (network error or URL changed)",
            "matched_keywords": [],
            "detection_method": "rss",
            "source_url": url
        }

    content_lower = content.lower()
    matched = [kw for kw in keywords if kw in content_lower]

    # We do NOT alert on every keyword match -- these keywords are expected
    # to appear in normal news items. Instead, we look for keywords that
    # suggest a VERSION CHANGE specifically, e.g. "v4.1" or "version 5".
    #
    # The logic here is intentionally conservative: we flag if ANY new version
    # keyword appears. The GitHub Issue template asks the reviewer to confirm
    # whether it is an actual new release.
    version_change_keywords = [kw for kw in matched if any(
        indicator in kw for indicator in ["v4.1", "v5", "version 5", "version 4.1",
                                          "v2.1", "v3.0", "2025", "2026", "new version",
                                          "updated standard", "revision"]
    )]

    if version_change_keywords:
        return {
            "change_detected": True,
            "reason": f"RSS feed contains possible new version keywords: {version_change_keywords}",
            "matched_keywords": version_change_keywords,
            "detection_method": "rss",
            "source_url": url
        }

    return {
        "change_detected": False,
        "reason": f"RSS feed checked. No new version keywords found. ({len(matched)} general keywords matched, none version-specific)",
        "matched_keywords": matched,
        "detection_method": "rss",
        "source_url": url
    }


def check_hash(framework: dict, stored_hashes: dict, update_hashes: bool) -> dict:
    """
    Fetch a web page and compare its SHA-256 hash against the stored value.

    On the first run, there is no stored hash. We store the current hash
    and return change_detected=False (this is the "baseline" run).

    On subsequent runs, we compare against the stored hash. If they differ,
    something on the page changed and a human should investigate.

    The update_hashes flag lets you force-update all hashes without alerting.
    Use this when a page had a cosmetic change (e.g. website redesign) that
    is not related to a new framework version.
    """
    fw_id = framework["id"]
    url   = framework["source_url"]

    log(f"  Fetching page for hash check: {url}")
    content = fetch_url(url)

    if content is None:
        return {
            "change_detected": False,
            "reason": "Could not fetch page (network error or URL changed)",
            "detection_method": "hash",
            "source_url": url,
            "current_hash": None,
            "stored_hash": stored_hashes.get(fw_id)
        }

    current_hash = sha256_of_text(content)
    stored_hash  = stored_hashes.get(fw_id)

    # Update the hash in memory (will be persisted by the caller)
    if update_hashes or stored_hash is None:
        stored_hashes[fw_id] = current_hash

    if stored_hash is None:
        return {
            "change_detected": False,
            "reason": "First run: baseline hash stored. No comparison possible yet.",
            "detection_method": "hash",
            "source_url": url,
            "current_hash": current_hash,
            "stored_hash": None
        }

    if update_hashes:
        return {
            "change_detected": False,
            "reason": "Hash updated manually (--update-hashes flag used). No alert raised.",
            "detection_method": "hash",
            "source_url": url,
            "current_hash": current_hash,
            "stored_hash": current_hash
        }

    if current_hash != stored_hash:
        return {
            "change_detected": True,
            "reason": "Page content has changed since last check. This may indicate a new version, a page update, or a website redesign. Human review required.",
            "detection_method": "hash",
            "source_url": url,
            "current_hash": current_hash,
            "stored_hash": stored_hash
        }

    return {
        "change_detected": False,
        "reason": "Page hash matches stored value. No change detected.",
        "detection_method": "hash",
        "source_url": url,
        "current_hash": current_hash,
        "stored_hash": stored_hash
    }


# ── GitHub Issue creation ─────────────────────────────────────────────────────

def open_github_issue(framework: dict, detection_result: dict, dry_run: bool) -> bool:
    """
    Open a GitHub Issue to flag a detected framework change for human review.

    The issue title is formatted consistently so you can filter by label.
    The body includes:
      - What was detected and why
      - The confirmed version vs what was found
      - A checklist of review steps (what to do when you see this issue)
      - Links to the official source

    Returns True if the issue was opened successfully (or would have been in dry_run mode).
    """
    fw_name          = framework["display_name"]
    confirmed_version = framework["confirmed_version"]
    source_url       = framework["source_url"]

    title = f"[Framework Monitor] Possible update detected: {fw_name}"

    body = f"""## Framework Version Change Alert

**Framework:** {fw_name}
**Currently mapped version in controls.yaml:** `{confirmed_version}`
**Confirmed as of:** {framework["last_confirmed_date"]}
**Detection method:** {detection_result["detection_method"]}
**Official source:** {source_url}

---

### What was detected

{detection_result["reason"]}

---

### Review checklist

Please work through these steps before closing this issue:

- [ ] Visit the official source URL above and confirm whether a new version has been published.
- [ ] If a new version IS published:
  - [ ] Download and review the change log or summary of changes.
  - [ ] Identify which control IDs have changed, been added, or been removed.
  - [ ] Update `controls.yaml` to reflect the new control numbering.
  - [ ] Update `framework_versions.yaml` -- set `confirmed_version` and `last_confirmed_date`.
  - [ ] Add a note in `review_notes` describing what changed.
  - [ ] If new controls require new evidence signals, create a GitHub Issue for each collector update needed.
  - [ ] If control IDs changed, check whether any existing signals reference the old IDs.
- [ ] If the change is cosmetic (website redesign, no new version):
  - [ ] Run `python monitor_frameworks.py --update-hashes` to reset the baseline hash.
  - [ ] Add a note in `review_notes` in `framework_versions.yaml` explaining the cosmetic change.
  - [ ] Close this issue with a comment explaining the resolution.

---

### Why this matters

Your `controls.yaml` maps evidence signals to specific control IDs. If a framework updates
its control numbering or adds new requirements, your compliance reports could reference
outdated IDs. Auditors checking your evidence against the published framework would find
a mismatch. This issue is your prompt to check before that happens.

---

*Opened automatically by monitor_frameworks.py*
"""

    labels = ["framework-update", "governance", "human-review-required"]

    if dry_run:
        log(f"  [DRY RUN] Would open GitHub Issue: {title}")
        log(f"  [DRY RUN] Labels: {labels}")
        return True

    if not GITHUB_TOKEN or not GITHUB_REPO:
        log("  WARNING: GITHUB_TOKEN or GITHUB_REPO not set. Skipping issue creation.")
        log(f"  Issue that would have been created: {title}")
        return False

    url = f"{GITHUB_API}/repos/{GITHUB_REPO}/issues"
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }
    payload = {
        "title": title,
        "body": body,
        "labels": labels
    }

    try:
        resp = requests.post(url, headers=headers, json=payload, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        issue_url = resp.json().get("html_url", "unknown")
        log(f"  GitHub Issue opened: {issue_url}")
        return True
    except requests.RequestException as e:
        log(f"  ERROR: Could not open GitHub Issue: {e}")
        return False


# ── Evidence saving ───────────────────────────────────────────────────────────

def save_evidence(results: list, run_timestamp: str) -> None:
    """
    Save detection results to the evidence folder.

    This follows the same envelope pattern used by all other collectors
    in the portfolio: evidence_id, collected_at, status, data.

    The file is committed to git by the GitHub Actions workflow, creating
    a timestamped audit trail of every framework check run.
    """
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

    any_change = any(r["change_detected"] for r in results)
    overall_status = "ALERT" if any_change else "PASS"

    artifact = {
        "evidence_id": "framework_versions",
        "collected_at": run_timestamp,
        "status": overall_status,
        "total_frameworks_checked": len(results),
        "changes_detected": sum(1 for r in results if r["change_detected"]),
        "data": {
            "results": results
        }
    }

    # latest.json -- always overwritten (quick status check)
    latest_path = EVIDENCE_DIR / "latest.json"
    with open(latest_path, "w") as f:
        json.dump(artifact, f, indent=2)

    # Timestamped snapshot -- never overwritten (audit trail)
    ts_clean = run_timestamp.replace(":", "").replace("-", "").replace("Z", "")
    snapshot_path = EVIDENCE_DIR / f"{ts_clean}.json"
    with open(snapshot_path, "w") as f:
        json.dump(artifact, f, indent=2)

    log(f"Evidence saved to {latest_path}")
    log(f"Snapshot saved to {snapshot_path}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Monitor compliance framework sources for version changes.")
    parser.add_argument("--dry-run",       action="store_true", help="Check everything but do not open GitHub Issues.")
    parser.add_argument("--update-hashes", action="store_true", help="Update all stored hashes without alerting (use after cosmetic page changes).")
    args = parser.parse_args()

    run_timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    log("=" * 60)
    log("Framework Version Monitor")
    log(f"Run started: {run_timestamp}")
    if args.dry_run:
        log("Mode: DRY RUN (no GitHub Issues will be opened)")
    if args.update_hashes:
        log("Mode: UPDATE HASHES (hashes reset, no alerts raised)")
    log("=" * 60)

    config       = load_versions_file()
    frameworks   = config.get("frameworks", [])
    stored_hashes = load_stored_hashes()
    results      = []
    alerts_opened = 0

    for fw in frameworks:
        if not fw.get("alert_on_change", True):
            log(f"\nSkipping {fw['display_name']} (alert_on_change: false)")
            continue

        log(f"\nChecking: {fw['display_name']} (confirmed: {fw['confirmed_version']})")
        method = fw.get("detection_method", "hash")

        if method == "rss":
            detection = check_rss(fw)
        elif method == "hash":
            detection = check_hash(fw, stored_hashes, args.update_hashes)
        else:
            log(f"  WARNING: Unknown detection method '{method}'. Skipping.")
            continue

        log(f"  Result: change_detected={detection['change_detected']}")
        log(f"  Reason: {detection['reason']}")

        result_entry = {
            "framework_id":       fw["id"],
            "framework_name":     fw["display_name"],
            "confirmed_version":  fw["confirmed_version"],
            "change_detected":    detection["change_detected"],
            "reason":             detection["reason"],
            "detection_method":   detection["detection_method"],
            "source_url":         detection["source_url"],
            "checked_at":         run_timestamp
        }
        results.append(result_entry)

        if detection["change_detected"]:
            log(f"  ALERT: Possible change detected for {fw['display_name']}. Opening GitHub Issue...")
            success = open_github_issue(fw, detection, dry_run=args.dry_run)
            if success:
                alerts_opened += 1

        # Be polite -- wait between requests
        time.sleep(REQUEST_DELAY_SECONDS)

    # Save updated hashes (only relevant for hash-based detection)
    save_stored_hashes(stored_hashes)

    # Save evidence artifact
    save_evidence(results, run_timestamp)

    log("\n" + "=" * 60)
    log(f"Frameworks checked: {len(results)}")
    log(f"Changes detected:   {sum(1 for r in results if r['change_detected'])}")
    log(f"Alerts opened:      {alerts_opened}")
    log("=" * 60)

    # Exit code 1 if any changes detected (makes GitHub Actions flag the run)
    if any(r["change_detected"] for r in results):
        log("Exiting with code 1 (changes detected -- see GitHub Issues for review checklist)")
        sys.exit(1)
    else:
        log("Exiting with code 0 (no changes detected)")
        sys.exit(0)


if __name__ == "__main__":
    main()
