"""
base.py — shared collector base class for Azure compliance collectors

All Azure collectors inherit from this to ensure a consistent output format
that matches the evidence artifact schema used by generate_report.py.

Output format (every collector produces this envelope):
{
    "evidence_id":   str   — unique ID matching controls.yaml (e.g. "azure_activity_logs")
    "collector":     str   — class name of the collector
    "collected_at":  str   — ISO 8601 UTC timestamp of when collection ran
    "azure_tenant":  str   — Azure tenant ID
    "azure_sub":     str   — Azure subscription ID
    "status":        str   — "ok" | "error"
    "data":          dict  — collector-specific payload (contains compliance_signals)
    "error":         str   — only present when status == "error"
}

Why this matters for compliance:
  Every artifact is timestamped and saved twice — once as latest.json for quick
  status checks, and once as a dated snapshot (e.g. 20250325_140000.json) that
  is NEVER overwritten.  Those dated snapshots are your audit trail — they prove
  what your posture looked like on a specific date even after you remediate.
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path


class BaseCollector:
    """
    Standardised evidence artifact base.

    To write a new collector:
      1. Subclass BaseCollector
      2. Call super().__init__(evidence_id, credential, subscription_id, tenant_id)
      3. Override the collect() method — return a dict with a 'compliance_signals' key
      4. Call .run() to execute, wrap in the envelope, and save to disk
    """

    # Where to write evidence files.
    # Overridden by the EVIDENCE_DIR environment variable (set by GitHub Actions).
    EVIDENCE_DIR = Path(os.getenv("EVIDENCE_DIR", "evidence"))

    def __init__(self, evidence_id: str, credential, subscription_id: str, tenant_id: str):
        """
        Parameters
        ----------
        evidence_id     : str   — folder name under evidence/ and key in controls.yaml
        credential      : azure.identity credential object (e.g. DefaultAzureCredential)
        subscription_id : str   — the Azure subscription being assessed
        tenant_id       : str   — the Azure Entra ID tenant
        """
        self.evidence_id = evidence_id
        self.credential = credential
        self.subscription_id = subscription_id
        self.tenant_id = tenant_id
        self.collected_at = datetime.now(timezone.utc).isoformat()

    def collect(self) -> dict:
        """
        Override this in every subclass.
        Must return a dict that always contains a 'compliance_signals' key.
        The compliance_signals dict holds bool or list values that
        generate_report.py reads to determine PASS / FAIL.
        """
        raise NotImplementedError

    def run(self) -> dict:
        """
        Execute collect(), wrap the result in the standard envelope, save to disk.
        Even if collect() raises an exception the artifact is saved with status=error
        so the report generator can surface the gap rather than silently skipping it.
        """
        try:
            data = self.collect()
            artifact = {
                "evidence_id": self.evidence_id,
                "collector": self.__class__.__name__,
                "collected_at": self.collected_at,
                "azure_tenant": self.tenant_id,
                "azure_sub": self.subscription_id,
                "status": "ok",
                "data": data,
            }
        except Exception as exc:
            artifact = {
                "evidence_id": self.evidence_id,
                "collector": self.__class__.__name__,
                "collected_at": self.collected_at,
                "azure_tenant": self.tenant_id,
                "azure_sub": self.subscription_id,
                "status": "error",
                "error": str(exc),
                "data": None,
            }

        self._save(artifact)
        return artifact

    def _save(self, artifact: dict):
        """
        Write the artifact to two locations:
          evidence/<evidence_id>/latest.json       — always overwritten (for reports)
          evidence/<evidence_id>/YYYYMMDD_HHMMSS.json — never overwritten (audit trail)

        The dated file is what an auditor looks at to prove posture on a given date.
        Git history adds a second layer — every commit is timestamped and tied to
        a specific workflow run ID in the commit message.
        """
        folder = self.EVIDENCE_DIR / self.evidence_id
        folder.mkdir(parents=True, exist_ok=True)

        latest_path = folder / "latest.json"
        latest_path.write_text(json.dumps(artifact, indent=2, default=str))

        date_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        snapshot_path = folder / f"{date_str}.json"
        snapshot_path.write_text(json.dumps(artifact, indent=2, default=str))

        status = artifact["status"].upper()
        print(f"[{status}] {self.evidence_id} → {latest_path}")
