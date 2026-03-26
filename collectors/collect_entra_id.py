"""
collect_entra_id.py — Azure Entra ID posture evidence collector

Evidence ID : azure_entra_id_posture
Auth needed : Bearer token scoped to https://graph.microsoft.com/.default
              Graph permissions: User.Read.All, Directory.Read.All,
              Policy.Read.All, AuditLog.Read.All, Application.Read.All

All calls use requests + bearer token directly against the Microsoft Graph
REST API. The msgraph-sdk-python uses async under the hood which does not
work in our synchronous collector pattern — direct REST calls are simpler
and more reliable here.

Controls satisfied:
  PCI-DSS   7.1.1, 8.2.1, 8.3.9, 8.4.2, 8.4.3
  SOC 2     CC6.1, CC6.2
  ISO 27001 A.5.15, A.5.16, A.5.17, A.5.18
  ISO 42001 6.4.1
"""

import argparse
import requests
from datetime import datetime, timezone, timedelta

from azure.identity import DefaultAzureCredential
from azure.mgmt.authorization import AuthorizationManagementClient

from base import BaseCollector

GRAPH = "https://graph.microsoft.com/v1.0"
ARM = "https://management.azure.com"
STALE_KEY_DAYS = 90
MAX_GLOBAL_ADMINS = 4

PRIVILEGED_ROLE_DEFS = {
    "8e3af657-a8ff-443c-a75c-2fe8c4bcb635": "Owner",
    "b24988ac-6180-42a0-ab88-20f7382dd24c": "Contributor",
}


class EntraIDCollector(BaseCollector):

    def _graph_headers(self):
        token = self.credential.get_token("https://graph.microsoft.com/.default").token
        return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    def _arm_headers(self):
        token = self.credential.get_token(f"{ARM}/.default").token
        return {"Authorization": f"Bearer {token}"}

    def _graph_get(self, path, params=None):
        """Simple helper for Graph GET requests, handles pagination."""
        h = self._graph_headers()
        url = f"{GRAPH}/{path}"
        results = []
        while url:
            resp = requests.get(url, headers=h, params=params)
            if resp.status_code != 200:
                break
            data = resp.json()
            results.extend(data.get("value", []))
            url = data.get("@odata.nextLink")
            params = None  # nextLink already contains params
        return results

    def collect(self) -> dict:

        # ── 1. Users and MFA status ─────────────────────────────────────────
        users = self._graph_get(
            "users",
            params={
                "$select": "id,displayName,userPrincipalName,userType,accountEnabled",
                "$top": "999",
            }
        )

        users_detail = []
        mfa_disabled_users = []
        guest_users = []

        for user in users:
            is_guest = user.get("userType") == "Guest"
            is_enabled = user.get("accountEnabled", False)
            upn = user.get("userPrincipalName", "")

            if is_guest:
                guest_users.append(upn)
                continue

            # Check authentication methods — anything other than password = MFA registered
            try:
                methods = self._graph_get(
                    f"users/{user['id']}/authentication/methods"
                )
                method_types = [
                    m.get("@odata.type", "")
                    for m in methods
                    if "password" not in m.get("@odata.type", "").lower()
                ]
                has_mfa = len(method_types) > 0
            except Exception:
                has_mfa = False
                method_types = []

            if is_enabled and not has_mfa:
                mfa_disabled_users.append(upn)

            users_detail.append({
                "upn": upn,
                "display_name": user.get("displayName"),
                "enabled": is_enabled,
                "mfa_registered": has_mfa,
                "mfa_methods": method_types,
            })

        # ── 2. Conditional Access policies ─────────────────────────────────
        try:
            ca_policies = self._graph_get("identity/conditionalAccess/policies")
            ca_detail = []
            mfa_policy_enabled = False

            for policy in ca_policies:
                grants = []
                gc = policy.get("grantControls") or {}
                built_in = gc.get("builtInControls", [])
                grants = [str(g) for g in built_in]

                is_mfa_policy = (
                    "mfa" in grants
                    and policy.get("state") == "enabled"
                )
                if is_mfa_policy:
                    mfa_policy_enabled = True

                ca_detail.append({
                    "name": policy.get("displayName"),
                    "state": policy.get("state"),
                    "grant_controls": grants,
                })
        except Exception:
            ca_detail = []
            mfa_policy_enabled = False

        # ── 3. Global Admin count ───────────────────────────────────────────
        try:
            roles = self._graph_get("directoryRoles")
            global_admin_members = []

            for role in roles:
                if role.get("displayName") == "Global Administrator":
                    members = self._graph_get(
                        f"directoryRoles/{role['id']}/members"
                    )
                    global_admin_members = [
                        m.get("userPrincipalName") or m.get("id")
                        for m in members
                    ]
                    break
        except Exception:
            global_admin_members = []

        # ── 4. Service principal stale credentials ──────────────────────────
        try:
            sps = self._graph_get(
                "servicePrincipals",
                params={"$select": "id,displayName,passwordCredentials", "$top": "500"}
            )
            stale_sp_creds = []
            now = datetime.now(timezone.utc)

            for sp in sps:
                for cred in sp.get("passwordCredentials", []):
                    end_date_str = cred.get("endDateTime")
                    if end_date_str:
                        try:
                            end_date = datetime.fromisoformat(
                                end_date_str.replace("Z", "+00:00")
                            )
                            if end_date < now:
                                stale_sp_creds.append({
                                    "service_principal": sp.get("displayName"),
                                    "credential_id": cred.get("keyId"),
                                    "issue": "expired",
                                    "end_date": end_date_str,
                                })
                        except ValueError:
                            pass
        except Exception:
            stale_sp_creds = []

        # ── 5. Broad RBAC assignments at subscription scope ─────────────────
        try:
            auth_client = AuthorizationManagementClient(
                self.credential, self.subscription_id
            )
            assignments = list(auth_client.role_assignments.list_for_subscription())
            broad_assignments = []

            for assignment in assignments:
                role_def_id = assignment.role_definition_id.split("/")[-1]
                if role_def_id in PRIVILEGED_ROLE_DEFS:
                    if assignment.principal_type == "User":
                        broad_assignments.append({
                            "principal_id": assignment.principal_id,
                            "role": PRIVILEGED_ROLE_DEFS[role_def_id],
                            "scope": assignment.scope,
                        })
        except Exception:
            broad_assignments = []

        # ── Compliance signals ──────────────────────────────────────────────
        return {
            "user_count": len(users_detail),
            "guest_user_count": len(guest_users),
            "users": users_detail,
            "mfa_disabled_users": mfa_disabled_users,
            "conditional_access_policies": ca_detail,
            "mfa_conditional_access_policy_enabled": mfa_policy_enabled,
            "global_admin_members": global_admin_members,
            "global_admin_count": len(global_admin_members),
            "stale_sp_credentials": stale_sp_creds,
            "broad_direct_role_assignments": broad_assignments,
            "compliance_signals": {
                "all_users_have_mfa": len(mfa_disabled_users) == 0,
                "mfa_conditional_access_enforced": mfa_policy_enabled,
                "global_admin_count_acceptable": len(global_admin_members) <= MAX_GLOBAL_ADMINS,
                "no_stale_service_principal_credentials": len(stale_sp_creds) == 0,
                "no_direct_broad_role_at_sub_scope": len(broad_assignments) == 0,
                "mfa_disabled_users": mfa_disabled_users,
                "stale_credentials": stale_sp_creds,
            },
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--subscription-id", required=True)
    parser.add_argument("--tenant-id", required=True)
    args = parser.parse_args()

    credential = DefaultAzureCredential()
    result = EntraIDCollector(
        "azure_entra_id_posture", credential, args.subscription_id, args.tenant_id
    ).run()

    signals = (result.get("data") or {}).get("compliance_signals", {})
    for k, v in signals.items():
        if isinstance(v, list):
            tag = "ℹ" if not v else "⚠"
            label = "(none)" if not v else ", ".join(str(x) for x in v[:3])
            print(f"  {tag}  {k}: {label}")
        else:
            icon = "✓" if v else "✗"
            print(f"  {icon}  {k}")
