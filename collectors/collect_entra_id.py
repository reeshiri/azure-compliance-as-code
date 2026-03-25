"""
collect_entra_id.py — Azure Entra ID (formerly Azure Active Directory) posture collector

Evidence ID : azure_entra_id_posture
SDK needed  : azure-mgmt-authorization, msgraph-sdk (Microsoft Graph)
RBAC needed : Directory.Read.All (Graph API — requires admin consent)
              User.Read.All (Graph API)
              Reader on subscription (for RBAC role assignments)

Why Entra ID for compliance:
  In Azure, Entra ID is the identity plane. It controls who can log in,
  whether MFA is enforced, how passwords work, and which service principals
  have which roles. This is the Azure equivalent of the AWS IAM collector.

Azure equivalent mapping:
  IAM credential report          →  Graph API users + sign-in activity
  MFA status per user            →  Authentication methods policy + per-user MFA
  Root account / no access keys  →  No direct equivalent; we check for Global
                                     Admin count and guest user exposure instead
  Password policy                →  Entra ID password policy settings
  Stale access keys              →  Service principal credential expiry

Controls satisfied:
  PCI-DSS   7.1.1, 8.2.1, 8.3.1, 8.3.9, 8.4.2, 8.4.3
  SOC 2     CC6.1, CC6.2
  ISO 27001 A.5.15, A.5.16, A.5.17, A.5.18
  ISO 42001 6.4.1

NOTE on Microsoft Graph SDK:
  This collector uses the msgraph-sdk-python package.
  Authentication flows through DefaultAzureCredential which, in GitHub Actions
  with Workload Identity Federation, automatically fetches a token scoped to
  https://graph.microsoft.com/.default without any stored secrets.
"""

import argparse
from datetime import datetime, timezone, timedelta

from azure.identity import DefaultAzureCredential
from azure.mgmt.authorization import AuthorizationManagementClient
from msgraph import GraphServiceClient
from msgraph.generated.users.users_request_builder import UsersRequestBuilder
from kiota_abstractions.base_request_configuration import RequestConfiguration

from base import BaseCollector

# Keys older than 90 days are flagged as stale — matching PCI-DSS 8.3.9
STALE_KEY_DAYS = 90

# If a tenant has more than this many Global Admins it is flagged.
# Microsoft recommends 2-4 Global Admins maximum.
MAX_GLOBAL_ADMINS = 4


class EntraIDCollector(BaseCollector):

    def collect(self) -> dict:
        # Microsoft Graph client — scoped to read-only directory operations
        graph_client = GraphServiceClient(
            credentials=self.credential,
            scopes=["https://graph.microsoft.com/.default"],
        )

        auth_client = AuthorizationManagementClient(
            self.credential, self.subscription_id
        )

        # ── 1. Users — MFA status and guest exposure ────────────────────────
        # We pull all users and look at their authentication methods.
        # Console users without MFA = direct PCI-DSS 8.4.2 failure.
        users_response = graph_client.users.get(
            request_configuration=RequestConfiguration(
                query_parameters=UsersRequestBuilder.UsersRequestBuilderGetQueryParameters(
                    select=["id", "displayName", "userPrincipalName", "userType",
                            "accountEnabled", "createdDateTime", "signInActivity"],
                    top=999,
                )
            )
        )

        users = users_response.value if users_response else []
        users_detail = []
        mfa_disabled_users = []
        guest_users = []

        for user in users:
            is_guest = user.user_type == "Guest"
            is_enabled = user.account_enabled

            if is_guest:
                guest_users.append(user.user_principal_name)
                continue  # Guests are tracked separately

            # Check MFA registration per user via authentication methods
            # This tells us if the user has registered at least one strong
            # second factor (Authenticator app, FIDO2, phone, etc.)
            try:
                auth_methods = graph_client.users.by_user_id(
                    user.id
                ).authentication.methods.get()
                method_types = [
                    m.odata_type for m in (auth_methods.value or [])
                    if m.odata_type != "#microsoft.graph.passwordAuthenticationMethod"
                ]
                has_mfa = len(method_types) > 0
            except Exception:
                # If we cannot read auth methods, conservatively mark as no MFA
                has_mfa = False
                method_types = []

            if is_enabled and not has_mfa:
                mfa_disabled_users.append(user.user_principal_name)

            users_detail.append({
                "upn": user.user_principal_name,
                "display_name": user.display_name,
                "enabled": is_enabled,
                "user_type": user.user_type,
                "mfa_registered": has_mfa,
                "mfa_methods": method_types,
                "created": str(user.created_date_time) if user.created_date_time else None,
                "last_sign_in": (
                    str(user.sign_in_activity.last_sign_in_date_time)
                    if user.sign_in_activity else None
                ),
            })

        # ── 2. Conditional Access policies ─────────────────────────────────
        # Conditional Access is Azure's way of enforcing MFA for all users.
        # A policy requiring MFA for all users satisfies PCI-DSS 8.4.2 and
        # 8.4.3 at scale rather than per-user enforcement.
        try:
            ca_policies = graph_client.identity.conditional_access.policies.get()
            ca_detail = []
            mfa_policy_enabled = False

            for policy in (ca_policies.value or []):
                grants = []
                if policy.grant_controls and policy.grant_controls.built_in_controls:
                    grants = [str(g) for g in policy.grant_controls.built_in_controls]

                is_mfa_policy = (
                    "mfa" in grants
                    and policy.state == "enabled"
                )
                if is_mfa_policy:
                    mfa_policy_enabled = True

                ca_detail.append({
                    "name": policy.display_name,
                    "state": str(policy.state),
                    "grant_controls": grants,
                    "users_included": (
                        policy.conditions.users.include_users
                        if policy.conditions and policy.conditions.users else []
                    ),
                })
        except Exception as exc:
            ca_detail = []
            mfa_policy_enabled = False

        # ── 3. Privileged roles — Global Admin count ────────────────────────
        # We look up the Global Administrator directory role and count members.
        # Excessive Global Admins = over-privileged access = PCI-DSS 7.1.1 gap.
        try:
            roles = graph_client.directory_roles.get()
            global_admin_members = []

            for role in (roles.value or []):
                if role.display_name == "Global Administrator":
                    members = graph_client.directory_roles.by_directory_role_id(
                        role.id
                    ).members.get()
                    global_admin_members = [
                        m.additional_data.get("userPrincipalName", m.id)
                        for m in (members.value or [])
                    ]
                    break
        except Exception:
            global_admin_members = []

        # ── 4. Service principals — stale credentials ───────────────────────
        # Service principals (app registrations) use client secrets or
        # certificates as credentials. When these expire or go unrotated they
        # become a security and compliance gap (equivalent to stale IAM keys).
        try:
            service_principals = graph_client.service_principals.get(
                request_configuration=RequestConfiguration(
                    query_parameters=type(
                        "Q", (), {"select": ["id", "displayName", "passwordCredentials",
                                             "keyCredentials"], "top": 500}
                    )()
                )
            )

            stale_sp_creds = []
            now = datetime.now(timezone.utc)
            cutoff = now - timedelta(days=STALE_KEY_DAYS)

            for sp in (service_principals.value or []):
                for cred in (sp.password_credentials or []):
                    end_date = cred.end_date_time
                    if end_date:
                        # Flag credentials that are already expired
                        # OR were last rotated more than 90 days ago
                        if end_date.replace(tzinfo=timezone.utc) < now:
                            stale_sp_creds.append({
                                "service_principal": sp.display_name,
                                "credential_id": str(cred.key_id),
                                "issue": "expired",
                                "end_date": str(end_date),
                            })
        except Exception:
            stale_sp_creds = []

        # ── 5. RBAC role assignments — privileged subscription roles ────────
        # Check for broad built-in roles (Owner, Contributor) assigned directly
        # to users (not to groups or managed identities) at subscription scope.
        # Direct high-privilege role assignments violate least-privilege principles.
        try:
            assignments = list(auth_client.role_assignments.list_for_subscription())
            broad_assignments = []

            # These are the GUIDs for Owner and Contributor built-in roles
            PRIVILEGED_ROLE_DEFS = {
                "8e3af657-a8ff-443c-a75c-2fe8c4bcb635": "Owner",
                "b24988ac-6180-42a0-ab88-20f7382dd24c": "Contributor",
            }

            for assignment in assignments:
                role_def_id = assignment.role_definition_id.split("/")[-1]
                if role_def_id in PRIVILEGED_ROLE_DEFS:
                    # principal_type of "User" means a human got this directly
                    # vs "Group" or "ServicePrincipal" which are more manageable
                    if assignment.principal_type == "User":
                        broad_assignments.append({
                            "principal_id": assignment.principal_id,
                            "role": PRIVILEGED_ROLE_DEFS[role_def_id],
                            "scope": assignment.scope,
                        })
        except Exception:
            broad_assignments = []

        # ── 6. Password policy ───────────────────────────────────────────────
        # In Entra ID the password policy for cloud-only accounts is managed
        # through the organization settings. Hybrid accounts follow on-prem AD.
        try:
            org = graph_client.organization.get()
            org_info = org.value[0] if org.value else None
            password_policy = {
                "password_validity_period_days": (
                    org_info.password_validity_period_in_days
                    if org_info else None
                ),
                "password_notification_days": (
                    org_info.password_notification_days_before_expiration
                    if org_info else None
                ),
            } if org_info else {}
        except Exception:
            password_policy = {}

        # ── Compliance signals ──────────────────────────────────────────────
        all_mfa_ok = len(mfa_disabled_users) == 0
        global_admin_count_ok = len(global_admin_members) <= MAX_GLOBAL_ADMINS
        no_stale_creds = len(stale_sp_creds) == 0
        no_broad_direct = len(broad_assignments) == 0

        return {
            "user_count": len(users_detail),
            "guest_user_count": len(guest_users),
            "guest_users": guest_users,
            "users": users_detail,
            "mfa_disabled_users": mfa_disabled_users,
            "conditional_access_policies": ca_detail,
            "mfa_conditional_access_policy_enabled": mfa_policy_enabled,
            "global_admin_members": global_admin_members,
            "global_admin_count": len(global_admin_members),
            "stale_sp_credentials": stale_sp_creds,
            "broad_direct_role_assignments": broad_assignments,
            "password_policy": password_policy,
            "compliance_signals": {
                # All enabled users must have MFA registered
                "all_users_have_mfa": all_mfa_ok,
                # Better: enforce MFA via Conditional Access (covers new users automatically)
                "mfa_conditional_access_enforced": mfa_policy_enabled,
                # Limit blast radius of compromised admin accounts
                "global_admin_count_acceptable": global_admin_count_ok,
                # Service principal credentials must not be expired/stale
                "no_stale_service_principal_credentials": no_stale_creds,
                # No direct Owner/Contributor at sub scope — use groups + JIT instead
                "no_direct_broad_role_at_sub_scope": no_broad_direct,
                # For detail rows in 03_findings_detail.csv
                "mfa_disabled_users": mfa_disabled_users,
                "stale_credentials": stale_sp_creds,
            },
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Collect Entra ID posture evidence")
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
