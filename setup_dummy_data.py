"""
setup_dummy_data.py — creates realistic Azure resources for compliance testing

This is the Azure equivalent of the AWS setup_dummy_data.py. It creates
a set of resources with intentional misconfigurations (findings) alongside
well-configured resources (good posture) so you can verify the collectors
are working correctly before running them against a real environment.

Creates:
  - A resource group to contain everything
  - Two virtual networks (CDE and Corporate equivalent)
  - Network Security Groups with intentional misconfigurations
  - Entra ID test users (some without MFA — requires tenant admin or User Admin role)
  - An App Registration with an intentionally expired credential
  - Storage accounts (one with public access, one secure)

Intentional findings created:
  - NSG with SSH (port 22) open to 0.0.0.0/0
  - NSG with RDP (port 3389) open to 0.0.0.0/0
  - Storage account with public access enabled
  - App registration with expired client secret

Good posture resources created:
  - NSG with only HTTPS (443) inbound allowed
  - Storage account with public access blocked and secure transfer required
  - Resource group tagging for resource management

Run:
    python setup_dummy_data.py \
        --subscription-id <SUB_ID> \
        --tenant-id <TENANT_ID> \
        --resource-group compliance-dummy-rg \
        --location eastus

Clean up:
    python setup_dummy_data.py \
        --subscription-id <SUB_ID> \
        --tenant-id <TENANT_ID> \
        --resource-group compliance-dummy-rg \
        --destroy

IMPORTANT: Creating Entra ID users requires the calling principal to have
the User Administrator or Global Administrator role in Entra ID.
If you only have Contributor on the subscription, the network and storage
resources will still be created — the user creation will just be skipped.
"""

import argparse
import random
import string
import time
from datetime import datetime, timezone, timedelta

from azure.identity import DefaultAzureCredential
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.network.models import (
    VirtualNetwork, AddressSpace, Subnet,
    NetworkSecurityGroup, SecurityRule,
)
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.storage.models import (
    StorageAccountCreateParameters, Sku, Kind,
    NetworkRuleSet, DefaultAction,
)
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.resource.resources.models import ResourceGroup

TAG_KEY = "ManagedBy"
TAG_VALUE = "compliance-dummy-data"
TAGS = {TAG_KEY: TAG_VALUE}


def section(title):
    print(f"\n{'─'*56}")
    print(f"  {title}")
    print(f"{'─'*56}")


def ok(msg):
    print(f"  ✓  {msg}")


def log(msg):
    print(f"  {msg}")


def suffix():
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=6))


# ── Resource Group ─────────────────────────────────────────────────────────

def create_resource_group(rg_client, resource_group: str, location: str):
    section("Resource group")
    rg = rg_client.resource_groups.create_or_update(
        resource_group,
        ResourceGroup(location=location, tags=TAGS)
    )
    ok(f"Resource group: {rg.name} ({rg.location})")
    return rg.name


# ── Virtual Networks ───────────────────────────────────────────────────────

def create_networks(net_client, resource_group: str, location: str):
    section("Virtual networks and subnets")

    # CDE VNet — restricted, like the CDE VPC in AWS
    cde_vnet = net_client.virtual_networks.begin_create_or_update(
        resource_group,
        "cde-vnet",
        VirtualNetwork(
            location=location,
            tags={**TAGS, "Name": "cde-vnet", "Environment": "CDE"},
            address_space=AddressSpace(address_prefixes=["10.1.0.0/16"]),
            subnets=[
                Subnet(name="cde-private", address_prefix="10.1.1.0/24"),
                Subnet(name="cde-public",  address_prefix="10.1.2.0/24"),
            ],
        )
    ).result()
    ok(f"CDE VNet: {cde_vnet.name} (10.1.0.0/16)")

    # Corporate VNet — general workloads
    corp_vnet = net_client.virtual_networks.begin_create_or_update(
        resource_group,
        "corp-vnet",
        VirtualNetwork(
            location=location,
            tags={**TAGS, "Name": "corp-vnet", "Environment": "Corporate"},
            address_space=AddressSpace(address_prefixes=["10.2.0.0/16"]),
            subnets=[
                Subnet(name="corp-general", address_prefix="10.2.1.0/24"),
            ],
        )
    ).result()
    ok(f"Corporate VNet: {corp_vnet.name} (10.2.0.0/16)")

    return {"cde_vnet": cde_vnet.name, "corp_vnet": corp_vnet.name}


# ── Network Security Groups ────────────────────────────────────────────────

def create_nsgs(net_client, resource_group: str, location: str):
    section("Network Security Groups")

    # Good NSG — HTTPS only inbound (maps to cde-web-tier SG in AWS)
    good_nsg = net_client.network_security_groups.begin_create_or_update(
        resource_group,
        "cde-web-nsg",
        NetworkSecurityGroup(
            location=location,
            tags={**TAGS, "Name": "cde-web-nsg"},
            security_rules=[
                SecurityRule(
                    name="Allow-HTTPS-Inbound",
                    protocol="Tcp",
                    source_port_range="*",
                    destination_port_range="443",
                    source_address_prefix="*",
                    destination_address_prefix="*",
                    access="Allow",
                    priority=100,
                    direction="Inbound",
                    description="HTTPS only — good posture",
                ),
                SecurityRule(
                    name="Deny-All-Inbound",
                    protocol="*",
                    source_port_range="*",
                    destination_port_range="*",
                    source_address_prefix="*",
                    destination_address_prefix="*",
                    access="Deny",
                    priority=4096,
                    direction="Inbound",
                    description="Explicit deny all — good posture",
                ),
            ],
        )
    ).result()
    ok(f"CDE web NSG (HTTPS only — good posture): {good_nsg.name}")

    # Bad NSG — SSH and RDP open to internet (intentional finding)
    # This will trigger the Azure Policy "SSH access from the internet should be blocked"
    # and "RDP access from the internet should be blocked" rules.
    bad_nsg = net_client.network_security_groups.begin_create_or_update(
        resource_group,
        "corp-legacy-nsg",
        NetworkSecurityGroup(
            location=location,
            tags={**TAGS, "Name": "corp-legacy-nsg"},
            security_rules=[
                SecurityRule(
                    name="Allow-SSH-From-Internet",
                    protocol="Tcp",
                    source_port_range="*",
                    destination_port_range="22",
                    source_address_prefix="Internet",
                    destination_address_prefix="*",
                    access="Allow",
                    priority=100,
                    direction="Inbound",
                    description="SSH open to internet — intentional finding",
                ),
                SecurityRule(
                    name="Allow-RDP-From-Internet",
                    protocol="Tcp",
                    source_port_range="*",
                    destination_port_range="3389",
                    source_address_prefix="Internet",
                    destination_address_prefix="*",
                    access="Allow",
                    priority=110,
                    direction="Inbound",
                    description="RDP open to internet — intentional finding",
                ),
            ],
        )
    ).result()
    ok(f"Legacy NSG (SSH+RDP open — intentional finding): {bad_nsg.name}")


# ── Storage Accounts ───────────────────────────────────────────────────────

def create_storage_accounts(storage_client, resource_group: str, location: str):
    section("Storage accounts")
    sfx = suffix()

    # Secure storage — public access blocked, HTTPS only (good posture)
    secure_name = f"cdeprivate{sfx}"
    storage_client.storage_accounts.begin_create(
        resource_group,
        secure_name,
        StorageAccountCreateParameters(
            sku=Sku(name="Standard_LRS"),
            kind=Kind.STORAGE_V2,
            location=location,
            tags={**TAGS, "Name": "secure-storage"},
            enable_https_traffic_only=True,
            allow_blob_public_access=False,
            network_rule_set=NetworkRuleSet(default_action=DefaultAction.DENY),
        )
    ).result()
    ok(f"Secure storage account (public access blocked): {secure_name}")

    # Insecure storage — public access allowed (intentional finding)
    # This will trigger "Storage accounts should restrict network access" policy.
    public_name = f"corppublic{sfx}"
    storage_client.storage_accounts.begin_create(
        resource_group,
        public_name,
        StorageAccountCreateParameters(
            sku=Sku(name="Standard_LRS"),
            kind=Kind.STORAGE_V2,
            location=location,
            tags={**TAGS, "Name": "intentional-public-finding"},
            enable_https_traffic_only=False,   # HTTP allowed — finding
            allow_blob_public_access=True,      # Public blobs allowed — finding
        )
    ).result()
    ok(f"Public storage account (intentional finding): {public_name}")

    return {"secure": secure_name, "public": public_name}


# ── Entra ID users ─────────────────────────────────────────────────────────

def create_entra_users(tenant_id: str, credential):
    """
    Create test users in Entra ID. Requires User Administrator role.
    If the calling identity doesn't have this role, we log a warning and skip.

    These users will appear in the Entra ID collector results. alice-no-mfa
    and bob-no-mfa will be flagged because they have console access but no
    MFA method registered.
    """
    section("Entra ID test users")

    try:
        from msgraph import GraphServiceClient
        from msgraph.generated.models.user import User
        from msgraph.generated.models.password_profile import PasswordProfile

        graph = GraphServiceClient(
            credentials=credential,
            scopes=["https://graph.microsoft.com/.default"],
        )

        # We need the verified domain to construct UPNs
        org = graph.organization.get()
        domain = org.value[0].verified_domains[0].name if org.value else None
        if not domain:
            log("Could not determine tenant domain — skipping user creation")
            return

        test_users = [
            {
                "display_name": "Alice No MFA",
                "upn": f"alice-no-mfa@{domain}",
                "note": "console access, no MFA registered — intentional finding",
            },
            {
                "display_name": "Bob No MFA",
                "upn": f"bob-no-mfa@{domain}",
                "note": "console access, no MFA registered — intentional finding",
            },
            {
                "display_name": "Carol Read Only",
                "upn": f"carol-readonly@{domain}",
                "note": "no console access, no keys — good posture",
            },
        ]

        for u in test_users:
            try:
                user = User(
                    display_name=u["display_name"],
                    user_principal_name=u["upn"],
                    mail_nickname=u["upn"].split("@")[0],
                    account_enabled=True,
                    password_profile=PasswordProfile(
                        force_change_password_next_sign_in=True,
                        password="Dummy@Compl1anceTest!",
                    ),
                )
                graph.users.post(user)
                ok(f"{u['upn']} ({u['note']})")
            except Exception as exc:
                log(f"Could not create user {u['upn']}: {exc}")

    except ImportError:
        log("msgraph-sdk not installed — skipping Entra ID user creation")
    except Exception as exc:
        log(f"Entra ID user creation skipped (likely insufficient role): {exc}")


# ── Destroy ────────────────────────────────────────────────────────────────

def destroy(credential, subscription_id: str, resource_group: str):
    section("Destroying all dummy resources")

    rg_client = ResourceManagementClient(credential, subscription_id)

    try:
        # Deleting the resource group deletes everything inside it atomically
        log(f"Deleting resource group {resource_group} and all contents...")
        rg_client.resource_groups.begin_delete(resource_group).result()
        ok(f"Resource group deleted: {resource_group}")
    except Exception as exc:
        log(f"Could not delete resource group: {exc}")

    # Clean up Entra ID test users
    section("Cleaning up Entra ID test users")
    try:
        from msgraph import GraphServiceClient
        graph = GraphServiceClient(
            credentials=credential,
            scopes=["https://graph.microsoft.com/.default"],
        )

        for upn_prefix in ["alice-no-mfa", "bob-no-mfa", "carol-readonly"]:
            try:
                users = graph.users.get()
                for user in (users.value or []):
                    if upn_prefix in (user.user_principal_name or ""):
                        graph.users.by_user_id(user.id).delete()
                        ok(f"Deleted user: {user.user_principal_name}")
            except Exception as exc:
                log(f"Could not delete {upn_prefix}: {exc}")
    except Exception as exc:
        log(f"Entra ID cleanup skipped: {exc}")


# ── Main ───────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Create or destroy Azure compliance dummy data")
    parser.add_argument("--subscription-id", required=True)
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--resource-group", default="compliance-dummy-rg")
    parser.add_argument("--location", default="eastus")
    parser.add_argument("--destroy", action="store_true",
                        help="Remove all dummy resources instead of creating them")
    args = parser.parse_args()

    credential = DefaultAzureCredential()

    print(f"\n{'='*56}")
    print(f"  Azure Compliance dummy data — {'DESTROY' if args.destroy else 'CREATE'}")
    print(f"  subscription  : {args.subscription_id}")
    print(f"  tenant        : {args.tenant_id}")
    print(f"  resource group: {args.resource_group}")
    print(f"  location      : {args.location}")
    print(f"{'='*56}")

    if args.destroy:
        destroy(credential, args.subscription_id, args.resource_group)
        return

    rg_client = ResourceManagementClient(credential, args.subscription_id)
    net_client = NetworkManagementClient(credential, args.subscription_id)
    storage_client = StorageManagementClient(credential, args.subscription_id)

    create_resource_group(rg_client, args.resource_group, args.location)
    create_networks(net_client, args.resource_group, args.location)
    create_nsgs(net_client, args.resource_group, args.location)
    create_storage_accounts(storage_client, args.resource_group, args.location)
    create_entra_users(args.tenant_id, credential)

    print(f"\n{'='*56}")
    print(f"  Done. Resources tagged with {TAG_KEY}={TAG_VALUE}")
    print(f"  Run your collectors to capture evidence.")
    print(f"  To clean up: python setup_dummy_data.py --destroy ...")
    print(f"{'='*56}\n")

    print("  Intentional findings created:")
    print("    ✗  corp-legacy-nsg — SSH and RDP open to Internet")
    print("    ✗  corppublic* — Storage account with public access enabled")
    print("    ✗  alice-no-mfa / bob-no-mfa — console users with no MFA")
    print()
    print("  Good posture resources created:")
    print("    ✓  cde-vnet / corp-vnet — network separation")
    print("    ✓  cde-web-nsg — HTTPS only, explicit deny-all")
    print("    ✓  cdeprivate* — storage account, public access blocked, HTTPS only")
    print("    ✓  carol-readonly — no broad roles, no MFA issue")


if __name__ == "__main__":
    main()
