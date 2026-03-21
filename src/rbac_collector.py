import os
from typing import Dict, List, Optional

from azure.identity import DefaultAzureCredential
from azure.mgmt.authorization import AuthorizationManagementClient

from .models import RoleAssignmentRecord
from .scope_utils import classify_scope


def get_subscription_id() -> str:
    sub_id = os.environ.get("AZURE_SUBSCRIPTION_ID")
    if not sub_id:
        raise RuntimeError(
            "AZURE_SUBSCRIPTION_ID is not set. Run:\n"
            "  export AZURE_SUBSCRIPTION_ID=$(az account show --query id -o tsv)"
        )
    return sub_id


def build_role_definition_lookup(
    authz: AuthorizationManagementClient, subscription_id: str
) -> Dict[str, str]:
    """
    Returns a dict mapping full role_definition_id -> role_name.

    Azure role assignments DO NOT store role names. This lookup converts Azure API output into a normalized RBAC record.
    """
    scope = f"/subscriptions/{subscription_id}"
    lookup: Dict[str, str] = {}

    for rd in authz.role_definitions.list(scope):
        if rd.id and rd.role_name:
            lookup[rd.id] = rd.role_name

    return lookup


def collect_role_assignments(
    authz: AuthorizationManagementClient,
    subscription_id: str,
    role_lookup: Dict[str, str],
    *,
    scope: Optional[str] = None,
) -> List[RoleAssignmentRecord]:
    """
    Collect role assignments visible under a scope and normalize them.

    - scope defaults to subscription scope
    - role_name is resolved via role_lookup
    - scope_type is derived from the resolved scope string
    """
    target_scope = scope or f"/subscriptions/{subscription_id}"
    records: List[RoleAssignmentRecord] = []

    for ra in authz.role_assignments.list_for_scope(target_scope):
        resolved_scope = ra.scope or target_scope
        rd_id = ra.role_definition_id or ""
        role_name = role_lookup.get(rd_id, "UNKNOWN_ROLE")

        records.append(
            RoleAssignmentRecord(
                subscription_id=subscription_id,
                scope=resolved_scope,
                scope_type=classify_scope(resolved_scope),
                principal_id=ra.principal_id or "UNKNOWN_PRINCIPAL",
                principal_type=ra.principal_type,
                role_definition_id=rd_id,
                role_name=role_name,
            )
        )

    return records

