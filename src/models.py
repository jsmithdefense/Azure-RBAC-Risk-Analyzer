from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class RoleAssignmentRecord:
    """
    Normalized RBAC assignment record used by the analyzer.
    """
    subscription_id: str
    scope: str
    scope_type: str  # subscription / resource_group / resource

    principal_id: str
    principal_type: Optional[str]  # User / Group / ServicePrincipal / Unknown

    role_definition_id: str
    role_name: str  # resolved from role_definition_id