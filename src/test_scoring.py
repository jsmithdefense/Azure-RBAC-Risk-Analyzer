from __future__ import annotations

from .config_loader import load_risk_config
from .models import RoleAssignmentRecord
from .risk_model import score_records


def main() -> None:
    cfg = load_risk_config()

    # Fake sample RBAC records (no Azure calls)
    samples = [
        RoleAssignmentRecord(
            subscription_id="sub123",
            scope="/subscriptions/sub123",
            scope_type="subscription",
            principal_id="spn-1",
            principal_type="ServicePrincipal",
            role_definition_id="/subscriptions/sub123/providers/Microsoft.Authorization/roleDefinitions/owner-guid",
            role_name="Owner",
        ),
        RoleAssignmentRecord(
            subscription_id="sub123",
            scope="/subscriptions/sub123/resourceGroups/rg1",
            scope_type="resource_group",
            principal_id="user-1",
            principal_type="User",
            role_definition_id="/subscriptions/sub123/providers/Microsoft.Authorization/roleDefinitions/reader-guid",
            role_name="Reader",
        ),
    ]

    scored = score_records(samples, cfg)
    for s in scored:
        r = s.record
        print(
            f"{s.severity:<8} score={s.score:<3} "
            f"bucket={s.bucket:<20} role={r.role_name:<28} "
            f"principal={r.principal_type or 'Unknown':<16} scope_type={r.scope_type}"
        )


if __name__ == "__main__":
    main()