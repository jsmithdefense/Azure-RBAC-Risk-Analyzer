"""
Purpose:
Generate the analyst-editable RBAC role taxonomy by inspecting Azure role definition
permissions.

Process:
1. Enumerate role definitions from the Azure RBAC API.
2. Inspect each role's control-plane `actions` and data-plane `data_actions`.
3. Infer a capability bucket.
4. Write the resulting role -> bucket mapping to the taxonomy file used at runtime.

Output:
config/role_taxonomy.json

Notes:
- This file is both generated and editable.
- The runtime analyzer loads this same taxonomy file.
- Analysts can review and adjust classifications after generation.
"""

from __future__ import annotations

from pathlib import Path

from azure.identity import DefaultAzureCredential
from azure.mgmt.authorization import AuthorizationManagementClient

from .rbac_collector import get_subscription_id
from .role_taxonomy_generator import (
    build_role_taxonomy_template,
    write_role_taxonomy_template,
)


def main() -> None:
    """
    Generate the runtime taxonomy file by inspecting permissions of all roles
    in the subscription.
    """
    subscription_id = get_subscription_id()

    credential = DefaultAzureCredential(
        exclude_interactive_browser_credential=True
    )
    authz = AuthorizationManagementClient(credential, subscription_id)

    taxonomy = build_role_taxonomy_template(authz, subscription_id)

    output_path = (
        Path(__file__).resolve().parents[1]
        / "config"
        / "role_taxonomy.json"
    )

    write_role_taxonomy_template(taxonomy, output_path)

    print(f"Generated taxonomy entries: {len(taxonomy)}")
    print(f"Output written to: {output_path}")


if __name__ == "__main__":
    main()