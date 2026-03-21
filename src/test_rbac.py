import os
from azure.identity import DefaultAzureCredential
from azure.mgmt.authorization import AuthorizationManagementClient


def main() -> None:
    sub_id = os.environ.get("AZURE_SUBSCRIPTION_ID")
    if not sub_id:
        raise SystemExit(
            "AZURE_SUBSCRIPTION_ID is not set. Run:\n"
            "  export AZURE_SUBSCRIPTION_ID=$(az account show --query id -o tsv)"
        )

    credential = DefaultAzureCredential(exclude_interactive_browser_credential=True)
    authz = AuthorizationManagementClient(credential, sub_id)

    scope = f"/subscriptions/{sub_id}"
    count = 0
    max_print = 10

    print(f"Enumerating role assignments at: {scope}")

    for ra in authz.role_assignments.list_for_scope(scope):
        count += 1

        if count <= max_print:
            print(
                f"- principal_id={ra.principal_id} "
                f"role_definition_id={ra.role_definition_id} "
                f"scope={ra.scope}"
            )

    print(f"\nTotal role assignments visible: {count}")


if __name__ == "__main__":
    main()