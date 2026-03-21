from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import ResourceManagementClient
import os

def main() -> None:
    subscription_id = os.environ.get("AZURE_SUBSCRIPTION_ID")
    if not subscription_id:
        raise SystemExit(
            "AZURE_SUBSCRIPTION_ID is not set. Run:\n"
            "  export AZURE_SUBSCRIPTION_ID=$(az account show --query id -o tsv)"
        )

    credential = DefaultAzureCredential(exclude_interactive_browser_credential=True)
    client = ResourceManagementClient(credential, subscription_id)

    rgs = list(client.resource_groups.list())
    print(f"Authenticated. Resource groups visible: {len(rgs)}")
    for rg in rgs[:10]:
        print(f"- {rg.name}")

if __name__ == "__main__":
    main()