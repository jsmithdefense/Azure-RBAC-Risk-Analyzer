def classify_scope(scope: str) -> str:
    """
    Classifies an Azure RBAC scope into a simplified category.

    Returns:
        subscription
        resource_group
        resource
    """
    scope = scope.lower()

    if "/resourcegroups/" not in scope:
        return "subscription"

    if "/providers/" not in scope:
        return "resource_group"

    return "resource"

