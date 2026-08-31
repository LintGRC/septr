from typing import Any, Optional


def _get_nested_value(obj: dict[str, Any], path: str) -> Any:
    parts = path.split(".")
    current: Any = obj
    for part in parts:
        if current is None or not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def extract_tenant_from_jwt(
    claims: Optional[dict[str, Any]],
    jwt_claim: str,
) -> Optional[str]:
    if not claims:
        return None
    value = _get_nested_value(claims, jwt_claim)
    if value is None:
        return None
    return str(value)


def detect_cross_tenant_leaks(
    expected_tenant_id: str,
    body: Any,
    tenant_column: str,
) -> list[dict[str, Any]]:
    leaks: list[dict[str, Any]] = []

    def scan(obj: Any, path: str) -> None:
        if obj is None:
            return
        if not isinstance(obj, (dict, list)):
            return

        if isinstance(obj, list):
            for i, item in enumerate(obj):
                scan(item, f"{path}[{i}]")
            return

        if isinstance(obj, dict):
            for key, value in obj.items():
                current_path = f"{path}.{key}" if path else key

                if key == tenant_column and value is not None:
                    if str(value) != expected_tenant_id:
                        leaks.append({"path": current_path, "value": value})
                    continue

                if isinstance(value, (dict, list)):
                    scan(value, current_path)

    scan(body, "")
    return leaks


def create_tenant_check_response(
    tenant_id: str,
    body: Any,
    config: dict[str, Any],
) -> dict[str, Any]:
    leaks = detect_cross_tenant_leaks(tenant_id, body, config.get("tenantColumn", ""))
    blocked = len(leaks) > 0 and config.get("blockOnMismatch", False)
    return {"blocked": blocked, "leaks": leaks}
