import time
from typing import Any, Optional
from .secrets import DetectionEvent

PRICING_FIELDS = [
    "amount", "price", "total", "cost", "value",
    "subtotal", "grand_total", "order_total", "payment_amount",
]

QUANTITY_FIELDS = [
    "quantity", "qty", "count", "units", "items",
]

PERMISSION_FIELDS = [
    "role", "admin", "isAdmin", "is_admin", "superadmin",
    "super_admin", "permissions", "privilege", "access_level",
    "user_role", "account_type", "plan", "tier",
]

DISCOUNT_FIELDS = [
    "discount", "discount_percent", "discount_amount",
    "coupon", "promo", "promo_code", "voucher",
]

PRIVILEGED_VALUES = {
    "admin", "superadmin", "super_admin", "owner", "root",
    "god", "sysadmin", "moderator", "mod", "staff",
}

BOOLEAN_PRIVILEGE_FIELDS = {
    "admin", "isAdmin", "is_admin", "superadmin", "super_admin",
    "isSuperAdmin", "is_super_admin", "isOwner", "is_owner",
    "staff", "isStaff", "is_staff", "moderator", "isModerator",
}


def _to_number(val: Any) -> Optional[float]:
    if isinstance(val, (int, float)) and not isinstance(val, bool):
        return float(val)
    if isinstance(val, str):
        try:
            return float(val)
        except (ValueError, TypeError):
            return None
    return None


def _detect_suspicious_pricing(body: dict[str, Any], route: Optional[str], method: Optional[str]) -> list[DetectionEvent]:
    events: list[DetectionEvent] = []
    now = time.time() * 1000

    for field in PRICING_FIELDS:
        val = body.get(field)
        if val is None:
            continue
        num = _to_number(val)
        if num is None:
            continue

        if num < 0:
            events.append(DetectionEvent(
                type="business_logic_tamper",
                severity="critical",
                patternId="tamper_negative_amount",
                description=f"Pricing field `{field}` has negative value {num} — the server should reject negative amounts",
                route=route,
                method=method,
                timestamp=now,
            ))
        elif num == 0:
            events.append(DetectionEvent(
                type="business_logic_tamper",
                severity="high",
                patternId="tamper_zero_amount",
                description=f"Pricing field `{field}` is zero — verify this is intentional and not client-side price manipulation",
                route=route,
                method=method,
                timestamp=now,
            ))

    for field in QUANTITY_FIELDS:
        val = body.get(field)
        if val is None:
            continue
        num = _to_number(val)
        if num is None:
            continue

        if num < 0:
            events.append(DetectionEvent(
                type="business_logic_tamper",
                severity="critical",
                patternId="tamper_negative_quantity",
                description=f"Quantity field `{field}` has negative value {num}",
                route=route,
                method=method,
                timestamp=now,
            ))

    for field in DISCOUNT_FIELDS:
        val = body.get(field)
        if val is None:
            continue
        num = _to_number(val)
        if num is None:
            continue

        if num >= 100:
            events.append(DetectionEvent(
                type="business_logic_tamper",
                severity="critical",
                patternId="tamper_full_discount",
                description=f"Discount field `{field}` is {num}% — a 100%+ discount means free product",
                route=route,
                method=method,
                timestamp=now,
            ))
        elif num < 0:
            events.append(DetectionEvent(
                type="business_logic_tamper",
                severity="high",
                patternId="tamper_negative_discount",
                description=f"Discount field `{field}` has negative value {num}%",
                route=route,
                method=method,
                timestamp=now,
            ))

    return events


def _detect_suspicious_permissions(body: dict[str, Any], route: Optional[str], method: Optional[str]) -> list[DetectionEvent]:
    events: list[DetectionEvent] = []
    now = time.time() * 1000

    for field in PERMISSION_FIELDS:
        val = body.get(field)
        if val is None:
            continue

        if isinstance(val, bool):
            if field in BOOLEAN_PRIVILEGE_FIELDS and val is True:
                events.append(DetectionEvent(
                    type="business_logic_tamper",
                    severity="critical",
                    patternId="tamper_privilege_escalation",
                    description=f"Boolean privilege field `{field}` set to true in request body — permissions must be set server-side",
                    route=route,
                    method=method,
                    timestamp=now,
                ))
        elif isinstance(val, str):
            if val.lower() in PRIVILEGED_VALUES:
                events.append(DetectionEvent(
                    type="business_logic_tamper",
                    severity="critical",
                    patternId="tamper_privilege_escalation",
                    description=f"Permission field `{field}` set to privileged value `{val}` in request body",
                    route=route,
                    method=method,
                    timestamp=now,
                ))

    return events


def _validate_constraints(body: dict[str, Any], constraints: list[dict], route: Optional[str], method: Optional[str]) -> list[DetectionEvent]:
    events: list[DetectionEvent] = []
    now = time.time() * 1000

    for item in constraints:
        field = item.get("field", "")
        constraint = item.get("constraint") or item.get("type") or {}
        constraint_type = constraint.get("type") if isinstance(constraint, dict) else constraint

        val = body.get(field)
        if constraint_type == "readonly":
            if val is not None:
                events.append(DetectionEvent(
                    type="business_logic_tamper",
                    severity="critical",
                    patternId="tamper_readonly_field",
                    description=f"Read-only field `{field}` was included in request body — remove it from client input",
                    route=route,
                    method=method,
                    timestamp=now,
                ))
        elif constraint_type == "range":
            if val is None:
                continue
            num = _to_number(val)
            if num is None:
                events.append(DetectionEvent(
                    type="business_logic_tamper",
                    severity="high",
                    patternId="tamper_invalid_type",
                    description=f"Field `{field}` expected a number but got `{type(val).__name__}`",
                    route=route,
                    method=method,
                    timestamp=now,
                ))
                continue
            min_val = constraint.get("min")
            max_val = constraint.get("max")
            if min_val is not None and num < min_val:
                events.append(DetectionEvent(
                    type="business_logic_tamper",
                    severity="high",
                    patternId="tamper_below_min",
                    description=f"Field `{field}` value {num} is below minimum {min_val}",
                    route=route,
                    method=method,
                    timestamp=now,
                ))
            if max_val is not None and num > max_val:
                events.append(DetectionEvent(
                    type="business_logic_tamper",
                    severity="high",
                    patternId="tamper_above_max",
                    description=f"Field `{field}` value {num} is above maximum {max_val}",
                    route=route,
                    method=method,
                    timestamp=now,
                ))
        elif constraint_type == "enum":
            if val is None:
                continue
            allowed = constraint.get("values", [])
            if val not in allowed:
                events.append(DetectionEvent(
                    type="business_logic_tamper",
                    severity="high",
                    patternId="tamper_invalid_enum",
                    description=f"Field `{field}` value `{val}` is not in allowed values: {', '.join(map(str, allowed))}",
                    route=route,
                    method=method,
                    timestamp=now,
                ))

    return events


def detect_business_logic_tamper(
    body: dict[str, Any],
    constraints: Optional[list[dict]] = None,
    route: Optional[str] = None,
    method: Optional[str] = None,
) -> list[DetectionEvent]:
    if not body or not isinstance(body, dict):
        return []

    events: list[DetectionEvent] = []

    events.extend(_detect_suspicious_pricing(body, route, method))
    events.extend(_detect_suspicious_permissions(body, route, method))

    if constraints and len(constraints) > 0:
        events.extend(_validate_constraints(body, constraints, route, method))

    return events
