"""Approved input-validation helpers used alongside parameterized queries.

Parameterization protects values. These helpers cover what binding cannot:
identifiers, sort direction, and typed values that should be rejected early.
"""

from collections.abc import Mapping

ALLOWED_REPORT_TABLES = frozenset({"orders", "invoices", "refunds"})
SORT_DIRECTIONS = {"asc": "ASC", "desc": "DESC"}


class ValidationError(ValueError):
    """Raised for input that fails an allowlist or type check. Maps to HTTP 400."""


def require_allowed(value: str, allowed: frozenset[str], field: str) -> str:
    if value not in allowed:
        raise ValidationError(f"{field} must be one of {sorted(allowed)}")
    return value


def map_allowed(value: str, mapping: Mapping[str, str], field: str) -> str:
    """Translate a user-facing key into a trusted SQL fragment via an explicit mapping."""
    try:
        return mapping[value.lower()]
    except KeyError:
        raise ValidationError(f"{field} must be one of {sorted(mapping)}") from None


def parse_positive_int(raw: str, field: str, maximum: int = 10_000) -> int:
    try:
        value = int(raw)
    except (TypeError, ValueError):
        raise ValidationError(f"{field} must be an integer") from None
    if not 0 < value <= maximum:
        raise ValidationError(f"{field} must be between 1 and {maximum}")
    return value
