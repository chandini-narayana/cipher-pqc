"""Internal validation helpers shared across domain models.

Not part of the public models/ API — never re-exported via
models/__init__.py. Exists only to avoid duplicating the same few
checks (IP format, numeric ranges, non-empty strings, hex strings)
across every model's __post_init__.
"""
from __future__ import annotations

import ipaddress
from numbers import Real


def validate_ip(label: str, value: str) -> None:
    """Raise ValueError if `value` is not a syntactically valid IPv4/IPv6 address."""
    try:
        ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError(f"{label} '{value}' is not a valid IP address") from exc


def validate_range(label: str, value: Real, low: Real, high: Real) -> None:
    """Raise ValueError if `value` is not within the inclusive [low, high] range."""
    if not (low <= value <= high):
        raise ValueError(f"{label} must be within [{low}, {high}], got {value}")


def validate_non_empty(label: str, value: str) -> None:
    """Raise ValueError if `value` is empty or None."""
    if not value:
        raise ValueError(f"{label} must not be empty")


def validate_hex(label: str, value: str) -> None:
    """Raise ValueError if `value` is not a valid hexadecimal string."""
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"{label} is not valid hexadecimal: {value!r}") from exc


def validate_finite(label: str, value: float) -> None:
    """Raise ValueError if `value` is NaN or infinite."""
    import math

    if math.isnan(value) or math.isinf(value):
        raise ValueError(f"{label} must be a finite number, got {value}")