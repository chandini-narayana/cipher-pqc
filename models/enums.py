"""Shared enums used across CIPHER's domain models.

CaptureMode is intentionally NOT defined here: it selects which
capture/ implementation config.settings builds (see docs/SDD.md
Section 10) — an operational/config concern, not a business entity —
and none of Step 4's models need it. It stays a plain string on
Settings for now, unchanged from Step 3, so nothing there is touched
by this step.
"""
from __future__ import annotations

from enum import Enum


class ProtocolType(str, Enum):
    """Application-layer protocol observed for a connection/flow."""

    HTTPS = "HTTPS"
    HTTP = "HTTP"
    MQTT = "MQTT"
    TELNET = "TELNET"
    OTHER = "OTHER"


class RiskCategory(str, Enum):
    """Coarse risk bucket for a device.

    This enum only names the buckets. Deciding which bucket applies is
    business logic that belongs to risk/ (rule-based) and the future
    fusion step (rule-based + Isolation Forest) — never to the models
    themselves.
    """

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class TLSVersion(float, Enum):
    """Known TLS protocol versions CIPHER fingerprints.

    Modeled as a float-valued enum rather than a bare float field on
    ProtocolFingerprint, so a value like 2.7 is rejected at
    construction time instead of silently reaching the risk formula's
    version-to-score lookup later.
    """

    TLS_1_0 = 1.0
    TLS_1_1 = 1.1
    TLS_1_2 = 1.2
    TLS_1_3 = 1.3