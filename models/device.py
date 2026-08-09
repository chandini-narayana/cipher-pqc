"""Device — identity and lifecycle of a single network device seen by CIPHER."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict

from models._validation import validate_ip


@dataclass(frozen=True, slots=True)
class Device:
    """A single network device, identified by IP address.

    Immutable by design: a Device is a value describing "this IP, first
    seen at T1, last seen at T2" at the moment it was recorded. Updating
    last_seen produces a new Device (see `with_last_seen`) rather than
    mutating shared state.

    Raises:
        ValueError: if `ip` is not a syntactically valid IPv4/IPv6
            address, or if `last_seen` is earlier than `first_seen`.
    """

    ip: str
    first_seen: datetime
    last_seen: datetime

    def __post_init__(self) -> None:
        validate_ip("ip", self.ip)
        if self.last_seen < self.first_seen:
            raise ValueError(
                f"last_seen ({self.last_seen.isoformat()}) cannot be "
                f"earlier than first_seen ({self.first_seen.isoformat()})"
            )

    @classmethod
    def first_contact(cls, ip: str, timestamp: datetime) -> "Device":
        """Convenience constructor for a device seen for the first time —
        first_seen and last_seen both set to `timestamp`."""
        return cls(ip=ip, first_seen=timestamp, last_seen=timestamp)

    def with_last_seen(self, timestamp: datetime) -> "Device":
        """Return a new Device with last_seen updated to `timestamp`,
        leaving this instance unchanged."""
        return Device(ip=self.ip, first_seen=self.first_seen, last_seen=timestamp)

    def to_dict(self) -> Dict[str, Any]:
        """JSON-serializable representation."""
        return {
            "ip": self.ip,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Device":
        """Inverse of to_dict()."""
        return cls(
            ip=data["ip"],
            first_seen=datetime.fromisoformat(data["first_seen"]),
            last_seen=datetime.fromisoformat(data["last_seen"]),
        )