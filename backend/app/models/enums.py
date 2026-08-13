"""ORM model enums (stored as strings for database portability)."""

import enum


class AddressType(str, enum.Enum):
    IP = "ip"
    HOSTNAME = "hostname"


class ScanStatus(str, enum.Enum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class ScanType(str, enum.Enum):
    FULL = "full"
    PORTS = "ports"
    WEB = "web"
    TLS = "tls"
    DIRECTORIES = "directories"


class FindingSeverity(str, enum.Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FindingStatus(str, enum.Enum):
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    REMEDIATED = "REMEDIATED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
