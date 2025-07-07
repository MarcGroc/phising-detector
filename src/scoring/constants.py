from enum import IntEnum, StrEnum


class ImpactScore(IntEnum):
    """Classification of impact score for each analysis module"""
    # General
    ZERO = 0
    LOW = 15
    MEDIUM = 30
    HIGH = 60
    CRITICAL = 90

    # Redirect check
    REDIRECTED = 10

    # SSL cert check
    SSL_HOSTNAME_MISMATCH = 50
    SSL_SELF_SIGNED = 40
    SSL_EXPIRED = 40
    SSL_NO_HTTPS = 30
    SSL_NOT_YET_VALID = 15
    SSL_FETCH_FAILED = 15

class RiskLevel(StrEnum):
    """Human-readable risk levels"""
    MINIMAL = "Minimal"
    LOW ="Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"