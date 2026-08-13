"""CVSS v3.1 base score calculation and severity mapping.

The implementation follows the FIRST CVSS Specification Document v3.1
(https://www.first.org/cvss/specification-document). Scores are computed from
explicit metric values; CyberSentinel never claims official CVE/CVSS data for
findings it generates — scores are estimates derived from observed evidence.

Severity mapping (CVSS v3.1 qualitative scale):
    0.0          -> INFO (severity "None")
    0.1 - 3.9    -> LOW
    4.0 - 6.9    -> MEDIUM
    7.0 - 8.9    -> HIGH
    9.0 - 10.0   -> CRITICAL
"""

import math
from dataclasses import dataclass, field
from typing import Optional

from app.models.enums import FindingSeverity

CVSS_VERSION = "3.1"

# ---------------------------------------------------------------------------
# Metric weights (CVSS v3.1)
# ---------------------------------------------------------------------------
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_IMPACT = {"N": 0.0, "L": 0.22, "H": 0.56}
_PR_SCOPE_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_SCOPE_C = {"N": 0.85, "L": 0.68, "H": 0.50}
# Exploit Code Maturity / Remediation Level / Report Confidence are optional
# temporal metrics and are intentionally not used (base score only).


@dataclass
class CVSSMetrics:
    attack_vector: str = "N"
    attack_complexity: str = "L"
    privileges_required: str = "N"
    user_interaction: str = "N"
    scope: str = "U"
    confidentiality: str = "H"
    integrity: str = "H"
    availability: str = "H"

    @property
    def vector(self) -> str:
        return (
            f"CVSS:3.1/AV:{self.attack_vector}/AC:{self.attack_complexity}/"
            f"PR:{self.privileges_required}/UI:{self.user_interaction}/"
            f"S:{self.scope}/C:{self.confidentiality}/I:{self.integrity}/"
            f"A:{self.availability}"
        )


def _roundup(value: float) -> float:
    """Round up to one decimal place, per the CVSS specification."""
    return math.ceil(value * 10 - 1e-7) / 10


def calculate_base_score(m: CVSSMetrics) -> float:
    """Compute the CVSS v3.1 base score from explicit metric values."""
    iss = 1 - (
        (1 - _IMPACT[m.confidentiality])
        * (1 - _IMPACT[m.integrity])
        * (1 - _IMPACT[m.availability])
    )

    if m.scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15

    pr = _PR_SCOPE_U[m.privileges_required] if m.scope == "U" else _PR_SCOPE_C[m.privileges_required]
    exploitability = 8.22 * _AV[m.attack_vector] * _AC[m.attack_complexity] * pr * _UI[m.user_interaction]

    if impact <= 0:
        return 0.0
    if m.scope == "U":
        return _roundup(min(impact + exploitability, 10.0))
    return _roundup(min(1.08 * (impact + exploitability), 10.0))


def severity_from_score(score: float) -> FindingSeverity:
    """Map a CVSS v3.1 base score to a qualitative severity."""
    if score <= 0.0:
        return FindingSeverity.INFO
    if score < 4.0:
        return FindingSeverity.LOW
    if score < 7.0:
        return FindingSeverity.MEDIUM
    if score < 9.0:
        return FindingSeverity.HIGH
    return FindingSeverity.CRITICAL


# Representative scores used when a finding is assigned a severity directly
# (e.g. informational checks with no exploitable impact). These are documented
# assumptions, not official CVSS data.
_DEFAULT_SCORE = {
    FindingSeverity.INFO: 0.0,
    FindingSeverity.LOW: 2.0,
    FindingSeverity.MEDIUM: 5.0,
    FindingSeverity.HIGH: 8.0,
    FindingSeverity.CRITICAL: 9.5,
}


def score_for_severity(severity: FindingSeverity) -> float:
    return _DEFAULT_SCORE[severity]


def assess_scan_risk(scores: list[float]) -> float:
    """Overall scan risk = highest CVSS score among findings (0 if none)."""
    return round(max(scores), 1) if scores else 0.0
