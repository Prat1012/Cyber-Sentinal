"""CVSS v3.1 risk scoring tests (Phase 10 / 20)."""

import pytest

from app.models.enums import FindingSeverity
from app.scanners.base import FindingData
from app.services.risk_service import (
    CVSSMetrics,
    assess_scan_risk,
    calculate_base_score,
    score_for_severity,
    severity_from_score,
)


@pytest.mark.parametrize(
    "metrics,expected",
    [
        # Classic RCE-ish vector: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H -> 9.8
        (CVSSMetrics(), 9.8),
        # All None -> 0.0
        (
            CVSSMetrics(confidentiality="N", integrity="N", availability="N"),
            0.0,
        ),
        # AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N -> 5.4 (scope changed)
        (
            CVSSMetrics(
                attack_vector="N",
                attack_complexity="L",
                privileges_required="L",
                user_interaction="R",
                scope="C",
                confidentiality="L",
                integrity="L",
                availability="N",
            ),
            5.4,
        ),
        # Physical access, low impact: AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:N -> 2.7
        (
            CVSSMetrics(
                attack_vector="P",
                attack_complexity="H",
                privileges_required="H",
                user_interaction="R",
                scope="U",
                confidentiality="L",
                integrity="L",
                availability="N",
            ),
            2.7,
        ),
    ],
)
def test_cvss_base_scores(metrics, expected):
    assert calculate_base_score(metrics) == expected
    assert metrics.vector.startswith("CVSS:3.1/AV:")


@pytest.mark.parametrize(
    "score,severity",
    [
        (0.0, FindingSeverity.INFO),
        (3.9, FindingSeverity.LOW),
        (4.0, FindingSeverity.MEDIUM),
        (6.9, FindingSeverity.MEDIUM),
        (7.0, FindingSeverity.HIGH),
        (8.9, FindingSeverity.HIGH),
        (9.0, FindingSeverity.CRITICAL),
        (10.0, FindingSeverity.CRITICAL),
    ],
)
def test_severity_mapping(score, severity):
    assert severity_from_score(score) == severity


def test_representative_scores_are_documented_and_ordered():
    assert score_for_severity(FindingSeverity.INFO) == 0.0
    assert score_for_severity(FindingSeverity.LOW) < score_for_severity(FindingSeverity.MEDIUM) < score_for_severity(FindingSeverity.HIGH) < score_for_severity(FindingSeverity.CRITICAL)


def test_finding_data_uses_representative_score_when_not_supplied():
    f = FindingData(title="t", category="c", severity=FindingSeverity.MEDIUM, description="d")
    assert f.cvss_score == score_for_severity(FindingSeverity.MEDIUM)


def test_scan_risk_is_highest_score():
    scores = [1.0, 5.5, 9.8, 2.0]
    assert assess_scan_risk(scores) == 9.8
    assert assess_scan_risk([]) == 0.0


def test_cvss_version_documented():
    from app.services import risk_service

    assert risk_service.CVSS_VERSION == "3.1"
