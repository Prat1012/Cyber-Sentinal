"""Finding engine service tests (Phase 9 / 20)."""

from app.database import SessionLocal
from app.models.enums import FindingSeverity
from app.models.finding import Finding
from app.models.target import Target
from app.models.user import User
from app.scanners.base import FindingData
from app.services.finding_service import list_findings, persist_findings


def _seed_scan(db):
    user = User(username="fuser", hashed_password="!")
    db.add(user)
    db.flush()
    target = Target(user_id=user.id, name="t", address="127.0.0.1", address_type="ip")
    db.add(target)
    db.flush()
    from app.models.scan import Scan

    scan = Scan(user_id=user.id, target_id=target.id, status="COMPLETED")
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def _make_finding(title="Missing HSTS header", component="https://127.0.0.1:443"):
    return FindingData(
        title=title,
        category="security-headers",
        severity=FindingSeverity.MEDIUM,
        description="HSTS is missing.",
        evidence="GET https://127.0.0.1:443 -> 200; header absent",
        affected_component=component,
        remediation="Configure Strict-Transport-Security.",
        reference="https://owasp.org/www-project-secure-headers/",
    )


def test_persist_findings_creates_evidence_and_remediation():
    with SessionLocal() as db:
        scan = _seed_scan(db)
        findings = persist_findings(db, scan, [_make_finding()])
        assert len(findings) == 1
        assert findings[0].status == "OPEN"
        assert findings[0].evidence_items
        assert findings[0].remediations
        assert findings[0].affected_asset == "127.0.0.1"


def test_persist_findings_deduplicates_identical_entries():
    with SessionLocal() as db:
        scan = _seed_scan(db)
        findings = persist_findings(db, scan, [_make_finding(), _make_finding()])
        assert len(findings) == 1


def test_list_findings_filters_by_severity_and_status():
    with SessionLocal() as db:
        scan = _seed_scan(db)
        persist_findings(
            db,
            scan,
            [
                _make_finding(),
                FindingData(
                    title="Expired certificate",
                    category="tls",
                    severity=FindingSeverity.HIGH,
                    description="Cert expired.",
                    evidence="x",
                    affected_component="https://127.0.0.1:443",
                    remediation="Renew.",
                ),
            ],
        )
        rows, total = list_findings(db, scan.user_id, severity="HIGH")
        assert total == 1
        assert rows[0].title == "Expired certificate"

        rows, total = list_findings(db, scan.user_id, category="security-headers")
        assert total == 1


def test_update_finding_status():
    with SessionLocal() as db:
        scan = _seed_scan(db)
        created = persist_findings(db, scan, [_make_finding()])
        finding_id = created[0].id
        db.commit()

        from app.services.finding_service import update_finding_status

        updated = update_finding_status(db, scan.user_id, finding_id, "ACKNOWLEDGED")
        assert updated.status == "ACKNOWLEDGED"

        db.expire_all()
        row = db.get(Finding, finding_id)
        assert row.status == "ACKNOWLEDGED"
