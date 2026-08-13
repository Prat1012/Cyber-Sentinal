"""Finding, Evidence and Remediation models.

Findings use a unified vulnerability format (title, category, severity, CVSS,
description, evidence, affected component, remediation, reference).
"""

from datetime import datetime
from typing import TYPE_CHECKING, Optional

from sqlalchemy import DateTime, Float, ForeignKey, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.enums import FindingSeverity, FindingStatus

if TYPE_CHECKING:
    from app.models.host import Host
    from app.models.scan import Scan


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True, nullable=False
    )
    host_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("hosts.id", ondelete="CASCADE"), index=True, nullable=True
    )

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    category: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    severity: Mapped[str] = mapped_column(
        String(16), default=FindingSeverity.INFO.value, index=True, nullable=False
    )
    cvss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)

    description: Mapped[str] = mapped_column(Text, nullable=False)
    evidence: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    affected_component: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    affected_asset: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    remediation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    reference: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    status: Mapped[str] = mapped_column(
        String(16), default=FindingStatus.OPEN.value, index=True, nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    scan: Mapped["Scan"] = relationship(back_populates="findings")
    host: Mapped[Optional["Host"]] = relationship(back_populates="findings")
    evidence_items: Mapped[list["Evidence"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )
    remediations: Mapped[list["Remediation"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), index=True, nullable=False
    )
    detail_json: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    finding: Mapped["Finding"] = relationship(back_populates="evidence_items")


class Remediation(Base):
    __tablename__ = "remediations"

    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), index=True, nullable=False
    )
    action: Mapped[str] = mapped_column(Text, nullable=False)
    steps: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    finding: Mapped["Finding"] = relationship(back_populates="remediations")
