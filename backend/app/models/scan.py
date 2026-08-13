"""Scan model with lifecycle state machine."""

from datetime import datetime
from typing import TYPE_CHECKING, Optional

from sqlalchemy import DateTime, Float, ForeignKey, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.enums import ScanStatus

if TYPE_CHECKING:
    from app.models.finding import Finding
    from app.models.host import Host
    from app.models.report import Report
    from app.models.target import Target
    from app.models.user import User


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    target_id: Mapped[int] = mapped_column(
        ForeignKey("targets.id", ondelete="CASCADE"), index=True, nullable=False
    )

    status: Mapped[str] = mapped_column(String(16), default=ScanStatus.QUEUED.value, index=True)
    scan_type: Mapped[str] = mapped_column(String(32), default="full", nullable=False)
    port_range: Mapped[str] = mapped_column(String(32), default="top-1000", nullable=False)
    scan_engine: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)

    risk_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    summary_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_seconds: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    owner: Mapped["User"] = relationship(back_populates="scans")
    target: Mapped["Target"] = relationship(back_populates="scans")
    hosts: Mapped[list["Host"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    findings: Mapped[list["Finding"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    reports: Mapped[list["Report"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
