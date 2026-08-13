"""Host, Port and Service models discovered during a scan."""

from typing import TYPE_CHECKING, Optional

from sqlalchemy import Boolean, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base

if TYPE_CHECKING:
    from app.models.finding import Finding
    from app.models.scan import Scan


class Host(Base):
    __tablename__ = "hosts"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True, nullable=False
    )
    ip_address: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="up", nullable=False)
    os_guess: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    mac_address: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    is_local: Mapped[bool] = mapped_column(Boolean, default=False)

    scan: Mapped["Scan"] = relationship(back_populates="hosts")
    ports: Mapped[list["Port"]] = relationship(
        back_populates="host", cascade="all, delete-orphan"
    )
    findings: Mapped[list["Finding"]] = relationship(back_populates="host")


class Port(Base):
    __tablename__ = "ports"

    id: Mapped[int] = mapped_column(primary_key=True)
    host_id: Mapped[int] = mapped_column(
        ForeignKey("hosts.id", ondelete="CASCADE"), index=True, nullable=False
    )
    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True, nullable=False
    )
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(8), default="tcp", nullable=False)
    state: Mapped[str] = mapped_column(String(16), default="open", nullable=False)
    service: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    product: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    version: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    extra_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    host: Mapped["Host"] = relationship(back_populates="ports")
    service_detail: Mapped[Optional["Service"]] = relationship(
        back_populates="port", cascade="all, delete-orphan", uselist=False
    )


class Service(Base):
    __tablename__ = "services"

    id: Mapped[int] = mapped_column(primary_key=True)
    port_id: Mapped[int] = mapped_column(
        ForeignKey("ports.id", ondelete="CASCADE"), unique=True, nullable=False
    )
    name: Mapped[str] = mapped_column(String(64), nullable=False)
    product: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    version: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    cpe: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    extra_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    port: Mapped["Port"] = relationship(back_populates="service_detail")
