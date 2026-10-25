"""ORM tables for scan history and the indicators each scan extracted."""

from datetime import UTC, datetime
from enum import StrEnum

from sqlalchemy import CheckConstraint, DateTime, Dialect, Enum, ForeignKey, Index, String, Text, TypeDecorator
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from src.schemas import VerdictLevel


class IndicatorType(StrEnum):
    IP = "IP"
    URL = "URL"
    DOMAIN = "DOMAIN"


class UTCDateTime(TypeDecorator[datetime]):
    """Stores UTC and always reads back timezone-aware (SQLite would otherwise drop the zone)."""

    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("naive datetimes are ambiguous; pass a timezone-aware value")
        return value.astimezone(UTC).replace(tzinfo=None)

    def process_result_value(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        return None if value is None else value.replace(tzinfo=UTC)


def _utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


class EmailScanRecord(Base):
    """One analysed email and its final verdict."""

    __tablename__ = "email_scans"
    __table_args__ = (CheckConstraint("overall_risk BETWEEN 0 AND 100", name="ck_email_scans_risk_range"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(UTCDateTime(), default=_utcnow, index=True)
    subject: Mapped[str | None] = mapped_column(Text)
    sender: Mapped[str | None] = mapped_column(String(512))
    final_verdict: Mapped[VerdictLevel] = mapped_column(Enum(VerdictLevel, native_enum=False, length=16))
    overall_risk: Mapped[int]
    analyst_trace: Mapped[str] = mapped_column(Text)

    indicators: Mapped[list["ExtractedIndicator"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", lazy="selectin"
    )


class ExtractedIndicator(Base):
    """An IP, URL or domain seen in a scan, for pivoting across scans."""

    __tablename__ = "extracted_indicators"
    __table_args__ = (Index("ix_extracted_indicators_lookup", "type", "value"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("email_scans.id", ondelete="CASCADE"), index=True)
    type: Mapped[IndicatorType] = mapped_column(Enum(IndicatorType, native_enum=False, length=8))
    value: Mapped[str] = mapped_column(Text)
    malicious_flag: Mapped[bool] = mapped_column(default=False)

    scan: Mapped[EmailScanRecord] = relationship(back_populates="indicators")
