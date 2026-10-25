"""Scan history: browse past verdicts and pivot from an indicator to every scan that saw it."""

from datetime import datetime
from typing import Annotated, Final

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from src.core.database import get_db_session
from src.models.db_models import EmailScanRecord, ExtractedIndicator, IndicatorType
from src.schemas import VerdictLevel

router = APIRouter(prefix="/api/v1/history", tags=["History"])

MAX_PAGE: Final = 200

Session = Annotated[AsyncSession, Depends(get_db_session)]
Skip = Annotated[int, Query(ge=0, description="Records to skip (newest first).")]
Limit = Annotated[int, Query(ge=1, le=MAX_PAGE, description=f"Page size, at most {MAX_PAGE}.")]


class IndicatorOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    type: IndicatorType
    value: str
    malicious_flag: bool


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
    subject: str | None
    sender: str | None
    final_verdict: VerdictLevel
    overall_risk: int
    analyst_trace: str
    indicators: list[IndicatorOut]


@router.get("/scans", response_model=list[ScanOut])
async def list_scans(
    db: Session,
    skip: Skip = 0,
    limit: Limit = 50,
    min_risk: Annotated[float, Query(ge=0, le=100, description="Only scans at or above this risk.")] = 0.0,
) -> list[EmailScanRecord]:
    """Scans, newest first, with their indicators."""
    query = (
        select(EmailScanRecord)
        .options(selectinload(EmailScanRecord.indicators))
        .where(EmailScanRecord.overall_risk >= min_risk)
        .order_by(EmailScanRecord.timestamp.desc(), EmailScanRecord.id.desc())
        .offset(skip)
        .limit(limit)
    )
    return list((await db.execute(query)).scalars().all())


@router.get("/indicators/{indicator_value:path}", response_model=list[ScanOut])
async def scans_by_indicator(
    indicator_value: str,
    db: Session,
    type: Annotated[IndicatorType | None, Query(description="Restrict to IP, URL or DOMAIN.")] = None,
    skip: Skip = 0,
    limit: Limit = 50,
) -> list[EmailScanRecord]:
    """Every scan that saw ``indicator_value`` (an IP, URL or domain): one campaign's footprint.

    ``:path`` lets a URL indicator keep its slashes; percent-encode ``?`` and ``#``.
    """
    matches = select(ExtractedIndicator.scan_id).where(ExtractedIndicator.value == indicator_value)
    if type is not None:
        matches = matches.where(ExtractedIndicator.type == type)
    query = (
        select(EmailScanRecord)
        .options(selectinload(EmailScanRecord.indicators))
        .where(EmailScanRecord.id.in_(matches))
        .order_by(EmailScanRecord.timestamp.desc(), EmailScanRecord.id.desc())
        .offset(skip)
        .limit(limit)
    )
    return list((await db.execute(query)).scalars().all())
