from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker
from sqlalchemy.pool import StaticPool

from src.core.config import get_settings
from src.core.database import close_db, get_db_session, init_db, make_engine
from src.models.db_models import EmailScanRecord, ExtractedIndicator, IndicatorType
from src.schemas import VerdictLevel


@pytest_asyncio.fixture
async def engine() -> AsyncIterator[AsyncEngine]:
    # StaticPool: every session shares the one connection, so ":memory:" is one database.
    memory = make_engine("sqlite+aiosqlite:///:memory:", poolclass=StaticPool)
    await init_db(memory)
    yield memory
    await memory.dispose()


@pytest_asyncio.fixture
async def session(engine: AsyncEngine) -> AsyncIterator[AsyncSession]:
    async with async_sessionmaker(engine, expire_on_commit=False)() as db_session:
        yield db_session


def _scan(**overrides: object) -> EmailScanRecord:
    values: dict[str, object] = {
        "subject": "Your Apple ID is locked",
        "sender": '"Apple Support" <hacker@evil.com>',
        "final_verdict": VerdictLevel.CRITICAL,
        "overall_risk": 92,
        "analyst_trace": "Spoofed sender, private hop, DMARC fail. VERDICT: CRITICAL",
        "indicators": [
            ExtractedIndicator(type=IndicatorType.IP, value="185.220.101.4", malicious_flag=True),
            ExtractedIndicator(type=IndicatorType.URL, value="https://secure-apple-id.invalid/login", malicious_flag=True),
            ExtractedIndicator(type=IndicatorType.DOMAIN, value="evil.com"),
        ],
    }
    return EmailScanRecord(**{**values, **overrides})


@pytest.mark.asyncio
async def test_insert_scan_and_query_it_back(session: AsyncSession) -> None:
    session.add(_scan())
    await session.commit()
    session.expunge_all()  # force a real read

    loaded = (await session.execute(select(EmailScanRecord))).scalar_one()

    assert loaded.id is not None
    assert loaded.subject == "Your Apple ID is locked"
    assert loaded.final_verdict is VerdictLevel.CRITICAL
    assert loaded.overall_risk == 92
    assert loaded.timestamp.tzinfo is not None
    assert datetime.now(UTC) - loaded.timestamp < timedelta(minutes=1)
    assert sorted((i.type, i.value, i.malicious_flag) for i in loaded.indicators) == [
        (IndicatorType.DOMAIN, "evil.com", False),
        (IndicatorType.IP, "185.220.101.4", True),
        (IndicatorType.URL, "https://secure-apple-id.invalid/login", True),
    ]


@pytest.mark.asyncio
async def test_indicator_pivot_finds_every_scan_that_saw_an_ip(session: AsyncSession) -> None:
    session.add_all([_scan(), _scan(subject="Second wave"), _scan(subject="Unrelated", indicators=[])])
    await session.commit()

    subjects = (
        await session.execute(
            select(EmailScanRecord.subject)
            .join(ExtractedIndicator)
            .where(ExtractedIndicator.type == IndicatorType.IP, ExtractedIndicator.value == "185.220.101.4")
            .order_by(EmailScanRecord.id)
        )
    ).scalars().all()

    assert subjects == ["Your Apple ID is locked", "Second wave"]


@pytest.mark.asyncio
async def test_deleting_a_scan_cascades_to_its_indicators(session: AsyncSession) -> None:
    scan = _scan()
    session.add(scan)
    await session.commit()

    await session.delete(scan)
    await session.commit()

    assert (await session.execute(select(ExtractedIndicator))).scalars().all() == []


@pytest.mark.asyncio
async def test_foreign_keys_are_enforced(session: AsyncSession) -> None:
    session.add(ExtractedIndicator(scan_id=999, type=IndicatorType.IP, value="10.0.0.1"))

    with pytest.raises(IntegrityError):
        await session.commit()


@pytest.mark.asyncio
async def test_risk_outside_0_to_100_is_rejected(session: AsyncSession) -> None:
    session.add(_scan(overall_risk=150, indicators=[]))

    with pytest.raises(IntegrityError):
        await session.commit()


@pytest.mark.asyncio
async def test_timestamps_round_trip_as_utc(session: AsyncSession) -> None:
    ist = timezone(timedelta(hours=5, minutes=30))
    session.add(_scan(timestamp=datetime(2026, 10, 26, 9, 0, tzinfo=ist), indicators=[]))
    await session.commit()
    session.expunge_all()

    loaded = (await session.execute(select(EmailScanRecord))).scalar_one()

    assert loaded.timestamp == datetime(2026, 10, 26, 3, 30, tzinfo=UTC)


@pytest.mark.asyncio
async def test_naive_timestamps_are_refused(session: AsyncSession) -> None:
    session.add(_scan(timestamp=datetime(2026, 10, 26, 9, 0), indicators=[]))

    with pytest.raises(Exception, match="timezone-aware"):
        await session.commit()


@pytest.mark.asyncio
async def test_get_db_session_dependency_uses_configured_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SOC_DATABASE_URL", f"sqlite+aiosqlite:///{(tmp_path / 'scans.db').as_posix()}")
    get_settings.cache_clear()
    await close_db()
    try:
        await init_db()
        async for db in get_db_session():
            db.add(_scan(indicators=[]))
            await db.commit()
        async for db in get_db_session():
            count = len((await db.execute(select(EmailScanRecord))).scalars().all())
    finally:
        await close_db()
        monkeypatch.undo()
        get_settings.cache_clear()

    assert count == 1
    assert (tmp_path / "scans.db").is_file()
