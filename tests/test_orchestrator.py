import dataclasses
import hashlib
import json
from collections.abc import AsyncGenerator, AsyncIterator
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio
from fastapi import WebSocket
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.pool import StaticPool

from src.cognitive.slm_inference import DUMMY_REASONING
from src.core.database import init_db, make_engine
from src.core.logger import LOG_FILE_NAME, configure_logging, shutdown_logging
from src.core.orchestrator import AnalysisEngines, stream_analysis_pipeline
from src.models.db_models import EmailScanRecord, IndicatorType
from src.schemas import ThreatAssessment
from tests.factories import LURE_URL, StubSandbox, noise_png, phishing_email

SOCKET: Any = object()  # passed through to the sink untouched


class RecordingSink:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    async def send_telemetry(self, message: dict[str, Any], websocket: WebSocket) -> None:
        assert websocket is SOCKET
        self.events.append(json.loads(json.dumps(message)))  # must survive the wire as JSON

    def status_index(self, status: str) -> int:
        return next(i for i, event in enumerate(self.events) if event.get("status") == status)


async def _run(engines: AnalysisEngines, raw: bytes | None = None) -> tuple[ThreatAssessment, RecordingSink]:
    sink = RecordingSink()
    assessment = await stream_analysis_pipeline(raw or phishing_email(), SOCKET, sink, engines=engines)
    return assessment, sink


@pytest.mark.asyncio
async def test_events_stream_in_tier_order_with_one_analysis_id(engines: AnalysisEngines) -> None:
    _, sink = await _run(engines)

    phases = [event.get("phase") for event in sink.events]
    assert phases[:2] == ["RECEIVED", "TIER_1"]
    assert sink.events[1]["status"] == "Protocol Forensics Complete"
    tokens = [i for i, phase in enumerate(phases) if phase == "SLM_REASONING"]
    branch = [i for i, phase in enumerate(phases) if phase in {"VISION", "TOPOLOGY"}]
    assert max(branch) < min(tokens)  # reasoning starts once both branches have reported
    assert tokens == list(range(tokens[0], tokens[-1] + 1))
    assert "".join(sink.events[i]["token"] for i in tokens) == DUMMY_REASONING
    assert phases[-2:] == ["SLM_VERDICT", "COMPLETE"]
    assert len({event["analysis_id"] for event in sink.events}) == 1
    elapsed = [event["elapsed_ms"] for event in sink.events]
    assert elapsed == sorted(elapsed)


@pytest.mark.asyncio
async def test_complete_payload_is_a_valid_threat_assessment(engines: AnalysisEngines) -> None:
    assessment, sink = await _run(engines)
    complete = sink.events[-1]

    wire = ThreatAssessment.model_validate_json(json.dumps(complete["assessment"]))
    assert wire == assessment
    header = assessment.header_forensics
    assert (header.spf, header.dmarc, header.impersonated_brand) == ("fail", "fail", "apple")
    assert header.private_ip_leak is True and header.route_hop_count == 3
    assert assessment.vision_forensics is not None
    assert assessment.vision_forensics.screenshot_hash == hashlib.sha256(noise_png()).hexdigest()
    assert assessment.topology_forensics is not None
    assert assessment.topology_forensics.graph_nodes_count == 1 + 3 + 1 + 1
    assert 0 <= assessment.overall_risk <= 100
    assert assessment.overall_risk == round(complete["risk_probability"] * 100)
    assert assessment.analyst_trace == DUMMY_REASONING
    assert complete["verdict"] == "CRITICAL"
    assert complete["contributions"] and {"feature_name", "percentage", "subsystem", "impact"} <= set(
        complete["contributions"][0]
    )
    layout = complete["graph_layout"]
    assert [node["kind"] for node in layout["nodes"]] == ["SENDER", "RELAY_HOP", "RELAY_HOP", "RELAY_HOP", "RECEIVER", "URL"]
    assert layout["nodes"][-1]["label"] == LURE_URL
    assert len(layout["edges"]) == 5
    built = sink.events[sink.status_index("Delivery graph built")]
    assert built["graph_layout"] == layout  # the graph reaches the dashboard before scoring finishes
    assert complete["model_status"] == {
        "vision_placeholder": True,
        "memae_placeholder": True,
        "zero_day_calibrated": True,
        "fusion_dummy": True,
        "slm_dummy": True,
    }


@pytest.mark.asyncio
async def test_first_url_is_detonated_and_branches_run_concurrently(
    engines: AnalysisEngines, sandbox: StubSandbox
) -> None:
    sandbox.delay_s = 0.5

    _, sink = await _run(engines)

    assert sandbox.urls == [LURE_URL]
    # Topology finished while the (slow) sandbox was still detonating.
    assert sink.status_index("Graph anomaly scored") < sink.status_index("Sandbox detonation finished")
    assert sink.status_index("Sandbox detonation finished") < sink.status_index("Visual embedding complete")


@pytest.mark.asyncio
async def test_email_without_urls_skips_detonation(engines: AnalysisEngines, sandbox: StubSandbox) -> None:
    assessment, sink = await _run(engines, phishing_email(with_url=False))

    assert sandbox.urls == []
    assert assessment.vision_forensics is None
    assert any(event.get("status") == "No URL to detonate" for event in sink.events)
    assert sink.events[-1]["phase"] == "COMPLETE"


@pytest.mark.asyncio
async def test_failed_detonation_leaves_vision_empty(base_engines: AnalysisEngines) -> None:
    engines = dataclasses.replace(base_engines, detonate=StubSandbox(None))

    assessment, sink = await _run(engines)

    finished = sink.events[sink.status_index("Sandbox detonation finished")]
    assert finished["captured"] is False
    assert assessment.vision_forensics is None


@pytest.mark.asyncio
async def test_prompt_carries_every_tier_and_payload(
    engines: AnalysisEngines, monkeypatch: pytest.MonkeyPatch
) -> None:
    prompts: list[str] = []

    async def capture(prompt: str) -> AsyncGenerator[str, None]:
        prompts.append(prompt)
        yield "Spoofed Apple sender. VERDICT: PHISHING"

    monkeypatch.setattr(engines.slm, "stream_reasoning", capture)

    _, sink = await _run(engines)

    (prompt,) = prompts
    assert '"impersonated_brand":"apple"' in prompt
    assert '"topology":{' in prompt and '"vision":{' in prompt
    assert "[PAYLOAD]: Your Apple ID is locked. Unlock" in prompt
    assert sink.events[-1]["verdict"] == "PHISHING"


@pytest.mark.asyncio
async def test_threadpool_work_logs_under_the_analysis_id(engines: AnalysisEngines, tmp_path: Path) -> None:
    shutdown_logging()
    configure_logging(log_dir=tmp_path, level="DEBUG")
    try:
        _, sink = await _run(engines)
    finally:
        shutdown_logging()

    records = [json.loads(line) for line in (tmp_path / LOG_FILE_NAME).read_text("utf-8").splitlines()]
    analysis_id = sink.events[0]["analysis_id"]
    for event in ("mime.unpacked", "auth.identity_analyzed", "route.analyzed", "analysis.complete"):
        (record,) = [r for r in records if r.get("event") == event]
        assert record["correlation_id"] == analysis_id, event


# --- scan history ---------------------------------------------------------------


@pytest_asyncio.fixture
async def db_session() -> AsyncIterator[AsyncSession]:
    engine = make_engine("sqlite+aiosqlite:///:memory:", poolclass=StaticPool)
    await init_db(engine)
    async with async_sessionmaker(engine, expire_on_commit=False)() as session:
        yield session
    await engine.dispose()


@pytest.mark.asyncio
async def test_completed_scan_is_saved_with_its_indicators(engines: AnalysisEngines, db_session: AsyncSession) -> None:
    sink = RecordingSink()
    assessment = await stream_analysis_pipeline(phishing_email(), SOCKET, sink, engines=engines, db_session=db_session)

    complete = sink.events[-1]
    record = (await db_session.execute(select(EmailScanRecord))).scalar_one()
    assert complete["scan_id"] == record.id
    assert record.subject == "Your Apple ID is locked"
    assert record.sender is not None and "hacker@evil.com" in record.sender
    assert record.final_verdict == complete["verdict"]
    assert (record.overall_risk, record.analyst_trace) == (assessment.overall_risk, assessment.analyst_trace)
    assert [(i.type, i.value) for i in record.indicators] == [
        (IndicatorType.IP, "185.220.101.4"),
        (IndicatorType.IP, "10.0.0.1"),
        (IndicatorType.IP, "40.107.22.55"),
        (IndicatorType.URL, LURE_URL),
        (IndicatorType.DOMAIN, "evil.com"),
    ]


class _BrokenSession:
    """Fails every commit, as a locked or unreachable database would."""

    def __init__(self) -> None:
        self.rolled_back = False

    def add(self, record: object) -> None:
        pass

    async def commit(self) -> None:
        raise RuntimeError("database is locked")

    async def rollback(self) -> None:
        self.rolled_back = True


@pytest.mark.asyncio
async def test_database_failure_still_delivers_the_verdict(engines: AnalysisEngines) -> None:
    sink, broken = RecordingSink(), _BrokenSession()

    await stream_analysis_pipeline(phishing_email(), SOCKET, sink, engines=engines, db_session=broken)  # type: ignore[arg-type]

    assert sink.events[-1]["phase"] == "COMPLETE"
    assert sink.events[-1]["scan_id"] is None
    assert broken.rolled_back


@pytest.mark.asyncio
async def test_no_session_means_no_history(engines: AnalysisEngines) -> None:
    _, sink = await _run(engines)

    assert sink.events[-1]["scan_id"] is None
