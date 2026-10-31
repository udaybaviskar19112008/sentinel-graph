"""Streaming analysis pipeline: every tier, fanned out, with telemetry at each step.

Blocking work (parsing, graph building, ONNX/Torch inference, SHAP) runs in the
threadpool; the sandbox and the SLM are natively async. The vision branch
(detonate, then embed the screenshot) and the topology branch (build the DAG,
then score it) run concurrently and report as each step lands.
"""

import asyncio
import time
import uuid
from collections.abc import Awaitable, Callable
from contextlib import aclosing, suppress
from datetime import UTC, datetime
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, Final, Protocol

from fastapi import WebSocket
from fastapi.concurrency import run_in_threadpool
from numpy import float64
from numpy.typing import NDArray
from sqlalchemy.ext.asyncio import AsyncSession

from src.cognitive.prompt_engineer import build_soc_prompt
from src.cognitive.slm_inference import CognitiveSLM, extract_verdict
from src.core.config import get_settings
from src.core.logger import bind_correlation_id, get_logger
from src.extractors.mime_parser import unpack_email
from src.extractors.url_extractor import extract_urls
from src.forensics.auth_analyzer import analyze_identity
from src.forensics.dga_detector import analyze_dga_risk
from src.forensics.nlp_heuristics import CoercionAnalyzer, visible_text
from src.forensics.route_analyzer import RoutingFindings, analyze_routing
from src.fusion.meta_scorer import FusionMetaModel
from src.fusion.xai_engine import Contribution, extract_shap_contributions
from src.models.db_models import EmailScanRecord, ExtractedIndicator, IndicatorType
from src.schemas import HeaderForensics, ThreatAssessment, TopologyForensics, VerdictLevel, VisionForensics
from src.topology.graph_builder import GraphLayout, build_email_dag, describe_email_dag
from src.topology.memae_model import GraphMemAE
from src.vision.brand_detector import VisualSpoofDetector
from src.vision.sandbox import detonate_and_capture

logger = get_logger(__name__)

Emit = Callable[[dict[str, Any]], Awaitable[None]]

_EMPTY_TRACE: Final = "The reasoning model produced no output; verdict defaulted to SUSPICIOUS."
_MAX_SENDER_CHARS: Final = 512  # EmailScanRecord.sender column width
_COERCION: Final = CoercionAnalyzer()


class TelemetrySink(Protocol):
    """Anything that can deliver a telemetry event to a socket (``app.main.ConnectionManager``)."""

    async def send_telemetry(self, message: dict[str, Any], websocket: WebSocket) -> None: ...


@dataclass(frozen=True, slots=True)
class AnalysisEngines:
    """Models loaded once per process and shared by every analysis (all are safe to share)."""

    detector: VisualSpoofDetector
    memae: GraphMemAE
    meta: FusionMetaModel
    slm: CognitiveSLM
    brands: frozenset[str]
    detonate: Callable[[str], Awaitable[bytes | None]] = field(default=detonate_and_capture)

    @classmethod
    def load(cls) -> "AnalysisEngines":
        """Load every model from ``MODELS_DIR`` (blocking; generates placeholders where missing)."""
        return cls(
            detector=VisualSpoofDetector(),
            memae=GraphMemAE(),
            meta=FusionMetaModel(),
            slm=CognitiveSLM(),
            brands=get_settings().HIGH_RISK_BRAND_KEYWORDS,
        )

    @property
    def model_status(self) -> dict[str, bool]:
        """Which engines are stand-ins; scores from those carry no meaning."""
        return {
            "vision_placeholder": self.detector.is_placeholder,
            "memae_placeholder": self.memae.is_placeholder,
            "zero_day_calibrated": self.memae.zero_day_threshold is not None,
            "fusion_dummy": self.meta.is_dummy,
            "slm_dummy": self.slm.is_dummy,
        }


@lru_cache(maxsize=1)
def default_engines() -> AnalysisEngines:
    return AnalysisEngines.load()


@dataclass(frozen=True, slots=True)
class _ProtocolFindings:
    header: HeaderForensics
    routing: RoutingFindings
    urls: list[str]
    payload_text: str
    sender: str | None  # the decoded From header, as the recipient saw it


def _protocol_forensics(raw_bytes: bytes, brands: frozenset[str]) -> _ProtocolFindings:
    message, text, html, _ = unpack_email(raw_bytes)
    identity = analyze_identity(message, brands)
    routing = analyze_routing(message)
    urls = extract_urls(html, text)
    visible_html = visible_text(html)  # parsed once: the SLM payload and the coercion score share it
    payload_text = text if text.strip() else visible_html
    sender = message.get("From")
    header = HeaderForensics(
        **identity,
        **routing,
        dga_max_entropy=analyze_dga_risk(urls),
        nlp_urgency_score=_COERCION.score_parts(text, visible_html),
    )
    return _ProtocolFindings(
        header,
        routing,
        urls,
        payload_text,
        None if sender is None else str(sender)[:_MAX_SENDER_CHARS],
    )


def _indicators(findings: _ProtocolFindings) -> list[ExtractedIndicator]:
    """Each distinct IP, URL and sender-side domain once, in the order they were found."""
    header = findings.header
    values: dict[tuple[IndicatorType, str], None] = {}
    for ip in header.extracted_ips:
        values[(IndicatorType.IP, ip)] = None
    for url in findings.urls:
        values[(IndicatorType.URL, url)] = None
    for domain in (header.from_domain, header.reply_to_domain, header.return_path_domain):
        if domain:
            values[(IndicatorType.DOMAIN, domain)] = None
    return [ExtractedIndicator(type=kind, value=value) for kind, value in values]


async def _save_scan(
    db_session: AsyncSession, findings: _ProtocolFindings, assessment: ThreatAssessment, verdict: VerdictLevel
) -> int | None:
    """Persist the scan and its indicators; return its id, or None if the database failed.

    A database fault is logged and rolled back, never raised: the analyst still gets
    the verdict even when history cannot be written.
    """
    record = EmailScanRecord(
        timestamp=datetime.now(UTC),
        subject=assessment.header_forensics.subject,
        sender=findings.sender,
        final_verdict=verdict,
        overall_risk=assessment.overall_risk,
        analyst_trace=assessment.analyst_trace,
        indicators=_indicators(findings),
    )
    try:
        db_session.add(record)
        await db_session.commit()
    except Exception:
        with suppress(Exception):  # a broken connection can fail the rollback too
            await db_session.rollback()
        logger.exception("Scan could not be saved to history", extra={"event": "history.save_failed"})
        return None
    logger.info(
        "Scan saved to history",
        extra={"event": "history.saved", "scan_id": record.id, "indicators": len(record.indicators)},
    )
    return record.id


async def _vision_branch(urls: list[str], engines: AnalysisEngines, emit: Emit) -> VisionForensics | None:
    if not urls:
        await emit({"phase": "VISION", "status": "No URL to detonate"})
        return None
    target = urls[0]  # the first link is the lure in almost every campaign
    await emit({"phase": "VISION", "status": "Sandbox detonation started", "url": target})
    screenshot = await engines.detonate(target)
    await emit(
        {"phase": "VISION", "status": "Sandbox detonation finished", "url": target, "captured": screenshot is not None}
    )
    if screenshot is None:
        return None
    vision = await run_in_threadpool(engines.detector.analyze_screenshot, screenshot)
    await emit({"phase": "VISION", "status": "Visual embedding complete", "findings": vision.model_dump(mode="json")})
    return vision


async def _topology_branch(
    routing: RoutingFindings, urls: list[str], engines: AnalysisEngines, emit: Emit
) -> tuple[TopologyForensics, GraphLayout]:
    dag = await run_in_threadpool(build_email_dag, routing, urls)
    layout = describe_email_dag(dag, urls)
    # The dashboard can draw the route as soon as it exists, before it is scored.
    await emit(
        {"phase": "TOPOLOGY", "status": "Delivery graph built", "nodes": int(dag.num_nodes), "graph_layout": layout}
    )
    loss = await run_in_threadpool(engines.memae.compute_anomaly_loss, dag)
    topology = TopologyForensics(
        graph_nodes_count=int(dag.num_nodes),
        memae_reconstruction_loss=loss,
        is_zero_day_route=engines.memae.is_zero_day(loss),
    )
    await emit({"phase": "TOPOLOGY", "status": "Graph anomaly scored", "findings": topology.model_dump(mode="json")})
    return topology, layout


def _score(meta: FusionMetaModel, features: NDArray[float64]) -> tuple[float, list[Contribution]]:
    return meta.predict_risk(features), extract_shap_contributions(meta, features)


async def stream_analysis_pipeline(
    raw_bytes: bytes,
    websocket: WebSocket,
    manager: TelemetrySink,
    *,
    engines: AnalysisEngines | None = None,
    db_session: AsyncSession | None = None,
) -> ThreatAssessment:
    """Run every tier on ``raw_bytes``, streaming telemetry to ``websocket``; return the assessment.

    Every event carries ``analysis_id`` (also the log correlation id) and ``elapsed_ms``.
    The last one is ``{"phase": "COMPLETE", ...}`` with the assessment, verdict, SHAP
    contributions, which engines are placeholders, and ``scan_id``: the history record,
    when ``db_session`` is given and the save succeeded (otherwise null).
    """
    if engines is None:
        engines = await run_in_threadpool(default_engines)
    analysis_id = uuid.uuid4().hex
    started = time.perf_counter()

    async def emit(event: dict[str, Any]) -> None:
        elapsed_ms = round((time.perf_counter() - started) * 1000, 1)
        await manager.send_telemetry({**event, "analysis_id": analysis_id, "elapsed_ms": elapsed_ms}, websocket)

    with bind_correlation_id(analysis_id):
        await emit({"phase": "RECEIVED", "bytes": len(raw_bytes)})

        findings = await run_in_threadpool(_protocol_forensics, raw_bytes, engines.brands)
        await emit(
            {
                "phase": "TIER_1",
                "status": "Protocol Forensics Complete",
                "findings": findings.header.model_dump(mode="json"),
                "url_count": len(findings.urls),
            }
        )

        vision, (topology, graph_layout) = await asyncio.gather(
            _vision_branch(findings.urls, engines, emit),
            _topology_branch(findings.routing, findings.urls, engines, emit),
        )

        prompt = build_soc_prompt(
            findings.payload_text, {"header": findings.header, "vision": vision, "topology": topology}
        )
        chunks: list[str] = []
        async with aclosing(engines.slm.stream_reasoning(prompt)) as reasoning:
            async for chunk in reasoning:
                chunks.append(chunk)
                await emit({"phase": "SLM_REASONING", "token": chunk})
        trace = "".join(chunks).strip()
        verdict: VerdictLevel = extract_verdict(trace)
        await emit({"phase": "SLM_VERDICT", "verdict": verdict})

        features = FusionMetaModel._build_feature_vector(
            findings.header.model_dump(),
            vision.model_dump() if vision is not None else {},
            topology.model_dump(),
            verdict,
        )
        risk, contributions = await run_in_threadpool(_score, engines.meta, features)
        assessment = ThreatAssessment(
            header_forensics=findings.header,
            vision_forensics=vision,
            topology_forensics=topology,
            overall_risk=round(risk * 100),
            analyst_trace=trace or _EMPTY_TRACE,
        )
        scan_id = None if db_session is None else await _save_scan(db_session, findings, assessment, verdict)
        await emit(
            {
                "phase": "COMPLETE",
                "assessment": assessment.model_dump(mode="json"),
                "verdict": verdict,
                "risk_probability": risk,
                "contributions": contributions,
                "model_status": engines.model_status,
                "graph_layout": graph_layout,
                "scan_id": scan_id,
            }
        )
        logger.info(
            "Analysis complete",
            extra={
                "event": "analysis.complete",
                "overall_risk": assessment.overall_risk,
                "verdict": verdict,
                "elapsed_ms": round((time.perf_counter() - started) * 1000),
            },
        )
        return assessment
