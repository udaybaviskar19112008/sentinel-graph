import asyncio
import dataclasses
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi import WebSocketDisconnect
from fastapi.testclient import TestClient
from starlette.testclient import WebSocketTestSession

from app.main import STREAM_PATH, ConnectionManager, create_app
from src.core.config import get_settings
from src.core.orchestrator import AnalysisEngines
from tests.factories import StubSandbox, phishing_email


@pytest.fixture
def client(engines: AnalysisEngines) -> Iterator[TestClient]:
    with TestClient(create_app(engines)) as test_client:
        yield test_client


@pytest.fixture
def settings_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[pytest.MonkeyPatch]:
    """Set SOC_* variables for one test; the settings cache is reset on both sides."""
    get_settings.cache_clear()
    yield monkeypatch
    monkeypatch.undo()
    get_settings.cache_clear()


def _drain(ws: WebSocketTestSession) -> tuple[list[dict[str, Any]], int]:
    """Every event until the server closes the socket, plus the close code."""
    events: list[dict[str, Any]] = []
    while True:
        try:
            events.append(ws.receive_json())
        except WebSocketDisconnect as closed:
            return events, closed.code


def test_connection_accepts_bytes_and_replies_with_json(client: TestClient) -> None:
    email = phishing_email()

    with client.websocket_connect(STREAM_PATH) as ws:
        ws.send_bytes(email)
        first = ws.receive_json()
        rest, close_code = _drain(ws)

    assert first["phase"] == "RECEIVED" and first["bytes"] == len(email)
    assert rest[-1]["phase"] == "COMPLETE"
    assert close_code == 1000
    assert client.get("/api/v1/health").json()["active_streams"] == 0


def test_text_frames_are_rejected_with_an_error_event(client: TestClient) -> None:
    with client.websocket_connect(STREAM_PATH) as ws:
        ws.send_text("From: a@b.example")
        events, close_code = _drain(ws)

    assert events == [{"error": "send the raw email as a single binary frame"}]
    assert close_code == 1011


def test_oversized_emails_are_rejected(engines: AnalysisEngines, settings_env: pytest.MonkeyPatch) -> None:
    settings_env.setenv("SOC_MAX_EMAIL_BYTES", "100")
    get_settings.cache_clear()

    with TestClient(create_app(engines)) as client, client.websocket_connect(STREAM_PATH) as ws:
        ws.send_bytes(phishing_email())
        events, close_code = _drain(ws)

    assert "the limit is 100" in events[0]["error"]
    assert close_code == 1011


def test_pipeline_failure_reports_error_and_closes(base_engines: AnalysisEngines) -> None:
    broken = dataclasses.replace(base_engines, detonate=StubSandbox(None, error=RuntimeError("sandbox crashed")))

    with TestClient(create_app(broken)) as client, client.websocket_connect(STREAM_PATH) as ws:
        ws.send_bytes(phishing_email())
        events, close_code = _drain(ws)

    assert events[-1] == {"error": "sandbox crashed"}
    assert close_code == 1011


def test_disallowed_browser_origins_are_refused(engines: AnalysisEngines, settings_env: pytest.MonkeyPatch) -> None:
    settings_env.setenv("SOC_CORS_ALLOW_ORIGINS", '["https://soc.corp.example"]')
    get_settings.cache_clear()

    with TestClient(create_app(engines)) as client:
        with pytest.raises(WebSocketDisconnect) as refused:
            with client.websocket_connect(STREAM_PATH, headers={"origin": "https://evil.example"}):
                pass
        with client.websocket_connect(STREAM_PATH, headers={"origin": "https://soc.corp.example"}) as ws:
            ws.send_bytes(phishing_email())
            events, _ = _drain(ws)

    assert refused.value.code == 1008
    assert events[-1]["phase"] == "COMPLETE"


def test_health_reports_model_status(client: TestClient) -> None:
    body = client.get("/api/v1/health").json()

    assert body["status"] == "ok"
    assert body["models"]["slm_dummy"] is True
    assert body["models"]["zero_day_calibrated"] is True


class _RecordingSocket:
    """Minimal WebSocket double that detects overlapping sends."""

    def __init__(self) -> None:
        self.accepted = False
        self.sent: list[dict[str, Any]] = []
        self.in_flight = 0
        self.max_in_flight = 0

    async def accept(self) -> None:
        self.accepted = True

    async def send_json(self, data: dict[str, Any]) -> None:
        self.in_flight += 1
        self.max_in_flight = max(self.max_in_flight, self.in_flight)
        await asyncio.sleep(0.001)
        self.sent.append(data)
        self.in_flight -= 1


@pytest.mark.asyncio
async def test_manager_serialises_concurrent_sends_and_tracks_connections() -> None:
    manager = ConnectionManager()
    socket, other = _RecordingSocket(), _RecordingSocket()

    await manager.connect(socket)  # type: ignore[arg-type]
    await manager.connect(other)  # type: ignore[arg-type]
    await asyncio.gather(*(manager.send_telemetry({"n": n}, socket) for n in range(20)))  # type: ignore[arg-type]
    manager.disconnect(socket)  # type: ignore[arg-type]
    manager.disconnect(socket)  # type: ignore[arg-type]  # idempotent

    assert socket.accepted
    assert socket.max_in_flight == 1
    assert sorted(m["n"] for m in socket.sent) == list(range(20))
    assert manager.active_connections == [other]
