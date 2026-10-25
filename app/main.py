"""Real-time analysis API: one WebSocket per email, with telemetry streamed per tier.

    uvicorn app.main:app

Protocol: connect to ``/ws/api/v1/stream-analysis``, send the raw RFC 5322 message
as one binary frame, then read JSON events until ``{"phase": "COMPLETE", ...}`` or
``{"error": ...}``. The server closes the socket after either.
"""

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress
from typing import Any, Final

from fastapi import Depends, FastAPI, WebSocket, WebSocketDisconnect, status
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.routers import history
from src.core.config import get_settings
from src.core.database import close_db, get_db_session, init_db
from src.core.logger import configure_logging, get_logger, shutdown_logging
from src.core.orchestrator import AnalysisEngines, stream_analysis_pipeline

logger = get_logger(__name__)

STREAM_PATH: Final = "/ws/api/v1/stream-analysis"


class ConnectionManager:
    """Tracks open analysis sockets and serialises writes to each one.

    The vision and topology branches report concurrently; without a per-socket lock
    their sends could interleave on one connection.
    """

    def __init__(self) -> None:
        self.active_connections: list[WebSocket] = []
        # Keyed by id(): Starlette connections compare (and hash) like the mappings they are.
        self._send_locks: dict[int, asyncio.Lock] = {}

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections.append(websocket)
        self._send_locks[id(websocket)] = asyncio.Lock()

    def disconnect(self, websocket: WebSocket) -> None:
        self.active_connections = [ws for ws in self.active_connections if ws is not websocket]
        self._send_locks.pop(id(websocket), None)

    async def send_telemetry(self, message: dict[str, Any], websocket: WebSocket) -> None:
        lock = self._send_locks.setdefault(id(websocket), asyncio.Lock())
        async with lock:
            await websocket.send_json(message)


def _origin_allowed(origin: str | None, allowed: list[str]) -> bool:
    # Browsers always send Origin on a WebSocket handshake; tools such as curl or a
    # Python client usually do not, and cannot be cross-site attacks.
    return origin is None or "*" in allowed or origin in allowed


async def _receive_email(websocket: WebSocket, max_bytes: int) -> bytes:
    message = await websocket.receive()
    if message["type"] == "websocket.disconnect":
        raise WebSocketDisconnect(message.get("code", status.WS_1000_NORMAL_CLOSURE))
    raw_bytes = message.get("bytes")
    if raw_bytes is None:
        raise ValueError("send the raw email as a single binary frame")
    if len(raw_bytes) > max_bytes:
        raise ValueError(f"email is {len(raw_bytes)} bytes; the limit is {max_bytes}")
    return bytes(raw_bytes)


def create_app(engines: AnalysisEngines | None = None) -> FastAPI:
    """Build the API. Without ``engines``, models load from ``MODELS_DIR`` at startup."""
    settings = get_settings()
    manager = ConnectionManager()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        owns_logging = engines is None
        if owns_logging:
            configure_logging()
        # Model loading is blocking (ONNX sessions, torch); keep the loop free while it runs.
        app.state.engines = engines if engines is not None else await run_in_threadpool(AnalysisEngines.load)
        # The engine is created (and later disposed) on this app's own event loop.
        await init_db()
        try:
            yield
        finally:
            await close_db()
            if owns_logging:
                shutdown_logging()

    app = FastAPI(title="SOC Analysis Stream", lifespan=lifespan)
    app.add_middleware(
        CORSMiddleware, allow_origins=settings.CORS_ALLOW_ORIGINS, allow_methods=["*"], allow_headers=["*"]
    )
    app.state.manager = manager
    app.include_router(history.router)

    @app.get("/api/v1/health")
    async def health() -> dict[str, Any]:
        engines_: AnalysisEngines = app.state.engines
        return {"status": "ok", "models": engines_.model_status, "active_streams": len(manager.active_connections)}

    @app.websocket(STREAM_PATH)
    async def stream_analysis(websocket: WebSocket, db_session: AsyncSession = Depends(get_db_session)) -> None:
        current = get_settings()
        if not _origin_allowed(websocket.headers.get("origin"), current.CORS_ALLOW_ORIGINS):
            logger.warning(
                "WebSocket from a disallowed origin refused",
                extra={"event": "api.origin_refused", "origin": websocket.headers.get("origin")},
            )
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
        await manager.connect(websocket)
        try:
            raw_bytes = await _receive_email(websocket, current.MAX_EMAIL_BYTES)
            await stream_analysis_pipeline(
                raw_bytes, websocket, manager, engines=app.state.engines, db_session=db_session
            )
            await websocket.close(code=status.WS_1000_NORMAL_CLOSURE)
        except WebSocketDisconnect:
            logger.info("Client disconnected mid-analysis", extra={"event": "api.client_disconnected"})
        except Exception as exc:
            logger.exception("Analysis failed", extra={"event": "api.analysis_failed"})
            with suppress(Exception):  # the socket may already be unusable
                await manager.send_telemetry({"error": str(exc)}, websocket)
                await websocket.close(code=status.WS_1011_INTERNAL_ERROR)
        finally:
            manager.disconnect(websocket)

    return app


app = create_app()
