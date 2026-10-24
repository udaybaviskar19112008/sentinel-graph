"""Structured JSON logging for SIEM ingestion.

Records are rendered to one line of JSON on the caller's thread (so per-task
context such as the correlation id is captured), then handed through a queue to
a listener thread that owns all file I/O. Logging from the event loop therefore
never blocks on disk.

Entrypoints call ``configure_logging()`` once; modules only call ``get_logger``.
"""

import atexit
import json
import logging
import queue
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from logging.handlers import QueueHandler, QueueListener, RotatingFileHandler
from pathlib import Path
from typing import Any, Final

from pydantic import BaseModel

from src.core.config import get_settings

APP_LOGGER_NAME: Final = "soc"
LOG_FILE_NAME: Final = "system.log"

correlation_id: ContextVar[str | None] = ContextVar("soc_correlation_id", default=None)

_RESERVED_ATTRS: Final[frozenset[str]] = frozenset(
    vars(logging.LogRecord("", logging.INFO, "", 0, "", None, None))
) | {"message", "asctime"}


def _json_default(value: object) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, (set, frozenset)):
        return sorted(value, key=str)
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, (bytes, bytearray, memoryview)):
        # Never spill raw (possibly malicious) payloads into the SIEM.
        return {"type": type(value).__name__, "length": len(value)}
    return repr(value)


class JsonFormatter(logging.Formatter):
    """Render each record as a single NDJSON line."""

    def format(self, record: logging.LogRecord) -> str:
        document: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(
                timespec="milliseconds"
            ),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
            "process": record.process,
            "thread": record.threadName,
        }
        if record.taskName is not None:
            document["task"] = record.taskName
        if (cid := correlation_id.get()) is not None:
            document["correlation_id"] = cid
        if record.exc_info and record.exc_info[1] is not None:
            exc = record.exc_info[1]
            document["exception"] = {
                "type": type(exc).__qualname__,
                "message": str(exc),
                "stacktrace": self.formatException(record.exc_info),
            }
        if record.stack_info:
            document["stack"] = self.formatStack(record.stack_info)

        extras = {
            key: value
            for key, value in vars(record).items()
            if key not in _RESERVED_ATTRS and key not in document
        }
        document.update(extras)
        try:
            return json.dumps(document, default=_json_default, separators=(",", ":"))
        except (TypeError, ValueError):
            # e.g. a circular structure in ``extra``: keep the event, degrade the extras.
            document.update({key: repr(value) for key, value in extras.items()})
            return json.dumps(document, default=repr, separators=(",", ":"))


@dataclass(slots=True)
class _Pipeline:
    listener: QueueListener
    queue_handler: QueueHandler
    file_handler: logging.Handler
    log_path: Path


_lock = threading.Lock()
_pipeline: _Pipeline | None = None


def configure_logging(*, log_dir: Path | None = None, level: str | int | None = None) -> Path:
    """Attach the JSON pipeline to the ``soc`` logger (idempotent); return the log file path."""
    global _pipeline
    with _lock:
        if _pipeline is not None:
            return _pipeline.log_path

        settings = get_settings()
        target_dir = log_dir if log_dir is not None else settings.LOG_DIR
        target_dir.mkdir(parents=True, exist_ok=True)
        log_path = target_dir / LOG_FILE_NAME

        file_handler = RotatingFileHandler(
            log_path,
            maxBytes=settings.LOG_MAX_BYTES,
            backupCount=settings.LOG_BACKUP_COUNT,
            encoding="utf-8",
        )
        # The record already carries its JSON line by the time it reaches this handler.
        file_handler.setFormatter(logging.Formatter("%(message)s"))

        log_queue: queue.Queue[logging.LogRecord] = queue.Queue()
        queue_handler = QueueHandler(log_queue)
        queue_handler.setFormatter(JsonFormatter())
        listener = QueueListener(log_queue, file_handler, respect_handler_level=True)
        listener.start()

        app_logger = logging.getLogger(APP_LOGGER_NAME)
        app_logger.addHandler(queue_handler)
        app_logger.setLevel(level if level is not None else settings.LOG_LEVEL)
        app_logger.propagate = False

        _pipeline = _Pipeline(listener, queue_handler, file_handler, log_path)
        return log_path


def shutdown_logging() -> None:
    """Drain queued records to disk and detach the pipeline (idempotent)."""
    global _pipeline
    with _lock:
        if _pipeline is None:
            return
        _pipeline.listener.stop()
        app_logger = logging.getLogger(APP_LOGGER_NAME)
        app_logger.removeHandler(_pipeline.queue_handler)
        app_logger.setLevel(logging.NOTSET)
        app_logger.propagate = True
        _pipeline.file_handler.close()
        _pipeline = None


atexit.register(shutdown_logging)


def get_logger(name: str) -> logging.Logger:
    """Return a child of the ``soc`` logger; a leading ``src.`` package prefix is dropped."""
    return logging.getLogger(f"{APP_LOGGER_NAME}.{name.removeprefix('src.')}")


@contextmanager
def bind_correlation_id(value: str) -> Iterator[None]:
    """Tag every record logged in this context (thread or asyncio task) with ``value``."""
    token = correlation_id.set(value)
    try:
        yield
    finally:
        correlation_id.reset(token)
