"""JSON fallback encoding shared by the SIEM logger and the SLM telemetry packer."""

from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel


def json_default(value: object) -> Any:
    """``json.dumps(default=...)`` hook for the types the pipeline passes around."""
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
        # Never spill raw (possibly malicious) payloads into logs or prompts.
        return {"type": type(value).__name__, "length": len(value)}
    return repr(value)
