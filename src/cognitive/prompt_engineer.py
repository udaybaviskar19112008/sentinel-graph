"""Token-frugal, injection-hardened prompt for the local SOC reasoning model.

Every attacker-influenced string (the payload, and telemetry such as the subject)
is folded onto one plain line, and anything that could forge the template's
section markers, the verdict line, or the model's chat-role tokens is neutralised.
That stops format-level injection; it cannot stop text that merely argues with
the model, so the extracted verdict never downgrades on its own (see
``slm_inference.extract_verdict``).
"""

import json
import math
import re
import unicodedata
from collections.abc import Mapping
from enum import Enum
from typing import Any, Final

from pydantic import BaseModel

from src.core.serialization import json_default
from src.schemas import VerdictLevel

PAYLOAD_CHARS: Final = 500
SYSTEM_INSTRUCTION: Final = (
    "You are a Principal SOC Analyst. Output a rapid, 40-word step-by-step forensic deduction. "
    f"End with exactly VERDICT: [{'|'.join(VerdictLevel)}]."
)

# Whitespace padding must not push the real lure past the payload limit, so the
# cleaner scans this much raw text before truncating.
_SCAN_WINDOW_CHARS: Final = 64 * 1024
_TELEMETRY_STRING_CHARS: Final = 120
_TELEMETRY_LIST_ITEMS: Final = 10
_TELEMETRY_DEPTH: Final = 8

_SECTION_MARKER_RE: Final = re.compile(
    r"\[ \s* (SYSTEM|TELEMETRY|PAYLOAD|ANALYSIS) \s* \] \s* :", re.IGNORECASE | re.VERBOSE
)
_VERDICT_LABEL_RE: Final = re.compile(r"VERDICT \s* :", re.IGNORECASE | re.VERBOSE)
# Chat-role tokens such as <|assistant|> or <|end|>: collapsing the pipes leaves no way
# to reassemble one from fragments.
_CHAT_TOKEN_OPEN_RE: Final = re.compile(r"<\|+")
_CHAT_TOKEN_CLOSE_RE: Final = re.compile(r"\|+>")


def _clean(text: str, limit: int) -> str:
    """One NFKC-folded line, free of control/format characters and template syntax."""
    folded = unicodedata.normalize("NFKC", text[:_SCAN_WINDOW_CHARS])
    # Category C*: controls (incl. ANSI escapes), zero-width/bidi format characters,
    # lone surrogates and unassigned code points. Whitespace becomes plain spaces.
    visible = "".join(
        " " if char.isspace() else char for char in folded if char.isspace() or unicodedata.category(char)[0] != "C"
    )
    line = " ".join(visible.split())
    line = _CHAT_TOKEN_OPEN_RE.sub("<", line)
    line = _CHAT_TOKEN_CLOSE_RE.sub(">", line)
    line = _SECTION_MARKER_RE.sub(lambda match: f"({match[1]})", line)
    line = _VERDICT_LABEL_RE.sub("verdict -", line)
    return line[:limit]


def _compact(value: Any, depth: int = 0) -> Any:
    """Shrink telemetry for the prompt: drop empties, round floats, cap strings and lists."""
    if depth > _TELEMETRY_DEPTH:
        return "..."
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json")
    if isinstance(value, str):  # before Enum: StrEnum members are strings already
        return _clean(value, _TELEMETRY_STRING_CHARS)
    if isinstance(value, Enum):
        return _compact(value.value, depth + 1)
    if isinstance(value, Mapping):
        compacted = {_clean(str(key), _TELEMETRY_STRING_CHARS): _compact(item, depth + 1) for key, item in value.items()}
        return {key: item for key, item in compacted.items() if item not in (None, "", [], {})}
    if isinstance(value, (set, frozenset)):
        value = sorted(value, key=str)
    if isinstance(value, (list, tuple)):
        return [_compact(item, depth + 1) for item in value[:_TELEMETRY_LIST_ITEMS]]
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        return round(value, 3) if math.isfinite(value) else str(value)
    return _compact(json_default(value), depth + 1)


def build_soc_prompt(email_text: str, telemetry: Mapping[str, Any]) -> str:
    """The four-line SOC prompt: instruction, compact telemetry JSON, payload, analysis cue."""
    telemetry_json = json.dumps(
        _compact(telemetry), separators=(",", ":"), sort_keys=True, ensure_ascii=False, allow_nan=False
    )
    payload = _clean(email_text, PAYLOAD_CHARS)
    return (
        f"[SYSTEM]: {SYSTEM_INSTRUCTION}\n"
        f"[TELEMETRY]: {telemetry_json}\n"
        f"[PAYLOAD]: {payload}\n"
        "[ANALYSIS]:"
    )
