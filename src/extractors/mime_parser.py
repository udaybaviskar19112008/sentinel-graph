"""Defensive MIME unpacking for hostile email.

Phishing kits ship malformed boundaries, lying charset labels and pathological
nesting to crash or blind scanners. Everything here degrades to a best-effort
result and records what was wrong instead of raising.

With ``email.policy.default`` the stdlib *registers* defects on each part rather
than raising them, so defects are harvested from the parsed tree (after
transfer-decoding, which registers base64 defects of its own). ``MessageDefect``
is still caught wherever one could surface, so a stricter policy never crashes us.
"""

import codecs
import email.policy
import hashlib
import re
from collections.abc import Iterator
from dataclasses import dataclass
from email.errors import MessageDefect
from email.message import EmailMessage, Message
from email.parser import BytesParser
from typing import Final

from src.core.config import get_settings
from src.core.logger import get_logger

logger = get_logger(__name__)

_PARSER: Final = BytesParser(policy=email.policy.default)

_FALLBACK_CHARSETS: Final[tuple[str, ...]] = ("utf-8", "windows-1252", "iso-8859-1")
_HTML_CONTENT_TYPES: Final[frozenset[str]] = frozenset(
    {"text/html", "text/x-amp-html", "application/xhtml+xml"}
)
_HTML_SNIFF: Final = re.compile(
    r"<\s*(?:!doctype\s+html|html|head|body|a\s|form|iframe|script|table|div|meta)\b",
    re.IGNORECASE,
)
_ROOT_PATH: Final = "0"
# Bound per-event size; SIEM forwarders commonly truncate oversized lines, breaking the JSON.
_MAX_LOGGED_DEFECTS: Final = 100
_MAX_LOGGED_VALUE_CHARS: Final = 256


@dataclass(frozen=True, slots=True)
class MimePayload:
    """A transfer-decoded leaf of the MIME tree."""

    path: str  # dotted child indices from the root, e.g. "0.2.1"
    content_type: str
    charset: str | None
    filename: str | None
    is_attachment: bool
    data: bytes


@dataclass(frozen=True, slots=True)
class _Defect:
    path: str
    location: str  # "body" or "header:<Name>"
    name: str


def _clip(value: str | None) -> str | None:
    return value if value is None else value[:_MAX_LOGGED_VALUE_CHARS]


def _parse(raw_bytes: bytes) -> EmailMessage:
    try:
        return _PARSER.parsebytes(raw_bytes)
    except MessageDefect as exc:
        logger.warning(
            "MIME parse raised a defect; retrying headers-only",
            extra={"event": "mime.parse_failed", "defect_classes": [type(exc).__name__]},
        )
    except Exception as exc:  # RecursionError on absurd nesting, or a stdlib parser bug
        logger.error(
            "MIME parse failed; retrying headers-only",
            extra={"event": "mime.parse_failed", "error_type": type(exc).__name__},
        )
    try:
        # Headers-only keeps the whole body as one opaque payload: no recursion, still scannable.
        return _PARSER.parsebytes(raw_bytes, headersonly=True)
    except Exception as exc:
        logger.error(
            "Headers-only MIME parse failed; returning empty message",
            extra={"event": "mime.parse_failed", "error_type": type(exc).__name__},
        )
        return EmailMessage(policy=email.policy.default)


def _collect_defects(part: Message, path: str, sink: list[_Defect]) -> None:
    sink.extend(_Defect(path, "body", type(defect).__name__) for defect in part.defects)
    # Header defects live on the lazily parsed header objects, not on the part.
    for name in {key.lower(): key for key in part.keys()}.values():
        try:
            values = part.get_all(name, [])
        except Exception:
            logger.exception(
                "Header could not be parsed",
                extra={"event": "mime.header_error", "part_path": path, "header": _clip(name)},
            )
            continue
        for value in values:
            sink.extend(
                _Defect(path, f"header:{name}", type(defect).__name__)
                for defect in getattr(value, "defects", ())
            )


def _is_attachment(part: Message, content_type: str, filename: str | None) -> bool:
    if part.get_content_disposition() == "attachment" or filename:
        return True
    if content_type in _HTML_CONTENT_TYPES:
        return False
    # Inline images, PDFs, archives... anything not renderable as a text body.
    return content_type.partition("/")[0] not in {"text", "multipart"}


def _build_payload(part: Message, path: str) -> MimePayload:
    decoded = part.get_payload(decode=True)
    content_type = part.get_content_type()
    filename = part.get_filename()
    return MimePayload(
        path=path,
        content_type=content_type,
        charset=part.get_content_charset(),
        filename=filename,
        is_attachment=_is_attachment(part, content_type, filename),
        data=decoded if isinstance(decoded, bytes) else b"",
    )


def _walk_mime_tree(
    part: Message,
    defects: list[_Defect],
    *,
    max_depth: int,
    path: str = _ROOT_PATH,
    depth: int = 0,
) -> Iterator[MimePayload]:
    """Depth-first walk yielding every leaf payload, descending into message/rfc822.

    Defects of every visited node are appended to ``defects``.
    """
    if depth > max_depth:
        logger.warning(
            "MIME nesting exceeds depth limit; subtree skipped",
            extra={"event": "mime.depth_limit_exceeded", "part_path": path, "max_depth": max_depth},
        )
        return

    if part.is_multipart():
        _collect_defects(part, path, defects)
        # Not iter_parts(): it skips message/rfc822, a favourite wrapper for the real lure.
        children = part.get_payload()
        for index, child in enumerate(children if isinstance(children, list) else [], start=1):
            if isinstance(child, Message):
                yield from _walk_mime_tree(
                    child, defects, max_depth=max_depth, path=f"{path}.{index}", depth=depth + 1
                )
        return

    payload: MimePayload | None = None
    try:
        payload = _build_payload(part, path)
    except MessageDefect as exc:
        defects.append(_Defect(path, "body", type(exc).__name__))
    except Exception:
        logger.exception(
            "MIME part could not be decoded; skipped",
            extra={"event": "mime.part_error", "part_path": path},
        )
    # After decoding: get_payload(decode=True) registers base64 padding/alphabet defects.
    _collect_defects(part, path, defects)
    if payload is not None:
        yield payload


def _decode_text(data: bytes, declared: str | None, path: str) -> str:
    """Declared charset first, then utf-8 -> windows-1252 -> iso-8859-1, then replacement."""
    tried: set[str] = set()
    for charset in (declared, *_FALLBACK_CHARSETS):
        if charset is None:
            continue
        try:
            codec = codecs.lookup(charset).name
            if codec in tried:
                continue
            tried.add(codec)
            text = data.decode(codec)
        except (LookupError, ValueError):  # unknown/non-text codec, or UnicodeDecodeError
            continue
        if charset is not declared:
            # A declared charset that cannot decode the body is itself an evasion signal.
            logger.info(
                "Declared charset failed; decoded with fallback",
                extra={
                    "event": "mime.charset_fallback",
                    "part_path": path,
                    "declared_charset": _clip(declared),
                    "used_charset": codec,
                },
            )
        return text
    # iso-8859-1 maps every byte, so this is only a guard against the chain being edited.
    return data.decode("utf-8", errors="replace")


def _bounded_attachment(payload: MimePayload, limit: int) -> bytes:
    if len(payload.data) <= limit:
        return payload.data
    logger.warning(
        "Attachment truncated to sandbox size limit",
        extra={
            "event": "mime.attachment_truncated",
            "part_path": payload.path,
            "content_type": payload.content_type,
            "attachment_filename": _clip(payload.filename),
            "original_size": len(payload.data),
            "truncated_size": limit,
            # Threat-intel lookups need the digest of the whole file, not the prefix we keep.
            "sha256": hashlib.sha256(payload.data).hexdigest(),
        },
    )
    return payload.data[:limit]


def _is_html(content_type: str, text: str) -> bool:
    if content_type in _HTML_CONTENT_TYPES:
        return True
    if content_type == "text/plain":
        return False
    # Broken multiparts and exotic text/* subtypes: route by content, as a lenient client would.
    # Scan the whole body: a prefix window is trivially defeated by padding.
    return _HTML_SNIFF.search(text) is not None


def _log_defects(defects: list[_Defect]) -> None:
    if not defects:
        return
    logger.warning(
        "MIME defects detected",
        extra={
            "event": "mime.defects",
            "defect_classes": sorted({defect.name for defect in defects}),
            "defect_count": len(defects),
            "defects": [
                {"part_path": d.path, "location": _clip(d.location), "defect": d.name}
                for d in defects[:_MAX_LOGGED_DEFECTS]
            ],
        },
    )


def unpack_email(raw_bytes: bytes) -> tuple[EmailMessage, str, str, list[bytes]]:
    """Unpack a raw RFC 5322 message into (message, plain text, HTML, attachments).

    Never raises on malformed input. Text bodies from every inline leaf are joined
    with newlines; attachments are transfer-decoded and capped at
    ``MAX_ATTACHMENT_BYTES`` each.
    """
    settings = get_settings()
    message = _parse(raw_bytes)
    defects: list[_Defect] = []
    text_parts: list[str] = []
    html_parts: list[str] = []
    attachments: list[bytes] = []

    leaf_count = 0
    for payload in _walk_mime_tree(message, defects, max_depth=settings.MIME_MAX_DEPTH):
        if leaf_count == settings.MIME_MAX_PARTS:
            logger.warning(
                "MIME part limit reached; remaining parts skipped",
                extra={"event": "mime.part_limit_exceeded", "max_parts": settings.MIME_MAX_PARTS},
            )
            break
        leaf_count += 1
        if payload.is_attachment:
            attachments.append(_bounded_attachment(payload, settings.MAX_ATTACHMENT_BYTES))
            continue
        text = _decode_text(payload.data, payload.charset, payload.path)
        (html_parts if _is_html(payload.content_type, text) else text_parts).append(text)

    _log_defects(defects)
    logger.info(
        "Email unpacked",
        extra={
            "event": "mime.unpacked",
            "leaf_count": leaf_count,
            "text_chars": sum(map(len, text_parts)),
            "html_chars": sum(map(len, html_parts)),
            "attachment_count": len(attachments),
            "defect_count": len(defects),
        },
    )
    return message, "\n".join(text_parts), "\n".join(html_parts), attachments
