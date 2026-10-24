import base64
import hashlib
import json
import quopri
from collections.abc import Callable, Iterator
from email.message import EmailMessage
from pathlib import Path
from typing import Any

import pytest

from src.core.config import get_settings
from src.core.logger import LOG_FILE_NAME, configure_logging, shutdown_logging
from src.extractors.mime_parser import unpack_email

TWO_MB = 2 * 1024 * 1024
PHISH_URL = "https://login.example-phish.test/verify"

# Every non-ASCII character here sits in windows-1252's 0x80-0x9F block or high half,
# so decoding as latin-1 would yield C1 controls and as utf-8 would fail outright.
HTML_SOURCE = (
    "<html><head><title>Account notice</title></head><body>"
    "<p>“Urgent” — your invoice for €1,299.00 is overdue…</p>"
    "<p>Café Résumé™ Šimon • Œuvre ‘ok’</p>"
    f'<a href="{PHISH_URL}">Verify now</a>'
    "</body></html>"
)
PLAIN_SOURCE = f"Your invoice is overdue. Verify at {PHISH_URL}"
PNG_BYTES = b"\x89PNG\r\n\x1a\n" + bytes(range(64))
PDF_BYTES = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n1 0 obj<<>>endobj\n%%EOF\n"

LogEvents = Callable[[], list[dict[str, Any]]]


# --- raw MIME builders -------------------------------------------------------


def _b64(data: bytes) -> str:
    return base64.encodebytes(data).decode("ascii").replace("\n", "\r\n")


def _leaf(content_type: str, body: str, *, cte: str = "7bit", headers: str = "") -> str:
    return f"Content-Type: {content_type}\r\nContent-Transfer-Encoding: {cte}\r\n{headers}\r\n{body}"


def _multipart(subtype: str, boundary: str, *parts: str) -> str:
    body = "".join(f"--{boundary}\r\n{part}\r\n" for part in parts)
    return f'Content-Type: multipart/{subtype}; boundary="{boundary}"\r\n\r\n{body}--{boundary}--\r\n'


def _nest(entity: str, levels: int) -> str:
    for level in range(levels):
        entity = _multipart("mixed", f"nest-{level}", entity)
    return entity


def _message(entity: str) -> bytes:
    headers = (
        "From: \"Billing\" <billing@example-phish.test>\r\n"
        "To: victim@example.test\r\n"
        "Subject: Invoice overdue\r\n"
        "Message-ID: <test-1@example-phish.test>\r\n"
        "MIME-Version: 1.0\r\n"
    )
    return (headers + entity).encode("ascii")


def _html_leaf(charset: str, html: bytes) -> str:
    return _leaf(f'text/html; charset="{charset}"', _b64(html), cte="base64")


def _deeply_nested_email(html_leaf: str) -> bytes:
    alternative = _multipart(
        "alternative",
        "alt-boundary",
        _leaf('text/plain; charset="us-ascii"', PLAIN_SOURCE),
        html_leaf,
    )
    related = _multipart(
        "related",
        "rel-boundary",
        alternative,
        _leaf(
            "image/png",
            _b64(PNG_BYTES),
            cte="base64",
            headers="Content-ID: <logo@example-phish.test>\r\nContent-Disposition: inline\r\n",
        ),
    )
    outer = _multipart(
        "mixed",
        "outer-boundary",
        _nest(related, levels=5),
        _leaf(
            'application/pdf; name="invoice.pdf"',
            _b64(PDF_BYTES),
            cte="base64",
            headers='Content-Disposition: attachment; filename="invoice.pdf"\r\n',
        ),
    )
    return _message(outer)


# --- fixtures ----------------------------------------------------------------


@pytest.fixture
def log_events(tmp_path: Path) -> Iterator[LogEvents]:
    """Route the JSON logger to ``tmp_path``; calling the fixture flushes and parses it."""
    shutdown_logging()
    configure_logging(log_dir=tmp_path, level="DEBUG")

    def read() -> list[dict[str, Any]]:
        shutdown_logging()  # stops the listener, which drains the queue to disk
        lines = (tmp_path / LOG_FILE_NAME).read_text(encoding="utf-8").splitlines()
        return [json.loads(line) for line in lines]

    yield read
    shutdown_logging()


def _events(records: list[dict[str, Any]], name: str) -> list[dict[str, Any]]:
    return [record for record in records if record.get("event") == name]


# --- tests -------------------------------------------------------------------


def test_deeply_nested_windows_1252_html_decodes_flawlessly(log_events: LogEvents) -> None:
    raw = _deeply_nested_email(_html_leaf("windows-1252", HTML_SOURCE.encode("windows-1252")))

    message, text, html, attachments = unpack_email(raw)

    assert isinstance(message, EmailMessage)
    assert message["Subject"] == "Invoice overdue"
    assert html == HTML_SOURCE
    assert "�" not in html
    assert not any("\x80" <= char <= "\x9f" for char in html)
    assert text == PLAIN_SOURCE
    assert attachments == [PNG_BYTES, PDF_BYTES]

    records = log_events()
    assert not _events(records, "mime.defects")
    assert not _events(records, "mime.charset_fallback")
    (summary,) = _events(records, "mime.unpacked")
    assert summary["attachment_count"] == 2
    assert summary["level"] == "INFO"
    assert summary["logger"] == "soc.extractors.mime_parser"


def test_misdeclared_charset_falls_back_to_windows_1252(log_events: LogEvents) -> None:
    raw = _deeply_nested_email(_html_leaf("utf-8", HTML_SOURCE.encode("windows-1252")))

    _, _, html, _ = unpack_email(raw)

    assert html == HTML_SOURCE
    (fallback,) = _events(log_events(), "mime.charset_fallback")
    assert fallback["declared_charset"] == "utf-8"
    assert fallback["used_charset"] == "cp1252"


def test_unknown_charset_falls_back_to_utf8() -> None:
    body = "<html><p>Проверьте счёт</p></html>"
    raw = _message(_html_leaf("x-phish-unknown", body.encode("utf-8")))

    _, _, html, _ = unpack_email(raw)

    assert html == body


@pytest.mark.parametrize(
    ("charset", "body", "encode"),
    [
        pytest.param(
            "koi8-r",
            "Срочно: подтвердите пароль",
            lambda data: ("quoted-printable", quopri.encodestring(data).decode("ascii")),
            id="koi8-r-quoted-printable",
        ),
        pytest.param(
            "iso-2022-jp",
            "パスワードを確認してください",
            lambda data: ("7bit", data.decode("ascii")),
            id="iso-2022-jp-7bit",
        ),
        pytest.param(
            "gb18030",
            "请立即验证您的账户",
            lambda data: ("base64", _b64(data)),
            id="gb18030-base64",
        ),
    ],
)
def test_obscure_declared_charsets_decode(
    charset: str, body: str, encode: Callable[[bytes], tuple[str, str]]
) -> None:
    cte, encoded = encode(body.encode(charset))
    raw = _message(_leaf(f'text/plain; charset="{charset}"', encoded, cte=cte))

    _, text, _, _ = unpack_email(raw)

    assert text == body


def test_oversized_attachment_is_truncated_to_2mb(log_events: LogEvents) -> None:
    oversized = bytes(range(256)) * (TWO_MB // 256 + 8)
    small = b"MZ\x90\x00small-payload"
    raw = _message(
        _multipart(
            "mixed",
            "att-boundary",
            _leaf("text/plain", "see attached"),
            _leaf(
                "application/octet-stream",
                _b64(oversized),
                cte="base64",
                headers='Content-Disposition: attachment; filename="payload.bin"\r\n',
            ),
            _leaf(
                "application/x-msdownload",
                _b64(small),
                cte="base64",
                headers='Content-Disposition: attachment; filename="small.exe"\r\n',
            ),
        )
    )

    _, _, _, attachments = unpack_email(raw)

    assert get_settings().MAX_ATTACHMENT_BYTES == TWO_MB
    assert [len(item) for item in attachments] == [TWO_MB, len(small)]
    assert attachments[0] == oversized[:TWO_MB]
    assert attachments[1] == small
    (truncated,) = _events(log_events(), "mime.attachment_truncated")
    assert truncated["original_size"] == len(oversized)
    assert truncated["attachment_filename"] == "payload.bin"
    assert truncated["sha256"] == hashlib.sha256(oversized).hexdigest()


def test_html_attachment_is_not_treated_as_body() -> None:
    smuggled = b"<html><script>location='https://x.test'</script></html>"
    raw = _message(
        _multipart(
            "mixed",
            "smuggle-boundary",
            _leaf("text/plain", "Your remittance advice is attached."),
            _leaf(
                'text/html; charset="utf-8"',
                _b64(smuggled),
                cte="base64",
                headers='Content-Disposition: attachment; filename="remittance.html"\r\n',
            ),
        )
    )

    _, text, html, attachments = unpack_email(raw)

    assert text == "Your remittance advice is attached."
    assert html == ""
    assert attachments == [smuggled]


def test_embedded_rfc822_message_is_traversed() -> None:
    inner = _message(_html_leaf("utf-8", f'<html><a href="{PHISH_URL}">Login</a></html>'.encode()))
    raw = _message(
        _multipart(
            "mixed",
            "fwd-boundary",
            _leaf("text/plain", "Forwarding this for review."),
            "Content-Type: message/rfc822\r\n\r\n" + inner.decode("ascii"),
        )
    )

    _, text, html, _ = unpack_email(raw)

    assert text == "Forwarding this for review."
    assert PHISH_URL in html


@pytest.mark.parametrize(
    ("entity", "expected_defect"),
    [
        pytest.param(
            'Content-Type: multipart/mixed; boundary="declared"\r\n\r\n'
            f"--other\r\nContent-Type: text/html\r\n\r\n<html><a href=\"{PHISH_URL}\">x</a></html>\r\n",
            "StartBoundaryNotFoundDefect",
            id="start-boundary-missing",
        ),
        pytest.param(
            'Content-Type: multipart/mixed; boundary="b"\r\n\r\n'
            f"--b\r\nContent-Type: text/html\r\n\r\n<html><a href=\"{PHISH_URL}\">x</a></html>\r\n",
            "CloseBoundaryNotFoundDefect",
            id="close-boundary-missing",
        ),
        pytest.param(
            "Content-Type: multipart/alternative\r\n\r\n"
            f"<html><a href=\"{PHISH_URL}\">x</a></html>\r\n",
            "NoBoundaryInMultipartDefect",
            id="boundary-param-missing",
        ),
    ],
)
def test_malformed_boundaries_are_logged_not_fatal(
    log_events: LogEvents, entity: str, expected_defect: str
) -> None:
    _, _, html, _ = unpack_email(_message(entity))

    assert PHISH_URL in html
    (defects,) = _events(log_events(), "mime.defects")
    assert expected_defect in defects["defect_classes"]
    assert defects["level"] == "WARNING"


def test_base64_padding_defect_is_logged_with_part_path(log_events: LogEvents) -> None:
    body = b"<html><p>Pay now!</p></html>"
    assert len(body) % 3, "body length must need base64 padding"
    unpadded = base64.b64encode(body).decode("ascii").rstrip("=")
    raw = _message(
        _multipart("mixed", "pad-boundary", _leaf("text/html", unpadded, cte="base64"))
    )

    _, _, html, _ = unpack_email(raw)

    assert html == body.decode("ascii")
    (defects,) = _events(log_events(), "mime.defects")
    assert defects["defect_classes"] == ["InvalidBase64PaddingDefect"]
    assert defects["defects"] == [
        {"part_path": "0.1", "location": "body", "defect": "InvalidBase64PaddingDefect"}
    ]


def test_nesting_beyond_depth_limit_is_skipped_and_logged(log_events: LogEvents) -> None:
    max_depth = get_settings().MIME_MAX_DEPTH
    raw = _message(_nest(_leaf("text/html", "<html>deep</html>"), levels=max_depth + 10))

    message, text, html, attachments = unpack_email(raw)

    assert isinstance(message, EmailMessage)
    assert (text, html, attachments) == ("", "", [])
    assert _events(log_events(), "mime.depth_limit_exceeded")


def test_recursion_bomb_falls_back_to_headers_only(log_events: LogEvents) -> None:
    # Deep enough to blow the stdlib feedparser's recursion, not just our depth limit.
    raw = _message(_nest(_leaf("text/html", f'<html><a href="{PHISH_URL}">x</a></html>'), 5000))

    message, _, html, _ = unpack_email(raw)

    assert message["Subject"] == "Invoice overdue"
    assert PHISH_URL in html
    (failure,) = _events(log_events(), "mime.parse_failed")
    assert failure["error_type"] == "RecursionError"
