import json
from collections.abc import Iterator
from pathlib import Path

import pytest

from src.core.config import get_settings
from src.core.logger import LOG_FILE_NAME, configure_logging, shutdown_logging
from src.extractors.url_extractor import extract_urls


@pytest.fixture
def log_lines(tmp_path: Path) -> Iterator[Path]:
    shutdown_logging()
    configure_logging(log_dir=tmp_path, level="DEBUG")
    yield tmp_path / LOG_FILE_NAME
    shutdown_logging()


def test_hrefs_first_then_plain_text_deduplicated_in_order() -> None:
    html = (
        '<a href="https://login.evil.example/a">one</a>'
        '<a href="https://login.evil.example/a">dup</a>'
        '<a href="https://cdn.evil.example/b">two</a>'
    )
    plain = "Visit https://login.evil.example/a or https://plain.evil.example/c."

    assert extract_urls(html, plain) == [
        "https://login.evil.example/a",
        "https://cdn.evil.example/b",
        "https://plain.evil.example/c",
    ]


def test_zero_width_obfuscation_is_stripped_and_logged(log_lines: Path) -> None:
    html = '<a href="https://pay​pal-⁠secure.evil.example/﻿login">x</a>'
    plain = "Go to ht​tps://acc‍ount.evil.example/reset now"

    urls = extract_urls(html, plain)
    shutdown_logging()
    events = [json.loads(line) for line in log_lines.read_text("utf-8").splitlines()]

    assert urls == [
        "https://paypal-secure.evil.example/login",
        "https://account.evil.example/reset",
    ]
    (obfuscation,) = [e for e in events if e.get("event") == "url.obfuscation_stripped"]
    assert obfuscation["characters_removed"] == 5


def test_emoji_joiners_in_prose_are_not_counted_as_obfuscation(log_lines: Path) -> None:
    extract_urls("<p>Family \U0001f468‍\U0001f469‍\U0001f467 https://ok.example/x</p>", "")
    shutdown_logging()

    assert "url.obfuscation_stripped" not in log_lines.read_text("utf-8")


@pytest.mark.parametrize(
    ("html", "expected"),
    [
        pytest.param('<a href="  HTTPS://Evil.Example/Path ">x</a>', "https://evil.example/Path", id="case-and-space"),
        pytest.param('<a href="https://evil.ex\nample/lo\tgin">x</a>', "https://evil.example/login", id="tab-newline"),
        pytest.param('<a href="&#104;ttps://evil.example/">x</a>', "https://evil.example/", id="html-entity"),
        pytest.param('<a href="//evil.example/p">x</a>', "https://evil.example/p", id="protocol-relative"),
        pytest.param('<a href="https://evil.example\\login">x</a>', "https://evil.example/login", id="backslash"),
        pytest.param('<a href="https:\\\\evil.example\\a?q=\\x">x</a>', "https://evil.example/a?q=\\x", id="backslash-scheme"),
        pytest.param('<form action="https://harvest.evil.example/post"></form>', "https://harvest.evil.example/post", id="form-action"),
        pytest.param('<iframe src="https://frame.evil.example/"></iframe>', "https://frame.evil.example/", id="iframe"),
        pytest.param(
            '<meta http-equiv="Refresh" content="0; URL=\'https://redirect.evil.example/\'">',
            "https://redirect.evil.example/",
            id="meta-refresh",
        ),
        pytest.param(
            '<base href="https://kit.evil.example/x/"><a href="login.php">x</a>',
            "https://kit.evil.example/x/login.php",
            id="base-href",
        ),
        pytest.param("<p>Call www.evil.example/help today</p>", "http://www.evil.example/help", id="bare-www-text"),
    ],
)
def test_browser_equivalent_normalisation(html: str, expected: str) -> None:
    assert extract_urls(html, "") == [expected]


@pytest.mark.parametrize(
    "href",
    ["javascript:alert(1)", "mailto:a@b.example", "data:text/html,<h1>x</h1>", "/relative/no-base", "#top", "tel:123"],
)
def test_non_detonatable_targets_are_dropped(href: str) -> None:
    assert extract_urls(f'<a href="{href}">x</a>', "") == []


def test_prose_punctuation_and_brackets_are_trimmed() -> None:
    plain = (
        "See (https://evil.example/a). Also https://en.wikipedia.org/wiki/Foo_(bar), "
        "and <https://evil.example/b>!"
    )

    assert extract_urls("", plain) == [
        "https://evil.example/a",
        "https://en.wikipedia.org/wiki/Foo_(bar)",
        "https://evil.example/b",
    ]


def test_plain_text_fallback_without_html() -> None:
    assert extract_urls("", "Reset: https://reset.evil.example/?u=victim") == [
        "https://reset.evil.example/?u=victim"
    ]


def test_url_count_is_capped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SOC_MAX_EXTRACTED_URLS", "3")
    get_settings.cache_clear()
    try:
        html = "".join(f'<a href="https://evil.example/{i}">x</a>' for i in range(10))
        urls = extract_urls(html, "")
    finally:
        monkeypatch.undo()
        get_settings.cache_clear()

    assert urls == [f"https://evil.example/{i}" for i in range(3)]
