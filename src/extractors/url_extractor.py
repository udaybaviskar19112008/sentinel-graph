"""Clickable-URL extraction from email bodies.

URLs are normalised the way a browser reads them (WHATWG URL rules), so
obfuscation the browser silently discards cannot split or hide a link from us.
"""

import re
import unicodedata
from collections.abc import Iterator
from itertools import chain
from typing import Final, NamedTuple
from urllib.parse import urljoin, urlsplit, urlunsplit

from bs4 import BeautifulSoup, Tag

from src.core.config import get_settings
from src.core.logger import get_logger

logger = get_logger(__name__)

_DETONATABLE_SCHEMES: Final = frozenset({"http", "https"})
# Elements and attributes that send the browser, or a form submission, somewhere.
_URL_ATTRIBUTES: Final[dict[str, str]] = {
    "a": "href",
    "area": "href",
    "form": "action",
    "iframe": "src",
    "frame": "src",
}
_META_REFRESH_URL_RE: Final = re.compile(
    r""" url \s* = \s* ['"]? \s* (?P<url> [^'"\s;]+ ) """, re.IGNORECASE | re.VERBOSE
)
_TEXT_URL_RE: Final = re.compile(
    r"""
    (?: https?:// | (?<! [\w.@/-] ) www\. )   # a scheme, or a bare www. host that clients auto-link
    [^\s<>"'`]+
    """,
    re.IGNORECASE | re.VERBOSE,
)
# Browsers drop ASCII tab/CR/LF anywhere in a URL, and C0 controls/space at its ends.
_URL_INTERNAL_WHITESPACE: Final = str.maketrans("", "", "\t\r\n")
_C0_AND_SPACE: Final = "".join(map(chr, range(0x21)))
_TRAILING_PUNCTUATION: Final = ".,;:!?'\""
_CLOSERS: Final[dict[str, str]] = {")": "(", "]": "[", "}": "{", ">": "<"}


class _Candidate(NamedTuple):
    raw: str
    base: str | None
    hidden: int  # invisible characters removed from inside this URL


def _is_invisible(char: str) -> bool:
    # Cf: zero-width space/joiners, bidi overrides, soft hyphen, word joiner, BOM, tag characters.
    return unicodedata.category(char) == "Cf"


def _trim_prose_tail(url: str) -> str:
    """Drop sentence punctuation and unbalanced closing brackets that follow a URL in prose."""
    while url:
        tail = url[-1]
        if tail in _TRAILING_PUNCTUATION:
            url = url[:-1]
        elif tail in _CLOSERS and url.count(tail) > url.count(_CLOSERS[tail]):
            url = url[:-1]
        else:
            break
    return url


def _attribute_candidate(raw: str, base: str | None) -> _Candidate:
    visible = "".join(char for char in raw if not _is_invisible(char))
    return _Candidate(visible, base, len(raw) - len(visible))


def _text_candidates(text: str) -> Iterator[_Candidate]:
    """URLs in prose, matched after invisible characters are removed (as the reader sees it)."""
    kept = [index for index, char in enumerate(text) if not _is_invisible(char)]
    visible = "".join(text[index] for index in kept)
    for match in _TEXT_URL_RE.finditer(visible):
        url = _trim_prose_tail(match[0])
        if not url:
            continue
        start = match.start()
        original_span = kept[start + len(url) - 1] - kept[start] + 1
        yield _Candidate(url, None, original_span - len(url))


def _html_candidates(html_body: str) -> Iterator[_Candidate]:
    soup = BeautifulSoup(html_body, "html.parser")
    base_tag = soup.find("base", href=True)
    base_href = base_tag.get("href") if isinstance(base_tag, Tag) else None
    base = base_href if isinstance(base_href, str) else None

    for tag in soup.find_all(True):
        attribute = _URL_ATTRIBUTES.get(tag.name)
        if attribute is not None and isinstance(value := tag.get(attribute), str):
            yield _attribute_candidate(value, base)
        elif tag.name == "meta" and str(tag.get("http-equiv", "")).lower() == "refresh":
            if match := _META_REFRESH_URL_RE.search(str(tag.get("content", ""))):
                yield _attribute_candidate(match["url"], base)
    # Mail clients auto-link bare URLs in visible text whether or not the markup does.
    yield from _text_candidates(soup.get_text(" "))


def _normalise(raw: str, base: str | None) -> str | None:
    """Browser-equivalent absolute http(s) URL, or None for anything not detonatable."""
    url = raw.translate(_URL_INTERNAL_WHITESPACE).strip(_C0_AND_SPACE)
    if url.lower().startswith("www."):
        url = f"http://{url}"
    elif url.startswith("//"):
        url = f"https:{url}"
    if base:
        url = urljoin(base, url)
    if url.lower().startswith(("http:", "https:")):
        # Special schemes read '\' as '/' before the query, so "https:\\evil.example\login"
        # is a real link to evil.example; urlsplit alone would fold it all into the host.
        cut = min((i for i in (url.find("?"), url.find("#")) if i != -1), default=len(url))
        url = url[:cut].replace("\\", "/") + url[cut:]
    try:
        parts = urlsplit(url)
    except ValueError:  # e.g. an unbalanced IPv6 bracket
        return None
    if parts.scheme.lower() not in _DETONATABLE_SCHEMES or not parts.netloc:
        return None
    return urlunsplit(
        (parts.scheme.lower(), parts.netloc.lower(), parts.path, parts.query, parts.fragment)
    )


def extract_urls(html_body: str, plain_body: str) -> list[str]:
    """Unique absolute http(s) URLs: HTML targets first, then plain-text links, in order seen."""
    limit = get_settings().MAX_EXTRACTED_URLS
    candidates = chain(_html_candidates(html_body) if html_body else (), _text_candidates(plain_body))
    urls: dict[str, None] = {}
    hidden = 0
    for candidate in candidates:
        url = _normalise(candidate.raw, candidate.base)
        if url is None:
            continue
        hidden += candidate.hidden
        if url in urls:
            continue
        if len(urls) == limit:
            logger.warning(
                "URL extraction limit reached; remaining links ignored",
                extra={"event": "url.limit_reached", "max_urls": limit},
            )
            break
        urls[url] = None

    if hidden:
        # Invisible characters inside a link exist only to defeat scanners.
        logger.warning(
            "Invisible characters stripped from URLs",
            extra={"event": "url.obfuscation_stripped", "characters_removed": hidden},
        )
    logger.info("URLs extracted", extra={"event": "url.extracted", "url_count": len(urls)})
    return list(urls)
