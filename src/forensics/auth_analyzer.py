"""Identity verification: Authentication-Results parsing and display-name brand spoofing.

Only one Authentication-Results header is trusted: the one stamped by our own
boundary (``TRUSTED_AUTHSERV_IDS``), or failing that the topmost. Headers lower in
the stack were written before our MTA saw the message and may be forged.
"""

import logging
import re
import unicodedata
from collections.abc import Mapping
from email.errors import HeaderParseError
from email.header import decode_header
from email.message import EmailMessage
from email.utils import parseaddr
from itertools import accumulate
from typing import Final, TypedDict

from src.core.charsets import decode_bytes
from src.core.config import get_settings
from src.core.domains import registered_domain
from src.core.logger import get_logger
from src.schemas import AuthStatus

logger = get_logger(__name__)

_METHODS: Final[tuple[str, ...]] = ("spf", "dkim", "dmarc", "arc")
_RESULT_ALIASES: Final[dict[str, AuthStatus]] = {
    "pass": AuthStatus.PASS,
    "fail": AuthStatus.FAIL,
    "softfail": AuthStatus.FAIL,  # SPF "probably not authorised": still a negative assertion
    "hardfail": AuthStatus.FAIL,  # legacy vendor spelling
    "policy": AuthStatus.FAIL,  # RFC 8601: verified, but rejected by local policy
    "neutral": AuthStatus.NEUTRAL,
    "none": AuthStatus.NONE,
    "permerror": AuthStatus.PERMERROR,
    "temperror": AuthStatus.TEMPERROR,
}
# Duplicate results for one method resolve to the most suspicious, and PASS needs
# unanimity: text echoed from attacker-controlled fields can downgrade a verdict
# but never upgrade it.
_SEVERITY: Final[dict[AuthStatus, int]] = {
    AuthStatus.PASS: 0,
    AuthStatus.NONE: 1,
    AuthStatus.NEUTRAL: 2,
    AuthStatus.TEMPERROR: 3,
    AuthStatus.PERMERROR: 4,
    AuthStatus.FAIL: 5,
}

_MAX_AUTH_RESULTS_CHARS: Final = 16 * 1024
_MAX_COMMENT_DEPTH: Final = 16

_QUOTED_STRING_RE: Final = re.compile(r' " (?: [^"\\] | \\. )*+ " ', re.VERBOSE | re.DOTALL)
_INNERMOST_COMMENT_RE: Final = re.compile(
    r" \( (?: [^()\\] | \\. )*+ \) ", re.VERBOSE | re.DOTALL
)
_STRAY_DELIMITER_RE: Final = re.compile(r'[()"]')
_AUTHSERV_ID_RE: Final = re.compile(
    r"""
    ^ \s* (?P<authserv_id> [^\s;=]+ ) (?= \s | ; | $ )   # a leading 'spf=...' is not an id
    """,
    re.IGNORECASE | re.VERBOSE,
)
_RESINFO_RE: Final = re.compile(
    r"""
    (?: ^ | (?<= [\s;] ) )          # opens the value, follows ';', or follows FWS when ';' is missing
    (?P<method> spf | dkim | dmarc | arc )
    (?: \s* / \s* \d+ )?            # optional method version, e.g. dkim/1
    \s* = \s*                       # FWS is legal around '='
    (?P<result> [a-z]+ )
    (?! [\w.@-] )                   # whole keyword: not 'pass@evil.example' or 'passport'
    """,
    re.IGNORECASE | re.VERBOSE,
)

DISPLAY_NAME_SPOOF_RISK: Final = 1.0
SUBJECT_SPOOF_RISK: Final = 0.5

_MAX_DISPLAY_NAME_CHARS: Final = 512
_TOKEN_RE: Final = re.compile(r"[a-z0-9]+")
# A brand may end inside a token ("AppleID") from this length, and sit anywhere inside
# one from the next; shorter brands must be whole tokens so "ups" never fires on "groups".
_PREFIX_MATCH_MIN: Final = 5
_INFIX_MATCH_MIN: Final = 6
# Latin look-alikes that survive NFKC/NFKD (subset of Unicode TR39 confusables).
_CONFUSABLES: Final = str.maketrans(
    {
        "а": "a", "в": "b", "е": "e", "ё": "e", "і": "i", "ї": "i", "ј": "j", "к": "k",
        "м": "m", "н": "h", "о": "o", "р": "p", "с": "c", "т": "t", "у": "y", "х": "x",
        "ѕ": "s", "ԁ": "d", "ԛ": "q", "ԝ": "w", "һ": "h", "ӏ": "l", "ү": "y",
        "α": "a", "β": "b", "γ": "y", "ε": "e", "η": "n", "ι": "i", "κ": "k", "ν": "v",
        "ο": "o", "ρ": "p", "τ": "t", "υ": "u", "χ": "x", "ω": "w", "ϲ": "c",
        "ı": "i", "ł": "l", "ø": "o", "đ": "d", "ħ": "h", "ɡ": "g",
    }
)
_LEET: Final = str.maketrans(
    {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "|": "l", "!": "i"}
)


class IdentityFindings(TypedDict):
    """The ``HeaderForensics`` fields owned by identity verification."""

    spf: AuthStatus
    dkim: AuthStatus
    dmarc: AuthStatus
    arc: AuthStatus
    display_name_spoof_risk: float
    impersonated_brand: str | None
    subject: str | None
    from_domain: str | None
    reply_to_domain: str | None
    return_path_domain: str | None


# --- Authentication-Results ---------------------------------------------------


def _blank_comments_and_quotes(value: str) -> str:
    """Blank quoted strings and (nested) comments so their text cannot parse as results.

    MTAs echo attacker-controlled MAIL FROM local parts inside both. Only matched pairs
    are removed, so a stray '(' cannot swallow the rest of the header and hide a later
    ``dmarc=fail``.
    """
    text = _QUOTED_STRING_RE.sub(" ", value)
    for _ in range(_MAX_COMMENT_DEPTH):
        text, removed = _INNERMOST_COMMENT_RE.subn(" ", text)
        if not removed:
            break
    return _STRAY_DELIMITER_RE.sub(" ", text)


def _select_auth_results(msg: EmailMessage, trusted: frozenset[str]) -> tuple[str | None, str]:
    """Return (authserv-id, blanked value) of the header to trust, or (None, "")."""
    try:
        headers = [str(value) for value in msg.get_all("Authentication-Results", [])]
    except Exception:
        logger.exception(
            "Authentication-Results could not be read", extra={"event": "auth.header_error"}
        )
        return None, ""
    for raw in headers:
        cleaned = _blank_comments_and_quotes(raw[:_MAX_AUTH_RESULTS_CHARS])
        match = _AUTHSERV_ID_RE.match(cleaned)
        authserv_id = match["authserv_id"].casefold() if match else None
        if not trusted or authserv_id in trusted:
            return authserv_id, cleaned
    if headers:
        logger.warning(
            "No Authentication-Results header from a trusted authserv-id",
            extra={"event": "auth.untrusted_results_ignored", "header_count": len(headers)},
        )
    return None, ""


def _parse_results(cleaned: str) -> dict[str, AuthStatus]:
    found: dict[str, list[AuthStatus]] = {method: [] for method in _METHODS}
    for match in _RESINFO_RE.finditer(cleaned):
        status = _RESULT_ALIASES.get(match["result"].lower(), AuthStatus.NONE)
        found[match["method"].lower()].append(status)
    return {
        method: max(results, key=_SEVERITY.__getitem__, default=AuthStatus.NONE)
        for method, results in found.items()
    }


# --- addresses and domains ----------------------------------------------------


def _decode_header_text(value: str) -> str:
    """Decode RFC 2047 encoded-words the header registry left literal (all of them for compat32)."""
    if "=?" not in value:
        return value
    try:
        chunks = decode_header(value)
    except (HeaderParseError, ValueError):  # e.g. an undecodable base64 word
        return value
    return "".join(
        chunk if isinstance(chunk, str)
        # decode_header re-encodes literal runs with raw-unicode-escape; invert exactly that.
        else chunk.decode("raw-unicode-escape") if charset is None
        else decode_bytes(chunk, charset).text
        for chunk, charset in chunks
    )


def _first_mailbox(msg: EmailMessage, name: str) -> tuple[str, str | None] | None:
    """(display name, domain) of the first address in header ``name``."""
    try:
        header = msg.get(name)
    except Exception:
        logger.exception(
            "Address header could not be parsed", extra={"event": "auth.header_error", "header": name}
        )
        return None
    if header is None:
        return None
    addresses = getattr(header, "addresses", ())
    if addresses:
        first = addresses[0]
        return _decode_header_text(str(first.display_name)), str(first.domain) or None
    # Structure the header registry could not parse: fall back to the permissive legacy parser.
    display_name, address = parseaddr(str(header))
    return _decode_header_text(display_name), address.rpartition("@")[2] if "@" in address else None


# --- display-name spoofing ----------------------------------------------------


def _skeleton(text: str) -> str:
    """Fold to lower-case Latin so width, accent, zero-width and homoglyph tricks compare equal."""
    folded = unicodedata.normalize("NFKC", text[:_MAX_DISPLAY_NAME_CHARS]).casefold()
    stripped = "".join(
        char
        for char in unicodedata.normalize("NFKD", folded)
        # Cf: zero-width joiners, bidi overrides, soft hyphens. M*: combining accents.
        if unicodedata.category(char) != "Cf" and not unicodedata.category(char).startswith("M")
    )
    return stripped.translate(_CONFUSABLES)


def _variants(skeleton: str) -> set[str]:
    return {
        form
        for base in (skeleton, skeleton.translate(_LEET))
        for form in (base, base.replace("rn", "m").replace("vv", "w"))
    }


def _brand_key(brand: str) -> str:
    return "".join(_TOKEN_RE.findall(_skeleton(brand)))


def _names_brand(variant: str, key: str) -> bool:
    """Whether ``key`` appears token-aligned in ``variant`` ("Pay Pal" and "P-a-y-P-a-l" count)."""
    tokens = _TOKEN_RE.findall(variant)
    squashed = "".join(tokens)
    boundaries = {0, *accumulate(map(len, tokens))}
    start = squashed.find(key)
    while start != -1:
        if len(key) >= _INFIX_MATCH_MIN:
            return True
        if start in boundaries and (
            start + len(key) in boundaries or len(key) >= _PREFIX_MATCH_MIN
        ):
            return True
        start = squashed.find(key, start + 1)
    return False


def _impersonated_brand(
    display_name: str,
    from_domain: str | None,
    brands: frozenset[str],
    canonical_domains: Mapping[str, frozenset[str]],
) -> str | None:
    if not display_name:
        return None
    variants = _variants(_skeleton(display_name))
    for brand in sorted(brands):
        key = _brand_key(brand)
        if not key or not any(_names_brand(variant, key) for variant in variants):
            continue
        legitimate = canonical_domains.get(brand.strip().casefold()) or frozenset({f"{key}.com"})
        if from_domain not in legitimate:
            return brand
    return None


# --- entrypoint ----------------------------------------------------------------


def analyze_identity(
    msg: EmailMessage,
    config_brands: frozenset[str],
    *,
    canonical_domains: Mapping[str, frozenset[str]] | None = None,
    trusted_authserv_ids: frozenset[str] | None = None,
) -> IdentityFindings:
    """Authentication verdicts, sender domains and display-name spoofing for ``msg``.

    ``canonical_domains`` and ``trusted_authserv_ids`` default to the runtime settings.
    The result unpacks straight into ``HeaderForensics`` alongside the routing findings.
    """
    settings = get_settings()
    canonical = settings.BRAND_CANONICAL_DOMAINS if canonical_domains is None else canonical_domains
    trusted = settings.TRUSTED_AUTHSERV_IDS if trusted_authserv_ids is None else trusted_authserv_ids

    authserv_id, results_text = _select_auth_results(
        msg, frozenset(item.casefold() for item in trusted)
    )
    results = _parse_results(results_text)

    display_name, from_address_domain = _first_mailbox(msg, "From") or ("", None)
    reply_to = _first_mailbox(msg, "Reply-To")
    _, return_path = parseaddr(str(msg.get("Return-Path") or ""))
    raw_subject = msg.get("Subject")
    subject = None if raw_subject is None else _decode_header_text(str(raw_subject))

    from_domain = registered_domain(from_address_domain)
    # The display name is what the recipient trusts at a glance: full risk. A brand only in
    # the subject is weaker evidence (marketplaces and forwards mention brands legitimately).
    brand = _impersonated_brand(display_name, from_domain, config_brands, canonical)
    spoof_risk = DISPLAY_NAME_SPOOF_RISK if brand else 0.0
    if brand is None and subject:
        brand = _impersonated_brand(subject, from_domain, config_brands, canonical)
        spoof_risk = SUBJECT_SPOOF_RISK if brand else 0.0
    findings = IdentityFindings(
        spf=results["spf"],
        dkim=results["dkim"],
        dmarc=results["dmarc"],
        arc=results["arc"],
        display_name_spoof_risk=spoof_risk,
        impersonated_brand=brand,
        subject=subject,
        from_domain=from_domain,
        reply_to_domain=registered_domain(reply_to[1]) if reply_to else None,
        return_path_domain=registered_domain(return_path.rpartition("@")[2] if "@" in return_path else None),
    )
    logger.log(
        logging.WARNING if brand else logging.INFO,
        "Sender identity analyzed",
        extra={
            "event": "auth.identity_analyzed",
            "authserv_id": authserv_id,
            **{key: value for key, value in findings.items() if key != "subject"},
        },
    )
    return findings
