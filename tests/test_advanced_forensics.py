import math

import pytest

from src.core.domains import registrable_label
from src.forensics.dga_detector import analyze_dga_risk, calculate_shannon_entropy
from src.forensics.nlp_heuristics import SCAN_WINDOW_CHARS, CoercionAnalyzer, visible_text

# --- DGA entropy -----------------------------------------------------------------------


def test_shannon_entropy_math() -> None:
    assert calculate_shannon_entropy("google") < 2.5
    assert calculate_shannon_entropy("xkqjfhzyw") > 3.0
    # Exact values: two equiprobable symbols carry 1 bit; n distinct symbols carry log2(n).
    assert calculate_shannon_entropy("aabb") == pytest.approx(1.0)
    assert calculate_shannon_entropy("xkqjfhzyw") == pytest.approx(math.log2(9))
    assert calculate_shannon_entropy("") == 0.0


def test_single_symbol_entropy_is_positive_zero() -> None:
    entropy = calculate_shannon_entropy("aaaa")

    assert entropy == 0.0 and math.copysign(1.0, entropy) == 1.0  # not -0.0


@pytest.mark.parametrize(
    ("host", "label"),
    [
        ("login.secure-paypa1.co.uk", "secure-paypa1"),
        ("LOGIN.Google.com.", "google"),
        ("secure-apple-id.invalid", "secure-apple-id"),  # tldextract alone says "invalid"
        ("mx.corp.example", "corp"),
        ("localhost", "localhost"),
        ("185.220.101.4", None),
        ("[2001:db8::1]", None),
        ("", None),
        (None, None),
    ],
)
def test_registrable_label(host: str | None, label: str | None) -> None:
    assert registrable_label(host) == label


def test_dga_scores_only_the_registrable_label() -> None:
    # Subdomain padding is free for the attacker; the suffix is shared by everyone.
    assert analyze_dga_risk(["https://a1b2c3d4e5f6.google.com/x"]) == calculate_shannon_entropy("google")
    assert analyze_dga_risk(["https://login.xkqjfhzyw.co.uk/"]) == calculate_shannon_entropy("xkqjfhzyw")


def test_dga_takes_the_most_random_link() -> None:
    urls = ["https://www.google.com/", "http://xkqjfhzyw.com/verify", "https://mail.yahoo.com/"]

    assert analyze_dga_risk(urls) == calculate_shannon_entropy("xkqjfhzyw")


def test_dga_skips_ip_literals_and_unparseable_urls() -> None:
    assert analyze_dga_risk([]) == 0.0
    assert analyze_dga_risk(["http://185.220.101.4/login", "http://[::1]/", "http://[broken/"]) == 0.0


def test_dga_strips_invisible_characters_from_the_host() -> None:
    assert analyze_dga_risk(["https://goo​gle.com/"]) == calculate_shannon_entropy("google")


# --- coercion ----------------------------------------------------------------------------


@pytest.fixture(scope="module")
def analyzer() -> CoercionAnalyzer:
    return CoercionAnalyzer()


def test_nlp_urgency_bounds(analyzer: CoercionAnalyzer) -> None:
    loaded = (
        "IMMEDIATE ACTION required. Your account suspend notice. Verify identity now. "
        "Invoice attached. Password expire today."
    )

    assert analyzer.calculate_urgency_score("") == 0.0
    assert analyzer.calculate_urgency_score(loaded) == 1.0  # 5 phrases x 0.25, capped
    assert analyzer.calculate_urgency_score("Final notice.") == 0.25
    assert analyzer.calculate_urgency_score("Final notice. Click here to cancel.") == 0.5


@pytest.mark.parametrize(
    "body",
    [
        "Your account has been suspended.",
        "your account will be suspended within 24 hours",
        "Account suspension pending",
        "Please verify your identity",
        "Your password will expire tonight",
        "Your password has expired",
        "We detected unauthorised access",
    ],
)
def test_coercion_matches_natural_inflections(analyzer: CoercionAnalyzer, body: str) -> None:
    assert analyzer.calculate_urgency_score(body) == 0.25


@pytest.mark.parametrize(
    "body",
    [
        "final​ notice",  # zero-width space between the words
        "fi​nal no⁠tice",  # ... or inside them: the reader still sees "final notice"
        "FINAL\r\n\tNOTICE",  # line break inside the phrase
        "ｆｉｎａｌ ｎｏｔｉｃｅ",  # fullwidth letters (NFKC folds them)
    ],
)
def test_coercion_survives_obfuscation(analyzer: CoercionAnalyzer, body: str) -> None:
    assert analyzer.calculate_urgency_score(body) == 0.25


@pytest.mark.parametrize(
    "body",
    [
        "Pin it to the final noticeboard.",  # whole words only
        "The accountant suspended the audit.",
        "Thanks for the lunch on Tuesday.",
    ],
)
def test_coercion_ignores_lookalike_prose(analyzer: CoercionAnalyzer, body: str) -> None:
    assert analyzer.calculate_urgency_score(body) == 0.0


def test_score_parts_takes_the_higher_part_not_the_sum(analyzer: CoercionAnalyzer) -> None:
    html = visible_text("<p>Your account has been <b>suspended</b>.</p><p>Final notice.</p>")

    assert analyzer.score_parts("Hello, see the attached minutes.", html) == 0.5  # decoy text part
    assert analyzer.score_parts("Final notice. Account suspended.", html) == 0.5  # same message twice
    assert analyzer.score_parts("", visible_text("")) == 0.0


def test_only_the_scan_window_is_read(analyzer: CoercionAnalyzer) -> None:
    assert analyzer.calculate_urgency_score("x" * SCAN_WINDOW_CHARS + " final notice") == 0.0


def test_pattern_is_compiled_once_and_shared() -> None:
    assert CoercionAnalyzer()._pattern is CoercionAnalyzer()._pattern


def test_visible_text_drops_markup_but_keeps_words() -> None:
    assert visible_text('<a href="https://x.example">Verify</a><script>var a=1</script>').split()[0] == "Verify"
    assert visible_text("") == ""
