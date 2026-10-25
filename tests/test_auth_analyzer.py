import base64
import email.policy
from email.message import EmailMessage
from email.parser import BytesParser

import pytest

from src.core.config import DEFAULT_BRAND_DOMAINS, DEFAULT_HIGH_RISK_BRANDS, get_settings
from src.forensics.auth_analyzer import analyze_identity
from src.schemas import AuthStatus, HeaderForensics

BRANDS = get_settings().HIGH_RISK_BRAND_KEYWORDS
_PARSER = BytesParser(policy=email.policy.default)


def _msg(*headers: str) -> EmailMessage:
    raw = "\r\n".join((*headers, "To: victim@corp.example", "", "body", ""))
    return _PARSER.parsebytes(raw.encode("ascii"))


def _b_word(text: str) -> str:
    return f"=?utf-8?b?{base64.b64encode(text.encode()).decode('ascii')}?="


# --- Authentication-Results --------------------------------------------------


@pytest.mark.parametrize(
    "dkim_clause",
    [
        pytest.param(" dkim=none (message not signed) header.d=none;", id="explicit-none"),
        pytest.param("", id="clause-absent"),
    ],
)
def test_missing_dkim_signature_maps_to_none(dkim_clause: str) -> None:
    msg = _msg(
        "From: billing@sender.example",
        "Authentication-Results: mx.corp.example; spf=pass smtp.mailfrom=sender.example;"
        f"{dkim_clause} dmarc=pass header.from=sender.example",
    )

    findings = analyze_identity(msg, BRANDS)

    assert findings["dkim"] is AuthStatus.NONE
    assert findings["spf"] is AuthStatus.PASS
    assert findings["dmarc"] is AuthStatus.PASS


def test_dmarc_policy_failure() -> None:
    msg = _msg(
        "From: service@paypal.com",
        "Authentication-Results: mx.google.com;\r\n"
        "       dkim=fail header.i=@paypal.com header.s=pp-dkim1 header.b=Zm9v;\r\n"
        "       spf=softfail (google.com: domain of transitioning service@paypal.com\r\n"
        "        does not designate 185.220.101.4 as permitted sender)\r\n"
        "        smtp.mailfrom=service@paypal.com;\r\n"
        "       dmarc=fail (p=REJECT sp=REJECT dis=REJECT) header.from=paypal.com",
    )

    findings = analyze_identity(msg, BRANDS)

    assert findings["dmarc"] is AuthStatus.FAIL
    assert findings["spf"] is AuthStatus.FAIL  # softfail is a negative assertion
    assert findings["dkim"] is AuthStatus.FAIL
    assert findings["display_name_spoof_risk"] == 0.0  # no display name to spoof with


def test_valid_arc_chain_through_mailing_list() -> None:
    msg = _msg(
        "ARC-Seal: i=2; a=rsa-sha256; t=1791280800; cv=pass; d=google.com; s=arc-20240605; b=AAA",
        "ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc; bh=x; b=BBB",
        "ARC-Authentication-Results: i=2; mx.google.com; dkim=pass header.i=@list.example.org;"
        " arc=pass (i=1); spf=pass smtp.mailfrom=list.example.org; dmarc=fail header.from=sender.example",
        "Authentication-Results: mx.google.com;\r\n"
        "       dkim=pass header.i=@list.example.org header.s=lists;\r\n"
        "       arc=pass (i=2 spf=fail spfdomain=sender.example dkim=fail\r\n"
        "        dkdomain=sender.example dmarc=fail fromdomain=sender.example);\r\n"
        "       spf=pass (google.com: domain of owner@list.example.org designates 209.85.220.41)\r\n"
        "        smtp.mailfrom=owner@list.example.org;\r\n"
        "       dmarc=pass (p=NONE sp=NONE dis=NONE arc=pass) header.from=sender.example",
        "ARC-Seal: i=1; a=rsa-sha256; t=1791280700; cv=none; d=list.example.org; s=arc; b=CCC",
        "ARC-Authentication-Results: i=1; mx.list.example.org; dkim=pass header.i=@sender.example;"
        " spf=pass smtp.mailfrom=sender.example",
        "From: Alice <alice@sender.example>",
    )

    findings = analyze_identity(msg, BRANDS)

    # The arc=pass comment carries the *original* hop's failures; those must not leak out.
    assert findings["arc"] is AuthStatus.PASS
    assert findings["spf"] is AuthStatus.PASS
    assert findings["dkim"] is AuthStatus.PASS
    assert findings["dmarc"] is AuthStatus.PASS


def test_folded_whitespace_and_missing_delimiters() -> None:
    msg = _msg(
        "From: a@a.example",
        "Authentication-Results: mx.corp.example\r\n"
        "\tspf = pass smtp.mailfrom=a.example\r\n"
        "\tDKIM/1\r\n"
        "\t=\r\n"
        "\tPass header.d=a.example dmarc=pass header.from=a.example",
    )

    findings = analyze_identity(msg, BRANDS)

    assert (findings["spf"], findings["dkim"], findings["dmarc"], findings["arc"]) == (
        AuthStatus.PASS,
        AuthStatus.PASS,
        AuthStatus.PASS,
        AuthStatus.NONE,
    )


def test_attacker_text_in_comments_and_values_is_ignored() -> None:
    msg = _msg(
        'From: "x" <x@evil.example>',
        "Authentication-Results: mx.corp.example;"
        ' spf=fail (domain of "dmarc=pass"@evil.example does not designate 185.220.101.4)'
        ' smtp.mailfrom="dkim=pass arc=pass"@evil.example;'
        " dkim=none (dkim=pass hidden (nested arc=pass)) header.d=dkim=pass;"
        " dmarc=fail header.from=evil.example",
    )

    findings = analyze_identity(msg, BRANDS)

    assert findings["spf"] is AuthStatus.FAIL
    assert findings["dkim"] is AuthStatus.NONE
    assert findings["dmarc"] is AuthStatus.FAIL
    assert findings["arc"] is AuthStatus.NONE


def test_stray_parenthesis_cannot_hide_later_results() -> None:
    msg = _msg(
        "From: x@evil.example",
        "Authentication-Results: mx.corp.example; spf=fail (unterminated comment"
        " smtp.mailfrom=x@evil.example; dkim=fail header.d=evil.example; dmarc=fail",
    )

    findings = analyze_identity(msg, BRANDS)

    assert findings["dkim"] is AuthStatus.FAIL
    assert findings["dmarc"] is AuthStatus.FAIL


@pytest.mark.parametrize(
    ("clauses", "expected"),
    [
        pytest.param("dkim=pass header.d=a.example; dkim=fail header.d=b.example", AuthStatus.FAIL),
        pytest.param("dkim=pass header.d=a.example; dkim=pass header.d=b.example", AuthStatus.PASS),
        pytest.param("dkim=none; dkim=pass header.d=a.example", AuthStatus.NONE),
        pytest.param("dkim=bestguesspass header.d=a.example", AuthStatus.NONE),
    ],
)
def test_duplicate_or_unknown_results_never_upgrade(clauses: str, expected: AuthStatus) -> None:
    msg = _msg("From: a@a.example", f"Authentication-Results: mx.corp.example; {clauses}")

    assert analyze_identity(msg, BRANDS)["dkim"] is expected


def test_only_topmost_results_header_is_trusted_by_default() -> None:
    msg = _msg(
        "Authentication-Results: mx.corp.example; spf=fail smtp.mailfrom=evil.example; dmarc=fail",
        "Received: from relay.evil.example (relay.evil.example [185.220.101.4]) by mx.corp.example;"
        " Tue, 06 Oct 2026 10:00:00 +0000",
        # Forged by the sender before the message ever reached our boundary.
        "Authentication-Results: mx.corp.example; spf=pass; dkim=pass; dmarc=pass; arc=pass",
        "From: x@evil.example",
    )

    findings = analyze_identity(msg, BRANDS)

    assert (findings["spf"], findings["dkim"], findings["dmarc"], findings["arc"]) == (
        AuthStatus.FAIL,
        AuthStatus.NONE,
        AuthStatus.FAIL,
        AuthStatus.NONE,
    )


def test_trusted_authserv_ids_skip_headers_from_other_hosts() -> None:
    msg = _msg(
        "Authentication-Results: relay.evil.example; spf=pass dkim=pass dmarc=pass",
        "Authentication-Results: MX.Corp.Example; spf=fail dmarc=fail",
        "From: x@evil.example",
    )

    trusted = analyze_identity(msg, BRANDS, trusted_authserv_ids=frozenset({"mx.corp.example"}))
    untrusted = analyze_identity(msg, BRANDS, trusted_authserv_ids=frozenset({"mx.other.example"}))

    assert (trusted["spf"], trusted["dmarc"]) == (AuthStatus.FAIL, AuthStatus.FAIL)
    assert (untrusted["spf"], untrusted["dkim"], untrusted["dmarc"]) == (AuthStatus.NONE,) * 3


def test_no_authentication_results_defaults_to_none() -> None:
    findings = analyze_identity(_msg("From: a@a.example"), BRANDS)

    assert (findings["spf"], findings["dkim"], findings["dmarc"], findings["arc"]) == (
        (AuthStatus.NONE,) * 4
    )


# --- domains and decoding ----------------------------------------------------


def test_root_domains_extracted_offline() -> None:
    msg = _msg(
        "From: Billing <billing@mail.evil.example.com>",
        "Reply-To: collect@billing.evil-collector.co.uk",
        "Return-Path: <bounce+123@bounces.esp.example.net>",
    )

    findings = analyze_identity(msg, BRANDS)

    assert findings["from_domain"] == "example.com"
    assert findings["reply_to_domain"] == "evil-collector.co.uk"
    assert findings["return_path_domain"] == "example.net"


def test_null_return_path_and_missing_headers() -> None:
    findings = analyze_identity(_msg("Return-Path: <>"), BRANDS)

    assert findings["return_path_domain"] is None
    assert findings["from_domain"] is None
    assert findings["reply_to_domain"] is None
    assert findings["subject"] is None


def test_subject_is_decoded() -> None:
    msg = _msg("From: a@a.example", "Subject: =?iso-8859-1?q?Compte_bloqu=E9?= - action requise")

    assert analyze_identity(msg, BRANDS)["subject"] == "Compte bloqué - action requise"


# --- display-name spoofing ---------------------------------------------------


def test_display_name_spoof_apple_support_from_evil_com() -> None:
    findings = analyze_identity(_msg('From: "Apple Support" <hacker@evil.com>'), BRANDS)

    assert findings["display_name_spoof_risk"] == 1.0
    assert findings["impersonated_brand"] == "apple"
    assert findings["from_domain"] == "evil.com"


@pytest.mark.parametrize(
    "sender",
    [
        pytest.param('"Apple" <no_reply@email.apple.com>', id="apple-subdomain"),
        pytest.param('"PayPal" <service@paypal.co.uk>', id="paypal-cctld"),
        pytest.param('"Microsoft Outlook" <no-reply@microsoft.com>', id="brand-family"),
        pytest.param('"HMRC" <noreply@confirmation.hmrc.gov.uk>', id="gov-suffix"),
    ],
)
def test_genuine_brand_senders_are_not_flagged(sender: str) -> None:
    findings = analyze_identity(_msg(f"From: {sender}"), BRANDS)

    assert findings["display_name_spoof_risk"] == 0.0
    assert findings["impersonated_brand"] is None


def test_consumer_mailbox_cannot_vouch_for_its_brand() -> None:
    findings = analyze_identity(_msg('From: "Microsoft account team" <ms-security@outlook.com>'), BRANDS)

    assert findings["display_name_spoof_risk"] == 1.0
    assert findings["impersonated_brand"] == "microsoft"


@pytest.mark.parametrize(
    ("display_name", "brand"),
    [
        pytest.param(_b_word("PayPal Billing"), "paypal", id="rfc2047-word"),
        pytest.param('"=?utf-8?q?Micro=73oft?="', "microsoft", id="word-inside-quotes"),
        pytest.param(_b_word("Аррlе ID"), "apple", id="cyrillic-homoglyphs"),
        pytest.param(_b_word("Pay​Pal"), "paypal", id="zero-width-space"),
        pytest.param(_b_word("Ｎｅｔｆｌｉｘ"), "netflix", id="fullwidth"),
        pytest.param('"P a y P a l"', "paypal", id="letter-spacing"),
        pytest.param('"PayPa1 Security"', "paypal", id="leetspeak"),
        pytest.param('"Rnicrosoft 365"', "microsoft", id="rn-for-m"),
        pytest.param('"Bank of America Alerts"', "bankofamerica", id="multi-word-brand"),
        pytest.param('"AppleID Verification"', "apple", id="brand-prefix"),
        pytest.param('"service@paypal.com"', "paypal", id="address-as-display-name"),
    ],
)
def test_obfuscated_brand_display_names_are_flagged(display_name: str, brand: str) -> None:
    findings = analyze_identity(_msg(f"From: {display_name} <alert@evil-domain.example>"), BRANDS)

    assert findings["impersonated_brand"] == brand
    assert findings["display_name_spoof_risk"] == 1.0


@pytest.mark.parametrize(
    "display_name",
    ["Purchase Department", "Product Groups", "First Data Payroll", "Pineapple Studio", "Zoomies Pet Care"],
)
def test_brand_substrings_inside_words_are_not_flagged(display_name: str) -> None:
    findings = analyze_identity(_msg(f'From: "{display_name}" <team@vendor.example>'), BRANDS)

    assert findings["display_name_spoof_risk"] == 0.0


def test_unmapped_brand_falls_back_to_dot_com() -> None:
    brands = frozenset({"acmebank"})

    spoof = analyze_identity(_msg('From: "AcmeBank" <x@evil.example>'), brands, canonical_domains={})
    genuine = analyze_identity(_msg('From: "AcmeBank" <x@acmebank.com>'), brands, canonical_domains={})

    assert spoof["display_name_spoof_risk"] == 1.0
    assert genuine["display_name_spoof_risk"] == 0.0


def test_every_default_brand_has_canonical_domains() -> None:
    assert DEFAULT_HIGH_RISK_BRANDS <= DEFAULT_BRAND_DOMAINS.keys()


def test_findings_merge_into_header_forensics() -> None:
    msg = _msg(
        'From: "Apple Support" <hacker@evil.com>',
        "Authentication-Results: mx.corp.example; spf=fail; dkim=none; dmarc=fail; arc=none",
    )

    forensics = HeaderForensics(
        **analyze_identity(msg, BRANDS),
        route_hop_count=0,
        private_ip_leak=False,
        timestamp_regression_flag=False,
    )

    assert forensics.dmarc is AuthStatus.FAIL
    assert forensics.display_name_spoof_risk == 1.0
    assert forensics.impersonated_brand == "apple"


# --- subject spoofing ----------------------------------------------------------


def test_brand_only_in_subject_is_a_weaker_spoof_signal() -> None:
    findings = analyze_identity(
        _msg('From: "Billing Team" <billing@evil.example>', "Subject: Your PayPal account is limited"), BRANDS
    )

    assert findings["impersonated_brand"] == "paypal"
    assert findings["display_name_spoof_risk"] == 0.5


def test_display_name_spoof_outranks_subject() -> None:
    findings = analyze_identity(
        _msg('From: "PayPal" <x@evil.example>', "Subject: Microsoft 365 password expiry"), BRANDS
    )

    assert findings["impersonated_brand"] == "paypal"
    assert findings["display_name_spoof_risk"] == 1.0


def test_encoded_homoglyph_subject_is_folded_before_matching() -> None:
    findings = analyze_identity(
        _msg("From: notices@evil.example", f"Subject: {_b_word('Αpple ID locked')}"), BRANDS
    )

    assert findings["subject"] == "Αpple ID locked"
    assert findings["impersonated_brand"] == "apple"
    assert findings["display_name_spoof_risk"] == 0.5


def test_brand_subject_from_the_brands_own_domain_is_clean() -> None:
    findings = analyze_identity(_msg("From: service@paypal.com", "Subject: Your PayPal receipt"), BRANDS)

    assert findings["display_name_spoof_risk"] == 0.0
    assert findings["impersonated_brand"] is None
