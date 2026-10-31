"""Build the modern training corpus and a separate synthetic smoke-test corpus.

    python scripts/fetch_modern_corpus.py research             # -> data/raw/research/
    python scripts/fetch_modern_corpus.py synthetic            # -> data/raw/synthetic_2026/
    python scripts/fetch_modern_corpus.py real --limit 1000    # -> data/raw/modern_2026/

``research`` is the era-matched public corpus the reported metrics come from:
SpamAssassin's legitimate mail (2002-03) against Nazario's early phishing
(2004-07), both with intact Received chains. (Enron is unusable here: its public
release strips Received headers, so every benign email would have no route and
the route models would learn "has headers" instead of phishing.)

Synthetic and modern never mix. ``real`` downloads hand-classified, modern phishing from Jose
Nazario's public phishing corpus (CC-BY-4.0, attribution written alongside) and
takes legitimate mail from an mbox you supply (``--benign-mbox``): no public
archive of modern legitimate mail keeps full routing headers. ``synthetic`` writes
generated mail for exercising the pipeline only; a model trained on it learns the
generator, so its metrics are not detection results and it never feeds
``modern_2026``.
"""

import argparse
import base64
import hashlib
import ipaddress
import logging
import mailbox
import random
import sys
import tarfile
import time
from email.parser import BytesHeaderParser
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
from pathlib import Path
from typing import Final

import requests

PROJECT_ROOT: Final = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.core.logger import configure_logging, shutdown_logging  # noqa: E402
from src.extractors.mime_parser import unpack_email  # noqa: E402

MODERN_DIR: Final = PROJECT_ROOT / "data" / "raw" / "modern_2026"
SYNTHETIC_DIR: Final = PROJECT_ROOT / "data" / "raw" / "synthetic_2026"
DOWNLOAD_DIR: Final = PROJECT_ROOT / "data" / "raw" / "downloads" / "nazario"

NAZARIO_BASE_URL: Final = "https://monkey.org/~jose/phishing/"
NAZARIO_MAILBOXES: Final = ("phishing-2025", "phishing-2024", "phishing-2023")  # newest first
NAZARIO_ATTRIBUTION: Final = (
    "Phishing messages: Jose Nazario, phishing corpus, https://monkey.org/~jose/phishing/\n"
    "Licensed under CC BY 4.0 (https://creativecommons.org/licenses/by/4.0/).\n"
    "Changes: each mailbox was split into one .eml file per message; duplicates were dropped.\n"
)
MAX_DOWNLOAD_BYTES: Final = 64 * 1024 * 1024
LABEL_FOLDERS: Final = {0: "benign", 1: "phishing"}

RESEARCH_DIR: Final = PROJECT_ROOT / "data" / "raw" / "research"
SPAMASSASSIN_BASE_URL: Final = "https://spamassassin.apache.org/old/publiccorpus/"
SPAMASSASSIN_DOWNLOAD_DIR: Final = PROJECT_ROOT / "data" / "raw" / "downloads" / "spamassassin"
# Legitimate mail, 2002-03. The 2003 sets re-release some 2002 messages; Message-ID dedup drops them.
SPAMASSASSIN_HAM_ARCHIVES: Final = (
    "20021010_easy_ham.tar.bz2",
    "20021010_hard_ham.tar.bz2",
    "20030228_easy_ham.tar.bz2",
    "20030228_easy_ham_2.tar.bz2",
    "20030228_hard_ham.tar.bz2",
)
# Phishing, 2004-07 (sampled Date headers). private-phishing4.mbox runs 2007-2015, so it is left out.
NAZARIO_EARLY_MAILBOXES: Final = (
    "phishing0.mbox",
    "20051114.mbox",
    "phishing1.mbox",
    "phishing2.mbox",
    "phishing3.mbox",
)
RESEARCH_ATTRIBUTION: Final = (
    "Legitimate mail (benign/): SpamAssassin public corpus, easy_ham and hard_ham, 2002-10-10 and\n"
    "2003-02-28 releases, https://spamassassin.apache.org/old/publiccorpus/\n\n"
    + NAZARIO_ATTRIBUTION.replace("Phishing messages:", "Phishing messages (phishing/), 2004-2007 mailboxes:")
    + "\nBoth sources were deduplicated by Message-ID and by content hash.\n"
)
MAX_MEMBER_BYTES: Final = 10 * 1024 * 1024
DOWNLOAD_ATTEMPTS: Final = 3


# --- real corpus ------------------------------------------------------------------------


def _download(url: str, destination: Path) -> Path:
    """Stream ``url`` to ``destination`` (reused if already there), refusing oversized files."""
    if destination.exists():
        return destination
    destination.parent.mkdir(parents=True, exist_ok=True)
    partial = destination.with_suffix(".part")
    try:
        with requests.get(url, stream=True, timeout=60) as response:
            response.raise_for_status()
            received = 0
            with partial.open("wb") as sink:
                for chunk in response.iter_content(chunk_size=1 << 16):
                    received += len(chunk)
                    if received > MAX_DOWNLOAD_BYTES:
                        raise ValueError(f"{url} exceeds {MAX_DOWNLOAD_BYTES} bytes; refusing")
                    sink.write(chunk)
        partial.replace(destination)
    finally:
        partial.unlink(missing_ok=True)  # never leave a truncated download to be "reused"
    return destination


def _download_with_retries(url: str, destination: Path) -> Path:
    """``_download`` with a few retries on network errors (oversize refusals are not retried)."""
    for attempt in range(1, DOWNLOAD_ATTEMPTS + 1):
        try:
            return _download(url, destination)
        except requests.RequestException:
            if attempt == DOWNLOAD_ATTEMPTS:
                raise
            time.sleep(2**attempt)
    raise AssertionError("unreachable")


def _message_id(raw: bytes) -> str | None:
    try:
        value = BytesHeaderParser().parsebytes(raw).get("Message-ID")
    except Exception:  # a header block too broken to parse: fall back to the content hash
        return None
    if not value:
        return None
    return str(value).strip().lower() or None


def _is_new(raw: bytes, seen: set[str]) -> bool:
    """Record ``raw`` by content hash and Message-ID; False if either was seen before."""
    keys = {f"sha256:{hashlib.sha256(raw).hexdigest()}"}
    if message_id := _message_id(raw):
        keys.add(f"mid:{message_id}")
    if keys & seen:
        return False
    seen.update(keys)
    return True


def split_mbox(mbox_path: Path, out_dir: Path, *, prefix: str, limit: int, seen: set[str]) -> int:
    """Write each message of an mbox as ``<prefix>-NNNNN.eml``; return how many were new."""
    out_dir.mkdir(parents=True, exist_ok=True)
    written = 0
    box = mailbox.mbox(mbox_path, create=False)
    try:
        for index, key in enumerate(box.iterkeys()):
            if written >= limit:
                break
            raw = box.get_bytes(key)
            if not raw.strip() or not _is_new(raw, seen):
                continue
            (out_dir / f"{prefix}-{index:05d}.eml").write_bytes(raw)
            written += 1
    finally:
        box.close()
    return written


def split_tarball(archive: Path, out_dir: Path, *, prefix: str, limit: int, seen: set[str]) -> tuple[int, int]:
    """Write each email in a SpamAssassin ``.tar.bz2`` as ``<prefix>-<name>.eml``.

    Members are read in memory, never extracted, so archive paths cannot escape
    ``out_dir``. Returns (written, skipped as corrupt or oversized).
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    written = skipped = 0
    with tarfile.open(archive, "r:bz2") as tar:
        for member in tar:
            if written >= limit:
                break
            name = member.name.rsplit("/", 1)[-1]
            if not member.isfile() or name == "cmds" or name.startswith("."):
                continue
            if member.size > MAX_MEMBER_BYTES:
                skipped += 1
                continue
            try:
                handle = tar.extractfile(member)
                raw = handle.read() if handle else b""
            except (tarfile.TarError, OSError):
                skipped += 1
                continue
            if not raw.strip():
                skipped += 1
                continue
            if not _is_new(raw, seen):
                continue
            (out_dir / f"{prefix}-{name.split('.', 1)[0]}.eml").write_bytes(raw)
            written += 1
    return written, skipped


def fetch_research_corpus(limit: int = 0, *, out_dir: Path = RESEARCH_DIR) -> dict[str, int]:
    """Populate ``out_dir`` with the era-matched corpus; ``limit`` caps each class (0 = all).

    Corrupt archive members are skipped and counted, never fatal. Returns per-class counts.
    """
    cap = limit or sys.maxsize
    seen: set[str] = set()
    counts = {"benign": 0, "phishing": 0, "skipped": 0}
    for name in SPAMASSASSIN_HAM_ARCHIVES:
        if counts["benign"] >= cap:
            break
        archive = _download_with_retries(SPAMASSASSIN_BASE_URL + name, SPAMASSASSIN_DOWNLOAD_DIR / name)
        written, skipped = split_tarball(
            archive, out_dir / "benign", prefix=name.split(".", 1)[0], limit=cap - counts["benign"], seen=seen
        )
        counts["benign"] += written
        counts["skipped"] += skipped
    for name in NAZARIO_EARLY_MAILBOXES:
        if counts["phishing"] >= cap:
            break
        try:
            mbox_path = _download_with_retries(NAZARIO_BASE_URL + name, DOWNLOAD_DIR / name)
            counts["phishing"] += split_mbox(
                mbox_path, out_dir / "phishing", prefix=name.removesuffix(".mbox"), limit=cap - counts["phishing"], seen=seen
            )
        except OSError as exc:
            # Real phishing archives trip antivirus: a quarantined mailbox vanishes or refuses to
            # open mid-run. Skip it and say so; never weaken the scanner to get it back.
            counts["mailboxes_unavailable"] = counts.get("mailboxes_unavailable", 0) + 1
            print(f"Skipped {name}: {exc.strerror or exc} (quarantined by antivirus?)")
    (out_dir / "ATTRIBUTION.txt").write_text(RESEARCH_ATTRIBUTION, encoding="utf-8")
    return counts


def download_ceas_or_phishtank(limit: int = 1000, *, benign_mbox: Path | None = None, out_dir: Path = MODERN_DIR) -> dict[str, int]:
    """Populate ``out_dir``: up to ``limit`` phishing emails from the Nazario corpus, plus
    up to ``limit`` legitimate emails from ``benign_mbox`` if one is given.

    (CEAS-08 and PhishTank need accounts this script cannot hold, and neither ships raw
    emails with routing headers; the Nazario corpus is public, modern and complete.)
    """
    seen: set[str] = set()
    counts = {"phishing": 0, "benign": 0}
    for name in NAZARIO_MAILBOXES:
        remaining = limit - counts["phishing"]
        if remaining <= 0:
            break
        mbox_path = _download(NAZARIO_BASE_URL + name, DOWNLOAD_DIR / f"{name}.mbox")
        counts["phishing"] += split_mbox(mbox_path, out_dir / "phishing", prefix=name, limit=remaining, seen=seen)
    (out_dir / "ATTRIBUTION.txt").write_text(NAZARIO_ATTRIBUTION, encoding="utf-8")
    if benign_mbox is not None:
        counts["benign"] = split_mbox(benign_mbox, out_dir / "benign", prefix="benign", limit=limit, seen=seen)
    return counts


# --- synthetic corpus ---------------------------------------------------------------------


@dataclass(frozen=True)
class _Network:
    name: str
    cidr: str
    helo: str


# Address space each sender family really uses, so hops look like their real-world origin.
_MICROSOFT = _Network("Microsoft 365", "40.107.0.0/16", "{n}.outbound.protection.outlook.com")
_GOOGLE = _Network("Google Workspace", "209.85.128.0/17", "mail-{n}.google.com")
_AMAZON_SES = _Network("Amazon SES", "54.240.0.0/18", "a{n}-11.smtp-out.amazonses.com")
_HOSTILE = (
    _Network("bulletproof VPS", "185.220.100.0/22", "vps{n}.host.example"),
    _Network("compromised host", "45.83.64.0/22", "srv{n}.cloudhost.example"),
    _Network("residential proxy", "103.151.100.0/22", "dyn-{n}.isp.example"),
)
_BRANDS: Final = (
    ("Microsoft", "microsoft.com"),
    ("PayPal", "paypal.com"),
    ("Apple", "apple.com"),
    ("DocuSign", "docusign.net"),
    ("Amazon", "amazon.com"),
    ("DHL", "dhl.com"),
)
_LOOKALIKE_TEMPLATES: Final = ("{b}-secure-{n}.com", "{b}-verify{n}.net", "account-{b}-{n}.co", "{b}support{n}.info")
_ZERO_WIDTH: Final = ("​", "‌", "‍", "⁠")
_HOMOGLYPHS: Final = {"a": "а", "e": "е", "o": "о", "p": "р", "c": "с"}
_PARTNER_DOMAINS: Final = ("northwind.example", "contoso.example", "fabrikam.example", "tailspin.example")
_BENIGN_SUBJECTS: Final = (
    "Q3 roadmap review notes",
    "Invoice INV-{n} for October",
    "Your order #{n} has shipped",
    "Weekly digest: {n} updates",
    "Meeting moved to Thursday",
    "Re: draft contract v{n}",
)
_PHISH_SUBJECTS: Final = (
    "Action required: verify your {b} account",
    "{b}: unusual sign-in activity",
    "Your {b} password expires today",
    "Shared document: Payment_Remittance_{n}.pdf",
    "Final notice: invoice {n} overdue",
    "Your parcel could not be delivered",
)


def _ip(network: _Network, rng: random.Random) -> str:
    net = ipaddress.ip_network(network.cidr)
    return str(net[rng.randrange(1, net.num_addresses - 1)])


def _received_chain(
    networks: list[_Network], start: datetime, rng: random.Random, *, private_hop: bool, regress: bool
) -> list[str]:
    """Received headers for a route through ``networks``, newest first as MTAs prepend them."""
    hops = [(net.helo.format(n=rng.randrange(10, 99)), _ip(net, rng)) for net in networks]
    if private_hop and len(hops) >= 2:
        # Strictly inside the sender's path: a public sender hop always follows it, as in a
        # forged chain. (A private client of our own MX would be receiver-internal.)
        hops.insert(len(hops) // 2, (f"relay{rng.randrange(1, 9)}.internal", f"10.{rng.randrange(256)}.{rng.randrange(256)}.{rng.randrange(1, 255)}"))
    hops.append(("mx-edge.corp.example", _ip(_MICROSOFT, rng)))  # our own boundary
    lines, when = [], start
    regress_at = rng.randrange(1, len(hops)) if regress and len(hops) > 1 else None
    for position, (helo, ip) in enumerate(hops):
        when += timedelta(seconds=rng.randint(1, 45))
        stamp = when - timedelta(minutes=rng.randint(3, 20)) if position == regress_at else when
        receiver = hops[position + 1][0] if position + 1 < len(hops) else "inbox.corp.example"
        lines.append(
            f"Received: from {helo} ({helo} [{ip}])\r\n\tby {receiver} with ESMTPS id {rng.randrange(16**10):010X};"
            f" {format_datetime(stamp)}"
        )
    return lines[::-1]


def _obfuscate(text: str, rng: random.Random) -> str:
    """Homoglyphs and zero-width characters, as kits use to dodge keyword filters."""
    out = []
    for char in text:
        out.append(_HOMOGLYPHS.get(char, char) if rng.random() < 0.25 else char)
        if rng.random() < 0.15:
            out.append(rng.choice(_ZERO_WIDTH))
    return "".join(out)


def _encoded_word(text: str) -> str:
    return f"=?utf-8?b?{base64.b64encode(text.encode()).decode('ascii')}?="


def _html_smuggling_attachment(rng: random.Random, boundary: str) -> str:
    """An HTML attachment that rebuilds an (inert, random) archive in the browser via a Blob."""
    blob = base64.b64encode(rng.randbytes(rng.randint(256, 2048))).decode("ascii")
    page = (
        "<html><body><script>"
        f"var d=atob('{blob}');var u=new Uint8Array(d.length);for(var i=0;i<d.length;i++)u[i]=d.charCodeAt(i);"
        "var a=document.createElement('a');a.href=URL.createObjectURL(new Blob([u]));"
        f"a.download='Remittance_{rng.randrange(1000, 9999)}.iso';a.click();"
        "</script></body></html>"
    )
    encoded = base64.encodebytes(page.encode()).decode("ascii").replace("\n", "\r\n")
    return (
        f"--{boundary}\r\nContent-Type: text/html; name=\"Remittance_Advice.html\"\r\n"
        "Content-Disposition: attachment; filename=\"Remittance_Advice.html\"\r\n"
        f"Content-Transfer-Encoding: base64\r\n\r\n{encoded}"
    )


def _benign(rng: random.Random, index: int, when: datetime) -> bytes:
    kind = rng.choice(("partner", "brand_notice", "newsletter", "forwarded", "reseller"))
    partner = rng.choice(_PARTNER_DOMAINS)
    if kind == "brand_notice":
        brand, domain = rng.choice(_BRANDS)
        sender, network = (f'"{brand}" <no-reply@account.{domain}>', domain), _AMAZON_SES
    elif kind == "reseller":
        # Legitimate mail that names a brand it does not own (partners, resellers, marketplaces).
        brand, _ = rng.choice(_BRANDS)
        sender, network = (f'"{partner.split(".")[0].title()} | {brand} Partner" <sales@{partner}>', partner), _MICROSOFT
    elif kind == "newsletter":
        sender, network = (f'"{partner.split(".")[0].title()} News" <news@mail.{partner}>', partner), _AMAZON_SES
    else:
        sender, network = (f'"Priya Shah" <priya.shah@{partner}>', partner), rng.choice((_MICROSOFT, _GOOGLE))
    from_header, from_domain = sender
    spf = "fail" if kind == "forwarded" else rng.choices(("pass", "none"), (0.92, 0.08))[0]
    arc = "pass" if kind == "forwarded" else "none"
    headers = [
        *_received_chain([network] * rng.randint(1, 3), when, rng, private_hop=rng.random() < 0.05, regress=False),
        "ARC-Seal: i=1; a=rsa-sha256; cv=none; d=corp.example; s=arc; b=QVJDc2VhbA==" if arc == "pass" else "",
        f"DKIM-Signature: v=1; a=rsa-sha256; d={from_domain}; s=s1; h=from:subject:date; bh=Ym9keQ==; b=c2ln",
        f"Authentication-Results: mx-edge.corp.example; spf={spf} smtp.mailfrom={from_domain};"
        f" dkim=pass header.d={from_domain}; dmarc=pass header.from={from_domain}; arc={arc}",
        f"From: {from_header}",
        "To: team@corp.example",
        f"Subject: {rng.choice(_BENIGN_SUBJECTS).format(n=rng.randrange(1000, 99999))}",
        f"Date: {format_datetime(when)}",
        f"Message-ID: <{rng.randrange(16**16):016x}.{index}@{from_domain}>",
        "List-Unsubscribe: <https://mail.example/unsubscribe>" if kind == "newsletter" else "",
        "MIME-Version: 1.0",
        "Content-Type: text/plain; charset=utf-8",
    ]
    links = " ".join(f"https://www.{from_domain}/p/{rng.randrange(10**6)}" for _ in range(rng.randint(0, 2)))
    body = f"Hello team,\r\n\r\nPlease find the update below. {links}\r\n\r\nThanks\r\n"
    return "\r\n".join([h for h in headers if h] + ["", body]).encode("utf-8")


def _phishing(rng: random.Random, index: int, when: datetime) -> bytes:
    brand, brand_domain = rng.choice(_BRANDS)
    kind = rng.choice(("lookalike", "lookalike", "smuggling", "compromised"))
    if kind == "compromised":
        # A real account at a real (partner) domain: authentication passes, the content lies.
        domain = rng.choice(_PARTNER_DOMAINS)
        auth = "spf=pass smtp.mailfrom={d}; dkim=pass header.d={d}; dmarc=pass header.from={d}"
        networks = [rng.choice((_MICROSOFT, _GOOGLE))]
        display = f"{brand} Billing"
    else:
        domain = rng.choice(_LOOKALIKE_TEMPLATES).format(b=brand.lower(), n=rng.randrange(10, 999))
        auth = rng.choice((
            "spf=fail smtp.mailfrom={d}; dkim=none; dmarc=fail header.from={d}",
            "spf=softfail smtp.mailfrom={d}; dkim=fail header.d={d}; dmarc=fail header.from={d}",
            "spf=none; dkim=none; dmarc=none",
        ))
        networks = [rng.choice(_HOSTILE) for _ in range(rng.randint(1, 3))]
        display = rng.choice((
            _obfuscate(f"{brand} Security", rng),
            f"{brand} Support",
            # Plenty of lures name no brand at all.
            "Accounts Payable",
            "IT Helpdesk",
            "HR Department",
        ))
    subject = rng.choice(_PHISH_SUBJECTS).format(b=brand, n=rng.randrange(1000, 99999))
    url_host = f"login.{domain}" if kind != "compromised" else rng.choice(_LOOKALIKE_TEMPLATES).format(b=brand.lower(), n=index)
    url = f"https://{url_host}/verify?u={rng.randrange(16**8):08x}"
    href = "".join(c + (rng.choice(_ZERO_WIDTH) if rng.random() < 0.1 else "") for c in url)
    boundary = f"=_{rng.randrange(16**12):012x}"
    html = (
        f"<html><body><p>Dear customer,</p><p>{_obfuscate('We detected unusual activity.', rng)}</p>"
        f'<p><a href="{href}">Verify your {brand} account</a></p></body></html>'
    )
    parts = [
        f"--{boundary}\r\nContent-Type: text/html; charset=utf-8\r\n\r\n{html}",
        _html_smuggling_attachment(rng, boundary) if kind == "smuggling" else "",
    ]
    headers = [
        *_received_chain(
            networks, when, rng, private_hop=rng.random() < 0.35, regress=rng.random() < 0.3
        ),
        f"Authentication-Results: mx-edge.corp.example; {auth.format(d=domain)}",
        f"From: {_encoded_word(display) if not display.isascii() else display} <alert@{domain}>",
        f"Reply-To: billing@{rng.choice(('collect', 'payments', 'desk'))}-{index}.example" if rng.random() < 0.5 else "",
        "To: victim@corp.example",
        f"Subject: {_encoded_word(subject) if rng.random() < 0.4 else subject}",
        f"Date: {format_datetime(when)}",
        f"Message-ID: <{rng.randrange(16**16):016x}.{index}@{domain}>",
        "MIME-Version: 1.0",
        f'Content-Type: multipart/mixed; boundary="{boundary}"',
    ]
    body = "\r\n".join(p for p in parts if p) + f"\r\n--{boundary}--\r\n"
    return "\r\n".join([h for h in headers if h] + ["", body]).encode("utf-8")


def generate_synthetic_corpus(out_dir: Path = SYNTHETIC_DIR, *, count: int = 1000, seed: int = 2026) -> dict[str, int]:
    """Write ``count`` distinct emails (half benign, half phishing) under ``out_dir``."""
    rng = random.Random(seed)
    start = datetime(2025, 1, 1, tzinfo=UTC)
    seen: set[str] = set()
    counts = {"benign": 0, "phishing": 0}
    for label, folder in LABEL_FOLDERS.items():
        (out_dir / folder).mkdir(parents=True, exist_ok=True)
    attempts = 0
    while sum(counts.values()) < count:
        attempts += 1
        if attempts > count * 5:
            raise RuntimeError("generator keeps producing duplicates; widen its variety")
        label = 1 if counts["phishing"] < counts["benign"] else 0
        if counts[LABEL_FOLDERS[label]] >= (count + 1 - label) // 2:
            label = 1 - label
        index = sum(counts.values())
        when = start + timedelta(minutes=rng.randrange(60 * 24 * 600))
        raw = (_phishing if label else _benign)(rng, index, when)
        digest = hashlib.sha256(raw).hexdigest()
        if digest in seen:
            continue
        seen.add(digest)
        folder = LABEL_FOLDERS[label]
        (out_dir / folder / f"{folder}-{counts[folder]:05d}.eml").write_bytes(raw)
        counts[folder] += 1
    (out_dir / "README.txt").write_text(
        "Synthetic emails generated by scripts/fetch_modern_corpus.py for pipeline smoke tests.\n"
        "Not real mail. Do not train production models on it or report metrics from it.\n",
        encoding="utf-8",
    )
    return counts


def validate_corpus(root: Path) -> int:
    """Parse every .eml with the production MIME unpacker; return how many were checked."""
    checked = 0
    for path in sorted(root.rglob("*.eml")):
        message, text, html, _ = unpack_email(path.read_bytes())
        if not (message.get("From") and (text or html)):
            raise ValueError(f"{path} has no sender or no body")
        checked += 1
    return checked


def prune_invalid(root: Path) -> tuple[int, int]:
    """Delete .eml files the production unpacker cannot read as an email; return (kept, removed).

    Twenty-year-old mail has its share of truncated and header-only messages. They are
    dropped here, silently apart from the count, rather than failing the whole fetch.
    """
    kept = removed = 0
    for path in sorted(root.rglob("*.eml")):
        try:
            message, text, html, _ = unpack_email(path.read_bytes())
            usable = bool(message.get("From") and (text or html))
        except Exception:
            usable = False
        if usable:
            kept += 1
        else:
            path.unlink()
            removed += 1
    return kept, removed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    research = commands.add_parser("research", help="download the era-matched public corpus (~85 MB)")
    research.add_argument("--limit", type=int, default=0, help="emails per class; 0 = all")
    research.add_argument("--out", type=Path, default=RESEARCH_DIR)
    synthetic = commands.add_parser("synthetic", help="generate the smoke-test corpus (no network)")
    synthetic.add_argument("--count", type=int, default=1000)
    synthetic.add_argument("--seed", type=int, default=2026)
    synthetic.add_argument("--out", type=Path, default=SYNTHETIC_DIR)
    real = commands.add_parser("real", help="download the Nazario phishing corpus (~40 MB)")
    real.add_argument("--limit", type=int, default=1000, help="emails per class")
    real.add_argument("--benign-mbox", type=Path, help="mbox of legitimate mail (e.g. a mailbox export)")
    real.add_argument("--out", type=Path, default=MODERN_DIR)
    args = parser.parse_args(argv)

    # Real phishing is full of MIME defects; record them in the JSON log, not on the console.
    configure_logging(level=logging.WARNING)
    try:
        if args.command == "research":
            counts = fetch_research_corpus(args.limit, out_dir=args.out)
            kept, removed = prune_invalid(args.out)
            benign, phishing = (len(list((args.out / folder).glob("*.eml"))) for folder in ("benign", "phishing"))
            print(f"Wrote {counts} under {args.out}")
            print(f"Kept {kept} parseable emails (benign {benign}, phishing {phishing}); dropped {removed} unusable")
            return 0
        if args.command == "synthetic":
            counts = generate_synthetic_corpus(args.out, count=args.count, seed=args.seed)
        else:
            counts = download_ceas_or_phishtank(args.limit, benign_mbox=args.benign_mbox, out_dir=args.out)
        print(f"Wrote {counts} under {args.out}")
        print(f"Validated {validate_corpus(args.out)} emails with the production MIME unpacker")
    finally:
        shutdown_logging()
    if args.command == "real" and counts["benign"] == 0:
        print("No legitimate mail yet: pass --benign-mbox before training on this corpus.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
