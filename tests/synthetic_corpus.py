"""Deterministic SpamAssassin-style corpus for smoke-testing the training pipeline.

The classes overlap on purpose (some ham fails authentication, some spam passes),
so a pipeline that works yields a good but not perfect score.
"""

import hashlib
import random
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
from pathlib import Path

from src.core.network import is_bogon, parse_ip


def _public_ip(rng: random.Random) -> str:
    while True:
        candidate = ".".join(str(rng.randint(1, 223)) for _ in range(4))
        ip = parse_ip(candidate)
        if ip is not None and not is_bogon(ip):
            return candidate


def _received(hops: list[str], start: datetime, rng: random.Random, *, regress_at: int | None) -> list[str]:
    lines, when = [], start
    for position, ip in enumerate(hops):
        when += timedelta(seconds=rng.randint(1, 90))
        stamp = when - timedelta(minutes=6) if position == regress_at else when
        lines.append(
            f"Received: from relay{position}.example.net (relay{position}.example.net [{ip}])"
            f" by mx{position}.example.net with ESMTP id {rng.randrange(16**8):08x}; {format_datetime(stamp)}"
        )
    return lines[::-1]  # newest first, as MTAs prepend


def _message(headers: list[str], content_type: str, body: str) -> bytes:
    lines = [*headers, "MIME-Version: 1.0", f"Content-Type: {content_type}", "", body, ""]
    return "\r\n".join(lines).encode("utf-8")


def _ham(rng: random.Random, index: int) -> bytes:
    hops = [_public_ip(rng) for _ in range(rng.randint(2, 5))]
    auth = "pass" if rng.random() < 0.85 else "fail"
    urls = " ".join(f"https://lists.example.org/archive/{index}/{n}" for n in range(rng.randint(0, 2)))
    headers = [
        *_received(hops, datetime(2026, 3, 1, tzinfo=UTC) + timedelta(hours=index), rng, regress_at=None),
        f"Authentication-Results: mx.corp.example; spf={auth} smtp.mailfrom=lists.example.org; dkim=pass",
        f"From: Team Member {index} <member{index}@lists.example.org>",
        "To: dev@lists.example.org",
        f"Subject: Re: build notes {index}",
    ]
    return _message(headers, "text/plain; charset=utf-8", f"Notes for today. {urls}")


def _spam(rng: random.Random, index: int) -> bytes:
    hops = [_public_ip(rng) for _ in range(rng.randint(1, 7))]
    if len(hops) >= 3 and rng.random() < 0.45:
        hops[len(hops) // 2] = f"10.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
    regress_at = rng.randrange(1, len(hops)) if len(hops) > 1 and rng.random() < 0.35 else None
    auth = "fail" if rng.random() < 0.6 else "pass"
    sender = f"PayPal Security <alert@secure-{index}.example.ru>" if rng.random() < 0.5 else f"Deals <x{index}@promo.example.biz>"
    links = "".join(f'<a href="https://login-{index}.example.ru/v/{n}">Verify</a>' for n in range(rng.randint(2, 8)))
    headers = [
        *_received(hops, datetime(2026, 3, 1, tzinfo=UTC) + timedelta(hours=index), rng, regress_at=regress_at),
        f"Authentication-Results: mx.corp.example; spf={auth}; dkim=none; dmarc={auth}",
        f"From: {sender}",
        "To: victim@corp.example",
        "Subject: =?utf-8?b?QWNjb3VudCBzdXNwZW5kZWQ=?=",
    ]
    return _message(headers, "text/html; charset=utf-8", f"<html><body><p>Act now.</p>{links}</body></html>")


def write_corpus(root: Path, *, ham: int, spam: int, seed: int = 7) -> Path:
    """Write ``root/spamassassin/{easy_ham,spam}/`` (with SpamAssassin's ``cmds`` files); return it."""
    corpus = root / "spamassassin"
    rng = random.Random(seed)
    for folder, count, factory in (("easy_ham", ham, _ham), ("spam", spam, _spam)):
        directory = corpus / folder
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "cmds").write_text("mv 00001.a 00001.b\n", encoding="ascii")
        for index in range(count):
            raw = factory(rng, index)
            (directory / f"{index:05d}.{hashlib.md5(raw).hexdigest()}").write_bytes(raw)
    return corpus
