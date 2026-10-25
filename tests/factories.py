"""Builders shared by the API and pipeline tests."""

import asyncio
import io
from dataclasses import dataclass, field

import numpy as np
from PIL import Image

LURE_URL = "https://apple-id-verify.evil.example/login"


def phishing_email(*, with_url: bool = True) -> bytes:
    """Apple-branded lure from evil.com: auth fails, a 10.x hop sits between public hops."""
    body = f'<html><body><p>Your Apple ID is locked.</p><a href="{LURE_URL}">Unlock</a></body></html>'
    lines = [
        "Received: from relay2.evil.example (relay2.evil.example [40.107.22.55]) by mx.corp.example"
        " with ESMTPS id c3; Tue, 06 Oct 2026 10:02:00 +0000",
        "Received: from relay1.evil.example (relay1 [10.0.0.1]) by relay2.evil.example"
        " with ESMTP id b2; Tue, 06 Oct 2026 10:01:00 +0000",
        "Received: from sender.evil.example (unknown [185.220.101.4]) by relay1.evil.example"
        " with ESMTP id a1; Tue, 06 Oct 2026 10:00:00 +0000",
        "Authentication-Results: mx.corp.example; spf=fail smtp.mailfrom=evil.com; dkim=none; dmarc=fail",
        'From: "Apple Support" <hacker@evil.com>',
        "To: victim@corp.example",
        "Subject: Your Apple ID is locked",
        "MIME-Version: 1.0",
        "Content-Type: text/html; charset=utf-8" if with_url else "Content-Type: text/plain; charset=utf-8",
        "",
        body if with_url else "Please call the help desk.",
        "",
    ]
    return "\r\n".join(lines).encode("utf-8")


def noise_png() -> bytes:
    pixels = np.random.default_rng(3).integers(0, 256, size=(768, 1024, 3), dtype=np.uint8)
    buffer = io.BytesIO()
    Image.fromarray(pixels, mode="RGB").save(buffer, format="PNG")
    return buffer.getvalue()


@dataclass
class StubSandbox:
    """Stands in for ``detonate_and_capture``: records URLs, optionally waits or fails."""

    screenshot: bytes | None
    delay_s: float = 0.0
    error: Exception | None = None
    urls: list[str] = field(default_factory=list)

    async def __call__(self, url: str) -> bytes | None:
        self.urls.append(url)
        await asyncio.sleep(self.delay_s)
        if self.error is not None:
            raise self.error
        return self.screenshot
