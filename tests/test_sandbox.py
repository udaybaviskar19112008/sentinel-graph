import asyncio
import json
import os
import threading
from collections.abc import Callable, Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from playwright.async_api import Error as PlaywrightError
from playwright.async_api import Route, async_playwright

from src.core.config import get_settings
from src.core.logger import LOG_FILE_NAME, configure_logging, shutdown_logging
from src.vision.egress_proxy import EgressProxy
from src.vision.sandbox import detonate_and_capture

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
# A valid 1x1 transparent PNG, served as the page's logo.
TINY_PNG = bytes.fromhex(
    "89504e470d0a1a0a0000000d4948445200000001000000010806000000"
    "1f15c4890000000d49444154789c6360000002000154a24f5d0000000049454e44ae426082"
)
PHISH_PAGE = """<!doctype html>
<html><head><title>Sign in</title><link rel="stylesheet" href="/site.css"></head>
<body>
  <h1>Example Domain</h1>
  <img src="/logo.png" alt="logo">
  <iframe src="/payload.zip"></iframe>
  <object data="/plugin.dll"></object>
  <video src="/clip.mp4" autoplay></video>
  <script>fetch('/beacon?js=on');</script>
  <noscript><img src="/noscript.png"></noscript>
</body></html>"""


def _png_size(png: bytes) -> tuple[int, int]:
    return int.from_bytes(png[16:20], "big"), int.from_bytes(png[20:24], "big")


class FakeWeb:
    """Transport serving canned responses, recording every request that got past the guard."""

    def __init__(self, pages: dict[str, tuple[int, str, bytes, dict[str, str]]]) -> None:
        self.pages = pages
        self.seen: list[str] = []

    async def __call__(self, route: Route) -> None:
        url = route.request.url
        self.seen.append(url)
        status, content_type, body, headers = self.pages.get(
            urlsplit(url).path, (404, "text/plain", b"not found", {})
        )
        await route.fulfill(status=status, content_type=content_type, body=body, headers=headers)

    @property
    def paths(self) -> set[str]:
        return {urlsplit(url).path for url in self.seen}


@pytest.fixture
def events(tmp_path: Path) -> Iterator[Path]:
    shutdown_logging()
    configure_logging(log_dir=tmp_path, level="DEBUG")
    yield tmp_path / LOG_FILE_NAME
    shutdown_logging()


def _read_events(log_file: Path) -> list[dict[str, object]]:
    shutdown_logging()
    return [json.loads(line) for line in log_file.read_text("utf-8").splitlines()]


@pytest.fixture
def short_timeout(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setenv("SOC_SANDBOX_TIMEOUT_MS", "1500")
    get_settings.cache_clear()
    yield
    monkeypatch.undo()
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_safe_url_capture_returns_1024x768_png() -> None:
    web = FakeWeb(
        {
            "/": (200, "text/html", PHISH_PAGE.encode(), {}),
            "/logo.png": (200, "image/png", TINY_PNG, {}),
            "/site.css": (200, "text/css", b"body { background: #fff; }", {}),
            "/noscript.png": (200, "image/png", TINY_PNG, {}),
        }
    )

    png = await detonate_and_capture("https://example.com/", transport=web)

    assert png is not None
    assert png.startswith(PNG_SIGNATURE)
    assert _png_size(png) == (1024, 768)


@pytest.mark.asyncio
async def test_javascript_off_and_dangerous_or_heavy_requests_blocked() -> None:
    web = FakeWeb(
        {
            "/": (200, "text/html", PHISH_PAGE.encode(), {}),
            "/logo.png": (200, "image/png", TINY_PNG, {}),
            "/noscript.png": (200, "image/png", TINY_PNG, {}),
        }
    )

    assert await detonate_and_capture("https://example.com/", transport=web) is not None

    # <noscript> content only loads when scripting is disabled; the fetch() never runs.
    assert {"/", "/logo.png", "/site.css", "/noscript.png"} <= web.paths
    assert not {"/payload.zip", "/plugin.dll", "/clip.mp4", "/beacon"} & web.paths


@pytest.mark.asyncio
async def test_direct_executable_link_is_never_fetched() -> None:
    web = FakeWeb({})

    assert await detonate_and_capture("https://example.com/Invoice%2Eexe", transport=web) is None
    assert web.seen == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "url",
    [
        "file:///C:/Windows/win.ini",
        "javascript:alert(1)",
        "data:text/html,<h1>hi</h1>",
        "ftp://files.example.com/a",
        "not a url",
        "http://[::1",
    ],
)
async def test_non_http_urls_are_refused_without_launching(url: str) -> None:
    assert await detonate_and_capture(url) is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:8080/",  # not :9, which Chromium refuses itself as an unsafe port
        "http://169.254.169.254/latest/meta-data/iam/",
        "http://[::1]/admin",
        "http://localhost/",
    ],
)
async def test_default_transport_blocks_private_egress(events: Path, url: str) -> None:
    assert await detonate_and_capture(url) is None

    assert any(e.get("event") == "sandbox.egress_blocked" for e in _read_events(events))


@pytest.mark.asyncio
async def test_redirect_into_private_space_is_blocked(events: Path) -> None:
    # Playwright never routes redirect hops, so only the egress proxy can catch this one.
    web = FakeWeb({"/": (302, "text/plain", b"", {"Location": "http://169.254.169.254/latest/"})})

    assert await detonate_and_capture("https://example.com/", transport=web) is None

    records = _read_events(events)
    blocked = [e for e in records if e.get("event") == "sandbox.egress_blocked"]
    assert [(e["host"], e["port"]) for e in blocked] == [("169.254.169.254", 80)]
    (failure,) = [e for e in records if e.get("event") == "sandbox.failed"]
    assert failure["reason"] == "egress_blocked"


@pytest.fixture
def local_redirect() -> Iterator[tuple[int, int, dict[str, list[str]]]]:
    """Server A redirects to server B; both record the paths they were asked for."""
    hits: dict[str, list[str]] = {"A": [], "B": []}
    servers: list[ThreadingHTTPServer] = []

    def handler(name: str, location: Callable[[], str] | None) -> type[BaseHTTPRequestHandler]:
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                hits[name].append(self.path)
                if location is not None:
                    self.send_response(302)
                    self.send_header("Location", location())
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<h1>internal</h1>")

            def log_message(self, format: str, *args: object) -> None:
                pass

        return Handler

    server_b = ThreadingHTTPServer(("127.0.0.1", 0), handler("B", None))
    port_b = server_b.server_address[1]
    server_a = ThreadingHTTPServer(("127.0.0.1", 0), handler("A", lambda: f"http://127.0.0.1:{port_b}/secret"))
    for server in (server_a, server_b):
        servers.append(server)
        threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server_a.server_address[1], port_b, hits
    for server in servers:
        server.shutdown()
        server.server_close()


@pytest.mark.asyncio
@pytest.mark.parametrize("allow_b", [True, False])
async def test_every_redirect_hop_passes_through_egress_proxy(
    local_redirect: tuple[int, int, dict[str, list[str]]], allow_b: bool
) -> None:
    port_a, port_b, hits = local_redirect
    allowed_ports = {port_a, port_b} if allow_b else {port_a}

    async with EgressProxy(policy=lambda ip, port: port in allowed_ports) as proxy, async_playwright() as pw:
        browser = await pw.chromium.launch(proxy={"server": proxy.url})
        page = await browser.new_page()
        response = await page.goto(f"http://127.0.0.1:{port_a}/", wait_until="domcontentloaded")
        body = await page.content()
        await browser.close()

    assert response is not None
    assert hits["A"] == ["/"]
    if allow_b:
        assert hits["B"] == ["/secret"] and "internal" in body
        assert proxy.connected == [f"127.0.0.1:{port_a}", f"127.0.0.1:{port_b}"]
    else:
        assert hits["B"] == []
        assert response.headers.get("x-soc-egress") == "blocked"
        assert proxy.blocked == {f"egress:127.0.0.1:{port_b}": 1}


@pytest.mark.asyncio
async def test_navigation_timeout_returns_none(events: Path, short_timeout: None) -> None:
    release = asyncio.Event()

    async def hang(route: Route) -> None:
        await release.wait()
        try:
            await route.abort()
        except PlaywrightError:
            pass  # browser already gone

    loop = asyncio.get_running_loop()
    started = loop.time()
    result = await detonate_and_capture("https://example.com/", transport=hang)
    elapsed = loop.time() - started
    release.set()
    await asyncio.sleep(0.1)

    assert result is None
    assert elapsed < 15
    (failure,) = [e for e in _read_events(events) if e.get("event") == "sandbox.failed"]
    assert failure["reason"] == "navigation_timeout"


@pytest.mark.asyncio
@pytest.mark.skipif(
    not os.environ.get("SOC_LIVE_NETWORK_TESTS"), reason="set SOC_LIVE_NETWORK_TESTS=1 to hit the internet"
)
async def test_live_capture_of_example_com() -> None:
    png = await detonate_and_capture("https://example.com/")

    assert png is not None and png.startswith(PNG_SIGNATURE)
