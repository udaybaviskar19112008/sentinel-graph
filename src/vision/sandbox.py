"""Headless Chromium detonation of untrusted URLs.

Isolation, outermost first: Chromium's OS sandbox, a fresh browser per URL,
JavaScript disabled, downloads refused, executables/archives/heavy media aborted
by route interception, and every connection (redirect hops included) forced
through an egress proxy that only reaches publicly routable addresses.
"""

import asyncio
import contextlib
import time
from collections import Counter
from collections.abc import Awaitable, Callable
from posixpath import splitext
from typing import Final
from urllib.parse import unquote, urlsplit

from playwright.async_api import Error as PlaywrightError
from playwright.async_api import Route, async_playwright
from playwright.async_api import TimeoutError as PlaywrightTimeoutError

from src.core.config import Settings, get_settings
from src.core.logger import get_logger
from src.vision.egress_proxy import EGRESS_BLOCK_HEADER, EgressProxy

logger = get_logger(__name__)

Transport = Callable[[Route], Awaitable[None]]

VIEWPORT: Final = {"width": 1024, "height": 768}
_ALLOWED_SCHEMES: Final = frozenset({"http", "https"})
_BLOCKED_EXTENSIONS: Final = frozenset(
    {
        # executables, installers, scripts and libraries
        ".exe", ".dll", ".msi", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".hta", ".jar",
        ".apk", ".dmg", ".pkg", ".lnk",
        # archives and disk images
        ".zip", ".rar", ".7z", ".gz", ".tar", ".iso", ".vhd", ".cab",
        # heavy media
        ".mp4", ".webm", ".mov", ".avi", ".mkv", ".mp3", ".wav", ".ogg", ".flac",
    }
)
# Images stay allowed: the logos on a lure page are what the vision model recognises.
_BLOCKED_RESOURCE_TYPES: Final = frozenset({"media", "font", "websocket", "eventsource", "manifest"})
# Small /dev/shm in containers crashes Chromium; GPU is unused headless. "--no-sandbox" is
# deliberately absent: Chromium's OS sandbox is what contains a malicious page
# (SANDBOX_CHROMIUM_OS_SANDBOX turns it off only where it cannot start).
_LAUNCH_ARGS: Final = ("--disable-dev-shm-usage", "--disable-gpu")
# Browser start-up is not part of the navigation budget, but it must not hang forever either.
_STARTUP_ALLOWANCE_S: Final = 15.0
_MAX_LOGGED_URL_CHARS: Final = 2048


class _EgressBlocked(Exception):
    """The main document was refused by the egress proxy."""


async def forward(route: Route) -> None:
    """Default transport: let Chromium fetch it, through the egress proxy."""
    await route.continue_()


def _block_reason(url: str, resource_type: str) -> str | None:
    try:
        parts = urlsplit(url)
    except ValueError:
        return "unparseable"
    if parts.scheme.lower() not in _ALLOWED_SCHEMES:
        return f"scheme:{parts.scheme.lower()}"
    if resource_type in _BLOCKED_RESOURCE_TYPES:
        return f"resource:{resource_type}"
    extension = splitext(unquote(parts.path).lower())[1]
    if extension in _BLOCKED_EXTENSIONS:
        return f"extension:{extension}"
    return None


async def _capture(url: str, transport: Transport, settings: Settings, blocked: Counter[str]) -> bytes:
    timeout_ms = settings.SANDBOX_TIMEOUT_MS

    async def guard(route: Route) -> None:
        reason = _block_reason(route.request.url, route.request.resource_type)
        if reason is not None:
            blocked[reason] += 1
            await route.abort("blockedbyclient")
            return
        await transport(route)

    async with EgressProxy() as proxy, async_playwright() as playwright:
        browser = await playwright.chromium.launch(
            headless=True,
            args=list(_LAUNCH_ARGS),
            chromium_sandbox=settings.SANDBOX_CHROMIUM_OS_SANDBOX,
            proxy={"server": proxy.url},
        )
        try:
            context = await browser.new_context(
                java_script_enabled=False,
                ignore_https_errors=True,
                viewport={"width": VIEWPORT["width"], "height": VIEWPORT["height"]},
                user_agent=settings.SANDBOX_USER_AGENT,
                accept_downloads=False,
                service_workers="block",
            )
            context.set_default_timeout(timeout_ms)
            context.set_default_navigation_timeout(timeout_ms)
            await context.route("**/*", guard)
            page = await context.new_page()

            deadline = time.monotonic() + timeout_ms / 1000
            response = await page.goto(url, wait_until="domcontentloaded")
            if response is not None and response.headers.get(EGRESS_BLOCK_HEADER) == "blocked":
                raise _EgressBlocked
            # Spend what is left of the budget letting images (the logos we need) arrive.
            remaining_ms = (deadline - time.monotonic()) * 1000
            if remaining_ms >= 1:  # Playwright reads timeout=0 as "wait forever"
                with contextlib.suppress(PlaywrightTimeoutError):
                    await page.wait_for_load_state("load", timeout=remaining_ms)
            return await page.screenshot(type="png")
        finally:
            blocked.update(proxy.blocked)
            await browser.close()


async def detonate_and_capture(url: str, *, transport: Transport = forward) -> bytes | None:
    """Render ``url`` in a throwaway, script-less Chromium; return a 1024x768 PNG or None.

    ``transport`` decides how requests that pass the static blocklist are answered
    (tests inject canned responses). Every failure is logged and returns None.
    """
    settings = get_settings()
    logged_url = url[:_MAX_LOGGED_URL_CHARS]
    try:
        scheme = urlsplit(url).scheme.lower()
    except ValueError:
        scheme = ""
    if scheme not in _ALLOWED_SCHEMES:
        logger.warning(
            "Refusing to detonate non-http(s) URL",
            extra={"event": "sandbox.refused", "url": logged_url, "scheme": scheme},
        )
        return None

    blocked: Counter[str] = Counter()
    started = time.monotonic()
    hard_deadline_s = 2 * settings.SANDBOX_TIMEOUT_MS / 1000 + _STARTUP_ALLOWANCE_S
    failure: str
    try:
        async with asyncio.timeout(hard_deadline_s):
            png = await _capture(url, transport, settings, blocked)
    except _EgressBlocked:
        failure = "egress_blocked"
    except PlaywrightTimeoutError:
        failure = "navigation_timeout"
    except PlaywrightError as exc:  # net::ERR_* (dead or refused host), missing browser, ...
        # TargetClosedError (browser died mid-run) subclasses Error but is not exported publicly.
        if type(exc).__name__ == "TargetClosedError":
            failure = "target_closed"
        else:
            failure = f"browser_error: {(str(exc).splitlines() or [''])[0][:300]}"
    except TimeoutError:  # asyncio hard deadline: launch or teardown hung
        failure = "hard_deadline"
    else:
        logger.info(
            "URL detonated and captured",
            extra={
                "event": "sandbox.captured",
                "url": logged_url,
                "elapsed_ms": round((time.monotonic() - started) * 1000),
                "screenshot_bytes": len(png),
                "blocked_requests": dict(blocked),
            },
        )
        return png

    logger.warning(
        "URL detonation failed",
        extra={
            "event": "sandbox.failed",
            "url": logged_url,
            "reason": failure,
            "elapsed_ms": round((time.monotonic() - started) * 1000),
            "blocked_requests": dict(blocked),
        },
    )
    return None
