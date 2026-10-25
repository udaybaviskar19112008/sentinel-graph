"""Loopback forward proxy that lets the detonation browser reach approved addresses only.

Chromium sends every connection through it, including redirect hops and
subresources that Playwright's route interception never sees. The proxy resolves
each host itself and connects to the exact address it vetted, so DNS rebinding
cannot swap in a private address between the check and the connection.
"""

import asyncio
import contextlib
import socket
from collections import Counter
from collections.abc import Callable
from types import TracebackType
from typing import Final, Self
from urllib.parse import urlsplit

from src.core.logger import get_logger
from src.core.network import IPAddress, is_bogon, parse_ip

logger = get_logger(__name__)

EgressPolicy = Callable[[IPAddress, int], bool]

# Marks the proxy's own refusal, so a blocked plain-HTTP navigation is not mistaken for a page.
EGRESS_BLOCK_HEADER: Final = "x-soc-egress"
_BLOCKED_RESPONSE: Final = (
    b"HTTP/1.1 403 Forbidden\r\n"
    + EGRESS_BLOCK_HEADER.encode("ascii")
    + b": blocked\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
)
_HOP_BY_HOP: Final = frozenset(
    {"connection", "keep-alive", "proxy-connection", "proxy-authorization", "te", "trailer", "upgrade"}
)
_MAX_HEAD_BYTES: Final = 64 * 1024
_HEAD_TIMEOUT_S: Final = 10.0
_CONNECT_TIMEOUT_S: Final = 5.0
_CLOSE_TIMEOUT_S: Final = 2.0
_CHUNK_BYTES: Final = 64 * 1024


def public_only(ip: IPAddress, port: int) -> bool:
    return not is_bogon(ip)


async def _resolve(host: str, port: int) -> list[IPAddress]:
    literal = parse_ip(host)
    if literal is not None:
        return [literal]
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (OSError, UnicodeError):
        return []
    resolved = (parse_ip(str(info[4][0]).split("%")[0]) for info in infos)
    return list(dict.fromkeys(ip for ip in resolved if ip is not None))


def _parse_target(target: str, tunnel: bool) -> tuple[str, int, str]:
    """(host, port, origin-form target) from a CONNECT authority or an absolute http URL."""
    if tunnel:
        host, _, port_text = target.rpartition(":")
        return host.strip("[]"), int(port_text), ""
    parts = urlsplit(target)
    if parts.scheme.lower() != "http" or not parts.hostname:
        raise ValueError(f"unsupported proxy target {target[:200]!r}")
    path = parts.path or "/"
    return parts.hostname, parts.port or 80, f"{path}?{parts.query}" if parts.query else path


def _origin_form_head(method: str, target: str, version: str, header_block: str) -> bytes:
    headers = [
        line
        for line in header_block.split("\r\n")
        if line and line.partition(":")[0].strip().lower() not in _HOP_BY_HOP
    ]
    # One request per upstream connection: a reused connection must not carry a request
    # for a different host past the vetting above.
    return "\r\n".join([f"{method} {target} {version}", *headers, "Connection: close", "", ""]).encode("latin-1")


async def _pipe(source: asyncio.StreamReader, sink: asyncio.StreamWriter) -> None:
    try:
        while data := await source.read(_CHUNK_BYTES):
            sink.write(data)
            await sink.drain()
    except OSError:
        pass
    finally:
        if sink.can_write_eof():
            with contextlib.suppress(OSError):
                sink.write_eof()


class EgressProxy:
    """``async with EgressProxy() as proxy:`` then launch Chromium with ``proxy={"server": proxy.url}``."""

    def __init__(self, policy: EgressPolicy = public_only) -> None:
        self._policy = policy
        self._server: asyncio.Server | None = None
        self._writers: set[asyncio.StreamWriter] = set()
        self.connected: list[str] = []
        self.blocked: Counter[str] = Counter()

    @property
    def url(self) -> str:
        if self._server is None:
            raise RuntimeError("EgressProxy is not running")
        host, port = self._server.sockets[0].getsockname()[:2]
        return f"http://{host}:{port}"

    async def __aenter__(self) -> Self:
        self._server = await asyncio.start_server(
            self._serve, host="127.0.0.1", port=0, limit=_MAX_HEAD_BYTES
        )
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if self._server is None:
            return
        self._server.close()
        for writer in list(self._writers):
            writer.close()
        with contextlib.suppress(TimeoutError):
            async with asyncio.timeout(_CLOSE_TIMEOUT_S):
                await self._server.wait_closed()
        self._server = None

    async def _vet(self, host: str, port: int) -> IPAddress | None:
        addresses = await _resolve(host, port)
        # Every record must pass: mixing public and private answers is itself an attack.
        if addresses and all(self._policy(ip, port) for ip in addresses):
            return addresses[0]
        self.blocked[f"egress:{host}:{port}"] += 1
        logger.warning(
            "Sandbox egress blocked",
            extra={
                "event": "sandbox.egress_blocked",
                "host": host,
                "port": port,
                "addresses": [str(ip) for ip in addresses],
            },
        )
        return None

    async def _serve(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter) -> None:
        self._writers.add(client_writer)
        upstream_writer: asyncio.StreamWriter | None = None
        try:
            async with asyncio.timeout(_HEAD_TIMEOUT_S):
                head = await client_reader.readuntil(b"\r\n\r\n")
            request_line, _, header_block = head.decode("latin-1").partition("\r\n")
            method, target, version = request_line.split(" ")
            tunnel = method.upper() == "CONNECT"
            host, port, origin_target = _parse_target(target, tunnel)

            address = await self._vet(host, port)
            if address is None:
                client_writer.write(_BLOCKED_RESPONSE)
                await client_writer.drain()
                return
            async with asyncio.timeout(_CONNECT_TIMEOUT_S):
                upstream_reader, upstream_writer = await asyncio.open_connection(str(address), port)
            self._writers.add(upstream_writer)
            self.connected.append(f"{host}:{port}")

            if tunnel:
                client_writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            else:
                upstream_writer.write(_origin_form_head(method, origin_target, version, header_block))
            await asyncio.gather(
                _pipe(client_reader, upstream_writer), _pipe(upstream_reader, client_writer)
            )
        except (OSError, ValueError, TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            pass  # malformed request, unreachable upstream, or a peer hung up: drop the connection
        finally:
            for writer in (client_writer, upstream_writer):
                if writer is not None:
                    writer.close()
                    self._writers.discard(writer)
