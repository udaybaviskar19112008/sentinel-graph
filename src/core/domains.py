"""Registered-domain lookup, offline, shared by identity and route forensics."""

from typing import Final

import tldextract

from src.core.network import parse_ip

# Offline: the bundled public-suffix snapshot only. No fetch at scan time, no cache writes.
_TLD_EXTRACT: Final = tldextract.TLDExtract(cache_dir=None, suffix_list_urls=())


def registered_domain(host: str | None) -> str | None:
    """``mail.evil.co.uk`` -> ``evil.co.uk``.

    Names without a public suffix (``edge.corp.internal``, ``mx.corp.example``) fall back
    to their last two labels, so hosts of one private organisation still group together.
    IP literals and single labels come back verbatim.
    """
    name = (host or "").strip().strip("[]").rstrip(".").casefold()
    if not name:
        return None
    parts = _TLD_EXTRACT(name)
    if parts.domain and parts.suffix:
        return f"{parts.domain}.{parts.suffix}"
    if parse_ip(name) is not None or "." not in name:
        return name
    return ".".join(name.split(".")[-2:])
