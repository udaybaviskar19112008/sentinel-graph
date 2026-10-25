"""Charset-resilient byte decoding shared by MIME bodies and RFC 2047 header words."""

import codecs
from typing import Final, NamedTuple

FALLBACK_CHARSETS: Final[tuple[str, ...]] = ("utf-8", "windows-1252", "iso-8859-1")


class DecodedText(NamedTuple):
    text: str
    codec: str
    declared_failed: bool  # a charset was declared but is unknown or could not decode the data


def decode_bytes(data: bytes, declared: str | None) -> DecodedText:
    """Declared charset first, then utf-8 -> windows-1252 -> iso-8859-1, then replacement."""
    tried: set[str] = set()
    for position, charset in enumerate((declared, *FALLBACK_CHARSETS)):
        if charset is None:
            continue
        try:
            codec = codecs.lookup(charset).name
            if codec in tried:
                continue
            tried.add(codec)
            text = data.decode(codec)
        except (LookupError, ValueError):  # unknown/non-text codec, or UnicodeDecodeError
            continue
        return DecodedText(text, codec, declared is not None and position > 0)
    # iso-8859-1 maps every byte, so this is only a guard against the chain being edited.
    return DecodedText(data.decode("utf-8", errors="replace"), "utf-8", declared is not None)
