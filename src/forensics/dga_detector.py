"""Domain-generation-algorithm (DGA) risk: character entropy of each link's registrable label.

Kits and botnets that mint throwaway domains (``xkqjfhzyw.com``) draw characters
close to uniformly, so the label's Shannon entropy runs high; names people choose
(``google``) reuse letters and score low. Only the label left of the public suffix
is scored: subdomains are free attacker padding and the suffix is shared by everyone.

Raw entropy is bounded by log2(label length), so long legitimate names score high
too. It is one fusion feature, never a verdict on its own.
"""

import math
import unicodedata
from collections import Counter
from urllib.parse import urlsplit

from src.core.domains import registrable_label


def calculate_shannon_entropy(string: str) -> float:
    """H(X) = -sum p(x) log2 p(x) over the characters of ``string``, in bits; 0.0 when empty."""
    if not string:
        return 0.0
    length = len(string)
    # Written as sum p log2(1/p): identical, but a one-symbol string gives 0.0 rather than -0.0.
    return sum(count / length * math.log2(length / count) for count in Counter(string).values())


def _visible(text: str) -> str:
    """``text`` without whitespace or invisible format characters (zero-width, bidi, BOM)."""
    return "".join(char for char in text if not char.isspace() and unicodedata.category(char) != "Cf")


def _label(url: str) -> str | None:
    try:
        host = urlsplit(url).hostname
    except ValueError:  # e.g. an unbalanced IPv6 bracket
        return None
    return registrable_label(_visible(host)) if host else None


def analyze_dga_risk(urls: list[str]) -> float:
    """The highest registrable-label entropy across ``urls``; 0.0 when there are none.

    IP-literal hosts are skipped: an address is not a generated name.
    """
    return max((calculate_shannon_entropy(label) for url in urls if (label := _label(url))), default=0.0)
