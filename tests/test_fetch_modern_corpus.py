import hashlib
import mailbox
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import requests

from scripts import fetch_modern_corpus as corpus
from scripts.train_orchestrator import corpus_generator
from src.extractors.mime_parser import unpack_email
from src.forensics.route_analyzer import analyze_routing


def _hashes(root: Path) -> list[str]:
    return [hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(root.rglob("*.eml"))]


# --- synthetic --------------------------------------------------------------------


@pytest.fixture(scope="module")
def synthetic(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("synthetic")
    corpus.generate_synthetic_corpus(root, count=60, seed=7)
    return root


def test_synthetic_corpus_is_balanced_distinct_and_valid(synthetic: Path) -> None:
    assert len(list((synthetic / "benign").glob("*.eml"))) == 30
    assert len(list((synthetic / "phishing").glob("*.eml"))) == 30
    hashes = _hashes(synthetic)
    assert len(hashes) == len(set(hashes)) == 60
    assert corpus.validate_corpus(synthetic) == 60
    assert "Not real mail" in (synthetic / "README.txt").read_text("utf-8")


def test_synthetic_corpus_is_reproducible(synthetic: Path, tmp_path: Path) -> None:
    corpus.generate_synthetic_corpus(tmp_path, count=60, seed=7)

    assert _hashes(tmp_path) == _hashes(synthetic)


def test_synthetic_mail_carries_modern_tradecraft(synthetic: Path) -> None:
    phishing = [path.read_bytes() for path in sorted((synthetic / "phishing").glob("*.eml"))]
    benign = [path.read_bytes() for path in sorted((synthetic / "benign").glob("*.eml"))]

    smuggled = [raw for raw in phishing if b'filename="Remittance_Advice.html"' in raw]
    assert smuggled and all(unpack_email(raw)[3] for raw in smuggled)  # kept as attachments
    assert any("​".encode() in raw or "⁠".encode() in raw for raw in phishing)
    assert any(b"ARC-Seal:" in raw for raw in benign)
    # Every email has a routable sender-side IP for the geo view.
    assert all(analyze_routing(unpack_email(raw)[0])["extracted_ips"] for raw in phishing + benign)


def test_trainer_reads_the_benign_and_phishing_layout(synthetic: Path) -> None:
    labels = [label for _, label in corpus_generator(synthetic)]

    assert labels[:4] == [0, 1, 0, 1] and labels.count(0) == labels.count(1) == 30


# --- real ---------------------------------------------------------------------------


def _write_mbox(path: Path, bodies: list[str]) -> Path:
    box = mailbox.mbox(path)
    for body in bodies:
        box.add(f"From: a@b.example\r\nSubject: {body}\r\n\r\n{body}\r\n".encode())
    box.flush()
    box.close()
    return path


def test_split_mbox_dedupes_and_honours_the_limit(tmp_path: Path) -> None:
    mbox = _write_mbox(tmp_path / "in.mbox", ["one", "two", "one", "three"])
    out = tmp_path / "out"
    seen: set[str] = set()

    written = corpus.split_mbox(mbox, out, prefix="p", limit=2, seen=seen)

    assert written == 2
    assert sorted(p.name for p in out.iterdir()) == ["p-00000.eml", "p-00001.eml"]
    assert corpus.split_mbox(mbox, out, prefix="q", limit=10, seen=seen) == 1  # only "three" is new


class _FakeResponse:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, *exc: object) -> None:
        pass

    def raise_for_status(self) -> None:
        pass

    def iter_content(self, chunk_size: int) -> Iterator[bytes]:
        for start in range(0, len(self.payload), chunk_size):
            yield self.payload[start : start + chunk_size]


@pytest.fixture
def fake_nazario(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Serve tiny mboxes in place of the real corpus; record every URL requested."""
    requested: list[str] = []
    payloads = {
        name: _write_mbox(tmp_path / f"{name}.src", [f"{name} lure {i}" for i in range(3)]).read_bytes()
        for name in corpus.NAZARIO_MAILBOXES
    }

    def fake_get(url: str, **kwargs: Any) -> _FakeResponse:
        requested.append(url)
        return _FakeResponse(payloads[url.rsplit("/", 1)[1]])

    monkeypatch.setattr(requests, "get", fake_get)
    monkeypatch.setattr(corpus, "DOWNLOAD_DIR", tmp_path / "downloads")
    return requested


def test_download_writes_phishing_attribution_and_benign(fake_nazario: list[str], tmp_path: Path) -> None:
    benign = _write_mbox(tmp_path / "inbox.mbox", ["minutes", "lunch"])
    out = tmp_path / "modern"

    counts = corpus.download_ceas_or_phishtank(4, benign_mbox=benign, out_dir=out)

    assert counts == {"phishing": 4, "benign": 2}
    # Newest mailbox first; the next is fetched only because the limit was not met.
    assert fake_nazario == [corpus.NAZARIO_BASE_URL + "phishing-2025", corpus.NAZARIO_BASE_URL + "phishing-2024"]
    assert "CC BY 4.0" in (out / "ATTRIBUTION.txt").read_text("utf-8")
    assert len(list((out / "benign").glob("*.eml"))) == 2


def test_downloads_are_reused_not_refetched(fake_nazario: list[str], tmp_path: Path) -> None:
    corpus.download_ceas_or_phishtank(2, out_dir=tmp_path / "first")
    corpus.download_ceas_or_phishtank(2, out_dir=tmp_path / "second")

    assert len(fake_nazario) == 1


def test_oversized_downloads_are_refused(fake_nazario: list[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(corpus, "MAX_DOWNLOAD_BYTES", 10)

    with pytest.raises(ValueError, match="refusing"):
        corpus.download_ceas_or_phishtank(1, out_dir=tmp_path / "modern")
    assert not list((tmp_path / "downloads").glob("*.mbox"))  # no truncated file left behind
