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


# --- research (era-matched) --------------------------------------------------------


def _write_ham_tarball(path: Path, bodies: dict[str, str]) -> Path:
    """A SpamAssassin-style .tar.bz2: one folder of numbered messages plus the 'cmds' file."""
    import io
    import tarfile

    with tarfile.open(path, "w:bz2") as tar:
        members = {**{f"easy_ham/{name}": body for name, body in bodies.items()}, "easy_ham/cmds": "mv 1 2\n"}
        for name, body in members.items():
            data = body.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return path


def _ham(message_id: str, subject: str) -> str:
    return f"From: list@lists.example\r\nMessage-ID: <{message_id}>\r\nSubject: {subject}\r\n\r\n{subject} body\r\n"


def test_split_tarball_reads_in_memory_skips_cmds_and_dedupes_by_message_id(tmp_path: Path) -> None:
    archive = _write_ham_tarball(
        tmp_path / "ham.tar.bz2",
        {
            "00001.abc": _ham("one@x", "minutes"),
            "00002.def": _ham("two@x", "release notes"),
            # The 2003 sets re-release 2002 messages with small byte differences: same Message-ID.
            "00003.ghi": _ham("ONE@x", "minutes (re-release)"),
            "00004.jkl": "   ",
        },
    )
    out, seen = tmp_path / "out", set[str]()

    written, skipped = corpus.split_tarball(archive, out, prefix="2002", limit=10, seen=seen)

    assert (written, skipped) == (2, 1)
    assert sorted(p.name for p in out.iterdir()) == ["2002-00001.eml", "2002-00002.eml"]


def test_research_fetch_builds_both_classes_and_survives_a_quarantined_mailbox(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    ham = _write_ham_tarball(tmp_path / "src.tar.bz2", {"00001.a": _ham("h1@x", "hello"), "00002.b": _ham("h2@x", "lunch")})
    phish = _write_mbox(tmp_path / "src.mbox", ["verify your account", "password expires"])
    quarantined = corpus.NAZARIO_EARLY_MAILBOXES[1]

    def fake_download(url: str, destination: Path) -> Path:
        name = url.rsplit("/", 1)[1]
        if name == quarantined:
            raise OSError(22, "Invalid argument")  # what Windows reports for a file AV just removed
        return ham if name.endswith(".tar.bz2") else phish

    monkeypatch.setattr(corpus, "_download_with_retries", fake_download)
    out = tmp_path / "research"

    counts = corpus.fetch_research_corpus(out_dir=out)

    assert counts["benign"] == 2 and counts["phishing"] == 2  # dedup collapses the repeated sources
    assert counts["mailboxes_unavailable"] == 1
    assert f"Skipped {quarantined}" in capsys.readouterr().out
    assert "SpamAssassin" in (out / "ATTRIBUTION.txt").read_text("utf-8")
    assert "CC BY 4.0" in (out / "ATTRIBUTION.txt").read_text("utf-8")


def test_prune_invalid_drops_unusable_mail(tmp_path: Path) -> None:
    (tmp_path / "benign").mkdir()
    (tmp_path / "benign" / "good.eml").write_bytes(_ham("g@x", "fine").encode())
    (tmp_path / "benign" / "headers-only.eml").write_bytes(b"Subject: no sender, no body\r\n\r\n")

    assert corpus.prune_invalid(tmp_path) == (1, 1)
    assert [p.name for p in (tmp_path / "benign").iterdir()] == ["good.eml"]
