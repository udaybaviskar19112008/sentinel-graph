"""Build the 10-slide capstone defense deck, ``Sentinel_Graph_Defense.pptx``, with python-pptx.

Usage (from the repository root)::

    python scripts/generate_ppt.py [--out Sentinel_Graph_Defense.pptx]

Every figure on the slides is quoted from ``docs/CAPSTONE_DEFENSE.md``, where each one was
measured on this codebase (deployed 12-feature model: OOF ROC-AUC 0.953); change both
together. Slides use the template's standard "Title Slide" and "Title and Content"
layouts on a 16:9 canvas, in the dashboard's own palette, with speaker notes adapted from
``docs/CAPSTONE_PRESENTATION.md``. The two screenshots live in ``docs/presentation/``.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from pptx import Presentation
from pptx.chart.data import ChartData
from pptx.dml.color import RGBColor
from pptx.enum.chart import XL_CHART_TYPE, XL_LABEL_POSITION, XL_TICK_MARK
from pptx.enum.shapes import MSO_CONNECTOR, MSO_SHAPE
from pptx.enum.text import MSO_ANCHOR, MSO_AUTO_SIZE, MSO_VERTICAL_ANCHOR, PP_ALIGN
from pptx.oxml.ns import qn
from pptx.presentation import Presentation as Deck
from pptx.shapes.autoshape import Shape
from pptx.shapes.base import BaseShape
from pptx.shapes.graphfrm import GraphicFrame
from pptx.shapes.picture import Picture
from pptx.slide import Slide
from pptx.text.text import _Paragraph, _Run
from pptx.util import Emu, Inches, Pt

ROOT = Path(__file__).resolve().parent.parent
ASSETS = ROOT / "docs" / "presentation"
TOTAL_SLIDES = 10


def _hex(value: str) -> RGBColor:
    return RGBColor(int(value[0:2], 16), int(value[2:4], 16), int(value[4:6], 16))


# The dashboard's palette (frontend/src/theme/colors.ts), plus light-slide neutrals.
DARK = _hex("171719")  # the app's ground: title and closing slides
DARK_CARD = _hex("212023")
WHITE = _hex("FFFFFF")
INK = _hex("171719")  # text on light slides
MUTED = _hex("5F6368")  # secondary text on white: 6.4:1
MUTED_ON_DARK = _hex("A1A3A8")  # secondary text on the dark ground: 7.0:1
TINT = _hex("F1F2F4")  # cards on white
RULE = _hex("D0D3D8")
ACCENT = _hex("4A8AD6")
NEGATIVE = _hex("E5566F")
POSITIVE = _hex("22A6A0")
WARNING = _hex("D9A441")
NEUTRAL_BAR = _hex("B4B8BF")

FONT = "Calibri"  # ships with Office and renders true to width
NBSP = " "  # keeps a figure on the same line as its unit ("~6 ms")

# 16:9 grid, inches: one pair of 0.6" margins, a bullet column on the left, a visual on the right.
SLIDE_W, SLIDE_H = 13.333, 7.5
MARGIN = 0.6
CONTENT_TOP = 1.45
CONTENT_H = 5.3
LEFT_W = 6.2
RIGHT_X = 7.2
RIGHT_W = SLIDE_W - MARGIN - RIGHT_X


@dataclass(frozen=True)
class Point:
    """One bullet: a bold lead-in, then plain text; level 1 is a sub-bullet."""

    lead: str
    text: str = ""
    level: int = 0


# ---------------------------------------------------------------------------
# Drawing helpers
# ---------------------------------------------------------------------------


def _background(slide: Slide, color: RGBColor) -> None:
    fill = slide.background.fill
    fill.solid()
    fill.fore_color.rgb = color


def _run(
    paragraph: _Paragraph, text: str, *, size: float, color: RGBColor, bold: bool = False, italic: bool = False
) -> _Run:
    run = paragraph.add_run()
    run.text = text
    font = run.font
    font.name = FONT
    font.size = Pt(size)
    font.bold = bold
    font.italic = italic
    font.color.rgb = color
    return run


def _place(shape: BaseShape, x: float, y: float, w: float, h: float) -> None:
    shape.left, shape.top, shape.width, shape.height = Inches(x), Inches(y), Inches(w), Inches(h)


def _title(slide: Slide, text: str, *, color: RGBColor) -> None:
    """The slide title, in the same place, size and alignment on every content slide."""
    title = slide.shapes.title
    assert title is not None, "the layout has no title placeholder"
    _place(title, MARGIN, 0.4, SLIDE_W - 2 * MARGIN, 0.85)
    frame = title.text_frame
    frame.clear()
    frame.word_wrap = True
    frame.vertical_anchor = MSO_ANCHOR.MIDDLE
    paragraph = frame.paragraphs[0]
    paragraph.alignment = PP_ALIGN.LEFT
    _run(paragraph, text, size=32, color=color, bold=True)


def _placeholder(slide: Slide, idx: int) -> Shape:
    """A layout placeholder as the text-bearing shape it is (the library types it as BaseShape)."""
    return cast(Shape, slide.placeholders[idx])


def _bullets(
    placeholder: Shape, points: list[Point], *, x: float, y: float, w: float, h: float, dark: bool = False
) -> None:
    """Fill the layout's content placeholder with bullets (bold lead-in, plain rest)."""
    _place(placeholder, x, y, w, h)
    ink = WHITE if dark else INK
    muted = MUTED_ON_DARK if dark else MUTED
    frame = placeholder.text_frame
    frame.clear()
    frame.word_wrap = True
    frame.auto_size = MSO_AUTO_SIZE.NONE
    frame.vertical_anchor = MSO_ANCHOR.TOP
    for index, point in enumerate(points):
        paragraph = frame.paragraphs[0] if index == 0 else frame.add_paragraph()
        paragraph.level = point.level
        paragraph.alignment = PP_ALIGN.LEFT
        paragraph.space_after = Pt(12 if point.level == 0 else 6)
        size = 18 if point.level == 0 else 15
        if point.lead:
            _run(paragraph, point.lead + (" " if point.text else ""), size=size, color=ink, bold=True)
        if point.text:
            _run(paragraph, point.text, size=size, color=ink if point.level == 0 else muted)


def _textbox(
    slide: Slide, x: float, y: float, w: float, h: float, *, anchor: MSO_VERTICAL_ANCHOR = MSO_ANCHOR.TOP
) -> Shape:
    box = slide.shapes.add_textbox(Inches(x), Inches(y), Inches(w), Inches(h))
    frame = box.text_frame
    frame.word_wrap = True
    frame.auto_size = MSO_AUTO_SIZE.NONE
    frame.vertical_anchor = anchor
    frame.margin_left = frame.margin_right = frame.margin_top = frame.margin_bottom = Emu(0)
    return box


def _card(slide: Slide, x: float, y: float, w: float, h: float, *, fill: RGBColor, name: str) -> Shape:
    """A rounded card: a tone step from the slide, no outline and no shadow."""
    card = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(x), Inches(y), Inches(w), Inches(h))
    card.name = name
    card.adjustments[0] = 0.08
    card.fill.solid()
    card.fill.fore_color.rgb = fill
    card.line.fill.background()
    card.shadow.inherit = False
    frame = card.text_frame
    frame.word_wrap = True
    frame.auto_size = MSO_AUTO_SIZE.NONE
    frame.margin_left = frame.margin_right = Inches(0.25)
    frame.margin_top = frame.margin_bottom = Inches(0.12)
    # A new autoshape's first paragraph is centred; cards read left-aligned unless a caller says otherwise.
    frame.paragraphs[0].alignment = PP_ALIGN.LEFT
    return card


def _stat(
    slide: Slide,
    x: float,
    y: float,
    w: float,
    h: float,
    figure: str,
    label: str,
    *,
    dark: bool = False,
    figure_color: RGBColor | None = None,
) -> None:
    """A stat callout: one large figure over a short label, on a card."""
    card = _card(slide, x, y, w, h, fill=DARK_CARD if dark else TINT, name=f"Stat {figure}")
    frame = card.text_frame
    # Top-anchored, so figures in one row line up whatever the length of their labels.
    frame.vertical_anchor = MSO_ANCHOR.TOP
    frame.margin_top = Inches(0.28)
    figure_paragraph = frame.paragraphs[0]
    figure_paragraph.alignment = PP_ALIGN.LEFT
    _run(figure_paragraph, figure, size=36, color=figure_color or (WHITE if dark else INK), bold=True)
    label_paragraph = frame.add_paragraph()
    label_paragraph.alignment = PP_ALIGN.LEFT
    label_paragraph.space_before = Pt(2)
    _run(label_paragraph, label, size=13, color=MUTED_ON_DARK if dark else MUTED)


def _arrow(slide: Slide, x1: float, y1: float, x2: float, y2: float, *, color: RGBColor = NEUTRAL_BAR) -> None:
    line = slide.shapes.add_connector(MSO_CONNECTOR.STRAIGHT, Inches(x1), Inches(y1), Inches(x2), Inches(y2))
    line.line.color.rgb = color
    line.line.width = Pt(1.5)
    # python-pptx has no arrowhead API; a triangle tail is a child of <a:ln>, after its fill.
    ln = line.line._get_or_add_ln()
    ln.append(ln.makeelement(qn("a:tailEnd"), {"type": "triangle", "w": "med", "len": "med"}))


def _route_mark(
    slide: Slide, x: float, y: float, height: float, *, color: RGBColor, hollow: RGBColor, labels: bool = False
) -> None:
    """The product's mark, drawn from its own delivery graph: a sender over two hops, a link to the side.

    Geometry matches frontend/src/components/SidebarNavigation.tsx (a 24-unit box).
    """
    unit = height / 24

    def at(ux: float, uy: float) -> tuple[float, float]:
        return x + ux * unit, y + uy * unit

    for (ax, ay), (bx, by) in (((7, 5), (7, 19)), ((7, 5), (17, 10))):
        (x1, y1), (x2, y2) = at(ax, ay), at(bx, by)
        edge = slide.shapes.add_connector(MSO_CONNECTOR.STRAIGHT, Inches(x1), Inches(y1), Inches(x2), Inches(y2))
        edge.line.color.rgb = color
        edge.line.width = Pt(1.75 * unit * 72)
    nodes = (((7, 5), 2.5, "Sender"), ((7, 12), 2.25, "Relay hop"), ((7, 19), 2.25, "Receiver"), ((17, 10), 2.25, "Link"))
    for index, ((ux, uy), radius, label) in enumerate(nodes):
        cx, cy = at(ux, uy)
        r = radius * unit
        node = slide.shapes.add_shape(MSO_SHAPE.OVAL, Inches(cx - r), Inches(cy - r), Inches(2 * r), Inches(2 * r))
        node.name = f"Mark node {label}"
        node.fill.solid()
        node.fill.fore_color.rgb = hollow if index == 3 else color
        node.shadow.inherit = False
        if index == 3:
            node.line.color.rgb = color
            node.line.width = Pt(1.75 * unit * 72)
        else:
            node.line.fill.background()
        if labels:
            # Route nodes are labelled on their left, the link on its right, so no label meets a node.
            is_link = index == 3
            box = _textbox(slide, cx + r + 0.15 if is_link else cx - r - 0.15 - 1.6, cy - 0.2, 1.6, 0.4, anchor=MSO_ANCHOR.MIDDLE)
            paragraph = box.text_frame.paragraphs[0]
            paragraph.alignment = PP_ALIGN.LEFT if is_link else PP_ALIGN.RIGHT
            _run(paragraph, label, size=14, color=MUTED_ON_DARK)


def _footer(slide: Slide, number: int, *, dark: bool = False) -> None:
    color = MUTED_ON_DARK if dark else MUTED
    _route_mark(slide, MARGIN, 6.98, 0.3, color=ACCENT, hollow=DARK if dark else WHITE)
    left = _textbox(slide, MARGIN + 0.38, 6.98, 6.0, 0.3, anchor=MSO_ANCHOR.MIDDLE)
    _run(left.text_frame.paragraphs[0], "Sentinel-Graph (SOC v2) · Capstone defense", size=11, color=color)
    right = _textbox(slide, SLIDE_W - MARGIN - 1.0, 6.98, 1.0, 0.3, anchor=MSO_ANCHOR.MIDDLE)
    paragraph = right.text_frame.paragraphs[0]
    paragraph.alignment = PP_ALIGN.RIGHT
    _run(paragraph, f"{number} / {TOTAL_SLIDES}", size=11, color=color)


def _caption(slide: Slide, x: float, y: float, w: float, text: str, *, h: float = 0.6) -> None:
    box = _textbox(slide, x, y, w, h)
    _run(box.text_frame.paragraphs[0], text, size=12, color=MUTED, italic=True)


def _picture(slide: Slide, path: Path, x: float, y: float, *, w: float | None = None, h: float | None = None) -> Picture:
    if not path.is_file():
        raise SystemExit(f"Missing slide image {path}; it is committed under docs/presentation/.")
    picture = slide.shapes.add_picture(
        str(path), Inches(x), Inches(y), Inches(w) if w else None, Inches(h) if h else None
    )
    picture.line.color.rgb = RULE
    picture.line.width = Pt(0.75)
    return picture


def _bar_chart(
    slide: Slide,
    kind: XL_CHART_TYPE,
    x: float,
    y: float,
    w: float,
    h: float,
    *,
    title: str,
    categories: list[str],
    values: list[float],
    colors: list[RGBColor],
) -> None:
    """A native chart: one series, per-bar colours, percentage labels on the bars, no axis chrome."""
    data = ChartData()
    data.categories = categories
    data.add_series("Share", values)
    # add_chart is annotated as returning the Chart, but it returns the graphic frame that holds it.
    frame = cast(GraphicFrame, slide.shapes.add_chart(kind, Inches(x), Inches(y), Inches(w), Inches(h), data))
    chart = frame.chart
    chart.font.name = FONT
    chart.font.size = Pt(12)
    chart.font.color.rgb = INK
    chart.has_legend = False
    chart.has_title = True
    title_frame = chart.chart_title.text_frame
    title_frame.text = title
    title_paragraph = title_frame.paragraphs[0]
    title_paragraph.font.size = Pt(14)
    title_paragraph.font.bold = True
    title_paragraph.font.name = FONT
    title_paragraph.font.color.rgb = INK

    plot = chart.plots[0]
    plot.gap_width = 55
    plot.vary_by_categories = False
    plot.has_data_labels = True
    labels = plot.data_labels
    labels.number_format = '0.0"%"'
    labels.number_format_is_linked = False
    labels.position = XL_LABEL_POSITION.OUTSIDE_END
    labels.font.size = Pt(13)
    labels.font.bold = True
    labels.font.color.rgb = INK
    for index, color in enumerate(colors):
        point_fill = plot.series[0].points[index].format.fill
        point_fill.solid()
        point_fill.fore_color.rgb = color

    values_axis = chart.value_axis
    values_axis.minimum_scale = 0
    values_axis.maximum_scale = 100  # true proportions: each bar is its share of 100%
    values_axis.has_major_gridlines = False
    values_axis.visible = False
    categories_axis = chart.category_axis
    categories_axis.major_tick_mark = XL_TICK_MARK.NONE
    categories_axis.format.line.color.rgb = RULE
    categories_axis.tick_labels.font.size = Pt(12)
    categories_axis.tick_labels.font.color.rgb = INK
    if kind == XL_CHART_TYPE.BAR_CLUSTERED:
        categories_axis.reverse_order = True  # first category on top, in reading order


def _notes(slide: Slide, text: str) -> None:
    notes = slide.notes_slide.notes_text_frame
    assert notes is not None, "the notes master has no body placeholder"
    notes.text = text


# ---------------------------------------------------------------------------
# Slides
# ---------------------------------------------------------------------------


def title_slide(prs: Deck) -> None:
    slide = prs.slides.add_slide(prs.slide_layouts[0])  # "Title Slide"
    _background(slide, DARK)
    title = slide.shapes.title
    assert title is not None, "the Title Slide layout has no title placeholder"
    _place(title, MARGIN, 1.75, 7.9, 2.3)
    frame = title.text_frame
    frame.clear()
    frame.word_wrap = True
    frame.vertical_anchor = MSO_ANCHOR.BOTTOM
    first = frame.paragraphs[0]
    first.alignment = PP_ALIGN.LEFT
    _run(first, "Sentinel-Graph (SOC v2)", size=48, color=WHITE, bold=True)
    second = frame.add_paragraph()
    second.alignment = PP_ALIGN.LEFT
    second.space_before = Pt(6)
    _run(second, "AI-Assisted Hybrid Phishing Detection", size=28, color=MUTED_ON_DARK)

    subtitle = _placeholder(slide, 1)
    _place(subtitle, MARGIN, 4.35, 7.9, 1.6)
    frame = subtitle.text_frame
    frame.clear()
    frame.word_wrap = True
    frame.vertical_anchor = MSO_ANCHOR.TOP
    lines = (
        ("Capstone Defense Presentation", 20, WHITE, True),
        ("Uday Babasaheb Baviskar · B.Sc. Cyber and Digital Science (SYBSc CDS)", 14, MUTED_ON_DARK, False),
        ("Suryadatta International Institute of Cyber Security (SIICS), Pune", 14, MUTED_ON_DARK, False),
    )
    for index, (text, size, color, bold) in enumerate(lines):
        paragraph = frame.paragraphs[0] if index == 0 else frame.add_paragraph()
        paragraph.alignment = PP_ALIGN.LEFT
        paragraph.space_after = Pt(6)
        _run(paragraph, text, size=size, color=color, bold=bold)

    _route_mark(slide, 8.75, 1.9, 3.9, color=ACCENT, hollow=DARK, labels=True)
    _notes(
        slide,
        "Good morning. Sentinel-Graph analyses a raw email the way a SOC analyst would: the protocol "
        "evidence, the delivery route, the rendered link and a local reasoning model, fused into one "
        "risk score that is explained feature by feature. The mark on the right is the product's own "
        "delivery graph: a sender, its relay hops, the receiver, and a link.",
    )


def content_slide(
    prs: Deck,
    number: int,
    title: str,
    points: list[Point],
    *,
    dark: bool = False,
    body: tuple[float, float, float, float] = (MARGIN, CONTENT_TOP, LEFT_W, CONTENT_H),
) -> Slide:
    slide: Slide = prs.slides.add_slide(prs.slide_layouts[1])  # "Title and Content"
    _background(slide, DARK if dark else WHITE)
    _title(slide, title, color=WHITE if dark else INK)
    x, y, w, h = body
    _bullets(_placeholder(slide, 1), points, x=x, y=y, w=w, h=h, dark=dark)
    _footer(slide, number, dark=dark)
    return slide


def problem_slide(prs: Deck) -> None:
    slide = content_slide(prs, 2, "The Phishing Evolution", [
        Point("Signature and text filters are bypassed:", "LLM-written lures, homoglyphs, zero-width characters, image-only bodies"),
        Point("DGA domains:", "machine-generated names rotate faster than blocklists"),
        Point("Psychological coercion:", "“account suspended”, “immediate action”, “verify your identity”"),
        Point("Needs multi-modal analysis:", "protocol, delivery route, rendered link and reasoning, not words alone"),
    ])
    card = _card(slide, RIGHT_X, 1.9, RIGHT_W, 3.6, fill=DARK, name="Key message")
    frame = card.text_frame
    frame.vertical_anchor = MSO_ANCHOR.MIDDLE
    frame.margin_left = frame.margin_right = Inches(0.45)
    quote = frame.paragraphs[0]
    _run(quote, "Text is cheap to change.", size=28, color=WHITE, bold=True)
    second = frame.add_paragraph()
    _run(second, "Delivery infrastructure and behaviour are not.", size=28, color=WHITE, bold=True)
    note = frame.add_paragraph()
    note.space_before = Pt(18)
    _run(note, "Sentinel-Graph examines the evidence an attacker cannot easily rewrite.", size=15, color=MUTED_ON_DARK)
    _notes(
        slide,
        "Most filters read the words of an email, and that is the part the attacker controls best: a "
        "language model writes a fluent, unique lure for every target, brand names hide behind Cyrillic "
        "look-alikes or invisible characters, some messages are only an image. What is hard to rewrite "
        "is how the email was delivered and what its link does when it is opened.",
    )


def architecture_slide(prs: Deck) -> None:
    slide = content_slide(prs, 3, "System Architecture: The Hybrid Approach", [
        Point("Decoupled, hardened HTML / MIME parsing", f"(Tier 1, ~6{NBSP}ms)"),
        Point("Playwright DOM sandbox", f"behind an egress proxy that only reaches public IPs (Tier 2, ~2.5{NBSP}s)"),
        Point("Delivery-topology graph", f"scored by a MemAE graph neural network (Tier 3, ~90{NBSP}ms)"),
        Point("Local ONNX language model", "writes a short forensic reading (Tier 4)"),
        Point("12D meta-scorer:", "a Random Forest fuses twelve features; exact SHAP explains every score"),
    ])
    # The pipeline, top to bottom; Tiers 2 and 3 run side by side because they run concurrently.
    row_h, gap = 0.72, 0.33
    rows = [CONTENT_TOP + 0.1 + i * (row_h + gap) for i in range(5)]
    half = (RIGHT_W - 0.3) / 2

    def box(x: float, y: float, w: float, head: str, tail: str, *, dark: bool = False) -> None:
        card = _card(slide, x, y, w, row_h, fill=DARK if dark else TINT, name=head)
        frame = card.text_frame
        frame.vertical_anchor = MSO_ANCHOR.MIDDLE
        paragraph = frame.paragraphs[0]
        paragraph.alignment = PP_ALIGN.CENTER
        _run(paragraph, head, size=14, color=WHITE if dark else INK, bold=True)
        if tail:
            _run(paragraph, f"  {tail}", size=13, color=MUTED_ON_DARK if dark else MUTED)

    box(RIGHT_X, rows[0], RIGHT_W, "Raw email (.eml)", "")
    box(RIGHT_X, rows[1], RIGHT_W, "Tier 1 · Protocol forensics", f"~6{NBSP}ms")
    box(RIGHT_X, rows[2], half, "Tier 2 · Sandbox", f"~2.5{NBSP}s")
    box(RIGHT_X + half + 0.3, rows[2], half, "Tier 3 · MemAE", f"~90{NBSP}ms")
    box(RIGHT_X, rows[3], RIGHT_W, "Tier 4 · Local language model", "")
    box(RIGHT_X, rows[4], RIGHT_W, "Fusion: 12 features → risk 0–100 + SHAP", "", dark=True)
    centre = RIGHT_X + RIGHT_W / 2
    left_centre, right_centre = RIGHT_X + half / 2, RIGHT_X + half + 0.3 + half / 2
    _arrow(slide, centre, rows[0] + row_h, centre, rows[1])
    for column in (left_centre, right_centre):
        _arrow(slide, column, rows[1] + row_h, column, rows[2])
        _arrow(slide, column, rows[2] + row_h, column, rows[3])
    _arrow(slide, centre, rows[3] + row_h, centre, rows[4])
    _notes(
        slide,
        "Tier one is deterministic forensics in about six milliseconds. Tiers two and three run "
        "concurrently: the sandbox renders the first link in a disposable browser whose every connection, "
        "redirects included, goes through an egress proxy that only reaches public addresses, while the "
        "topology model scores the route in about ninety milliseconds. Tier four is a local language "
        "model. A Random Forest fuses twelve features, and SHAP decomposes every score.",
    )


def features_slide(prs: Deck) -> None:
    slide = content_slide(prs, 4, "12D Feature Space: Protocol & Content Heuristics", [
        Point("Protocol forensics:", "SPF / DKIM / DMARC / ARC from the trusted Authentication-Results header, display-name spoofing, private hop, clock regression"),
        Point("DGA Shannon entropy", "of each link's domain: legitimate links cluster at 2.5–3.0 bits; phishing fills both tails"),
        Point("NLP coercion regex:", "eight phrase families, matched through zero-width and inflection tricks"),
        Point("Plus route, vision and language-model features:", "twelve columns the model takes by name"),
    ])
    stats: tuple[tuple[str, str, RGBColor | None], ...] = (
        ("2.5–3.0 bits", "DGA band holding 52% of legitimate links (23% of phishing)", None),
        ("20.3% vs 0.1%", "NLP coercion fires on phishing vs legitimate training mail", None),
        ("0.926 → 0.953", "OOF ROC-AUC once both heuristics join the model (identical folds)", ACCENT),
    )
    height, gap = 1.55, 0.3
    for index, (figure, label, color) in enumerate(stats):
        _stat(slide, RIGHT_X, CONTENT_TOP + 0.05 + index * (height + gap), RIGHT_W, height, figure, label, figure_color=color)
    _notes(
        slide,
        "Authentication results are read only from the header our own server wrote, because anything "
        "lower could be forged. The two content heuristics are the newest features. DGA entropy is not "
        "'higher is worse': legitimate links sit in a narrow band and phishing fills both tails. Together "
        "they lifted out-of-fold ROC-AUC from 0.926 to 0.953 on identical folds. Caveat: the 2002–06 "
        "corpora predate Authentication-Results headers, so the authentication-failure count is constant "
        "in training and the deployed model cannot use it yet.",
    )


def memae_slide(prs: Deck) -> None:
    slide = content_slide(prs, 5, "Topology Graph: Memory-Augmented Autoencoder", [
        Point("Email → directed graph:", "sender → relay hops → receiver, sender → each link"),
        Point("2 × GCN encoder", "(5 → 32 → 16), trained on legitimate mail only"),
        Point("Sparse memory addressing:", "50 prototypes, sharpened softmax (τ = 0.1), hard shrinkage (λ = 0.05)"),
        Point("Loss on raw logits:", "clamped BCE had zero gradient once saturated and two folds diverged; now all five converge"),
        Point("Zero-day flag", "when the reconstruction loss exceeds 1.10"),
    ])
    width = (RIGHT_W - 0.3) / 2
    _stat(slide, RIGHT_X, CONTENT_TOP + 0.05, width, 1.9, "2", "median active memory slots per node (max 6)")
    _stat(slide, RIGHT_X + width + 0.3, CONTENT_TOP + 0.05, width, 1.9, "1.10", "zero-day threshold: 99th pct. of out-of-fold benign loss")
    formula = _card(slide, RIGHT_X, CONTENT_TOP + 2.3, RIGHT_W, 2.9, fill=DARK, name="Addressing formula")
    frame = formula.text_frame
    frame.vertical_anchor = MSO_ANCHOR.MIDDLE
    frame.margin_left = frame.margin_right = Inches(0.4)
    steps = (
        ("Address", "w = softmax(cos(z, M) / τ)"),
        ("Shrink", "keep weights above λ, re-normalise"),
        ("Decode", "ẑ = ŵM,  Â = σ(ẑẑᵀ)"),
        ("Score", "BCE of Â against the real adjacency"),
    )
    for index, (head, tail) in enumerate(steps):
        paragraph = frame.paragraphs[0] if index == 0 else frame.add_paragraph()
        paragraph.space_after = Pt(8)
        _run(paragraph, f"{head}  ", size=15, color=MUTED_ON_DARK, bold=True)
        _run(paragraph, tail, size=16, color=WHITE)
    _notes(
        slide,
        "Each email becomes a small directed graph. Two graph-convolution layers turn every node into a "
        "sixteen-dimensional vector. The memory holds fifty learned prototypes of normal routing; a "
        "sharpened softmax and hard shrinkage force each node to be rebuilt from only a few of them, a "
        "median of two and never more than six, so an unfamiliar topology cannot be expressed and its error "
        "rises. The loss is computed on logits: the old clamped BCE had zero gradient once saturated, which "
        "let two folds diverge. The zero-day threshold, 1.10, is the 99th percentile of out-of-fold benign losses.",
    )


def rigor_slide(prs: Deck) -> None:
    slide = content_slide(prs, 6, "Empirical Rigor: Datasets & Confounds", [
        Point("Era-matched public corpus", "with full Received chains: 4,211 legitimate (SpamAssassin 2002–03) vs 2,361 phishing (Nazario 2004–06)"),
        Point("Leakage controls:", "5-fold out-of-fold scoring, cross-fitted MemAE, language-model verdict held constant"),
        Point("Confound found with SHAP:", "private_ip_leak fires on 66.8% of legitimate vs 3.0% of phishing mail"),
        Point("Cause:", "mailing lists relay legitimate mail through private hops, so the model learned the feature backwards (SHAP −0.243 on the demo lure)", level=1),
    ])
    _bar_chart(
        slide, XL_CHART_TYPE.COLUMN_CLUSTERED, RIGHT_X, CONTENT_TOP, RIGHT_W, 4.5,
        title="Training mail where private_ip_leak fires",
        categories=["Legitimate (2002–03)", "Phishing (2004–06)"],
        values=[66.8, 3.0],
        colors=[POSITIVE, NEGATIVE],
    )
    _caption(slide, RIGHT_X, CONTENT_TOP + 4.65, RIGHT_W, "Monotonic constraints would forbid a private hop from lowering risk.")
    _notes(
        slide,
        "The training data is public and era-matched, with full routing headers. Every reported prediction "
        "comes from a model that never saw that email; the MemAE score is cross-fitted; and the language-model "
        "verdict is held constant, because mapping it from the label wrote the answer into the input and gave "
        "a meaningless AUC of 1.0. SHAP then exposed a confound: two-thirds of the legitimate mail is "
        "mailing-list traffic through private corporate relays, so a private hop lowers the risk.",
    )


def ablation_slide(prs: Deck) -> None:
    slide = content_slide(prs, 7, "Ablation Study: What Each Feature Contributes", [
        Point("Baseline:", "OOF ROC-AUC 0.953 · recall 61.4% on unseen phishing from 2023–25"),
        Point("DGA entropy matters most among content features:", "without it 0.935 and 50.5%"),
        Point("Without the MemAE loss:", "AUC unchanged at 0.953, recall 71.6%"),
        Point("So today the topology signal is graph size", "(without graph size and MemAE: 37.6%)", level=1),
        Point("Recall is measured on phishing only:", "the false-positive rate on modern mail is unmeasured"),
    ])
    _bar_chart(
        slide, XL_CHART_TYPE.BAR_CLUSTERED, RIGHT_X, CONTENT_TOP, RIGHT_W, 4.6,
        title="Unseen 2023–25 phishing caught · OOF ROC-AUC",
        categories=[
            "Baseline · 0.953",
            "No MemAE loss · 0.953",
            "No NLP coercion · 0.950",
            "No DGA entropy · 0.935",
            "No protocol forensics · 0.934",
            "No graph size + MemAE · 0.936",
        ],
        values=[61.4, 71.6, 57.2, 50.5, 47.2, 37.6],
        colors=[ACCENT, WARNING, NEUTRAL_BAR, NEUTRAL_BAR, NEUTRAL_BAR, NEUTRAL_BAR],
    )
    _caption(slide, RIGHT_X, CONTENT_TOP + 4.75, RIGHT_W, "Drop-column ablation on identical folds; recall at threshold 0.5.")
    _notes(
        slide,
        "This is a drop-column ablation on identical folds. DGA entropy is the strongest content feature. "
        "The honest finding: removing the MemAE loss leaves the AUC at 0.953 and raises recall on unseen "
        "2023–25 phishing from 61.4% to 71.6%; removing graph size as well drops recall to 37.6%. So today "
        "the topology signal is route size and the MemAE duplicates it. I kept it for the zero-day flag; "
        "per-hop node attributes are what would let it contribute. Recall here is phishing-only, so false "
        "positives on modern mail are unmeasured.",
    )


def frontend_slide(prs: Deck) -> None:
    # A narrower bullet column, so the screenshot is large enough to read on a projector.
    slide = content_slide(prs, 8, "Interactive Frontend: Data-Terminal SOC Console", [
        Point("React 19 + Zustand SPA,", "streamed live over a FastAPI WebSocket"),
        Point("Built for long analyst sessions:", "no glass or glow; colour only on evidence"),
        Point("Verdict against the 50 decision line;", "React Flow route with edges coloured by SHAP sign"),
        Point("Stand-in models labelled", "beside every score, never shown as evidence"),
    ], body=(MARGIN, CONTENT_TOP, 5.3, CONTENT_H))
    x = 6.3
    width = SLIDE_W - MARGIN - x
    height = width * 900 / 1440
    _picture(slide, ASSETS / "live_scan.jpg", x, CONTENT_TOP + 0.1, w=width)
    _caption(slide, x, CONTENT_TOP + 0.25 + height, width, "Live scan of the demo lure: risk 61/100 with the route, globe and pipeline log.")
    _notes(
        slide,
        "The analyst drops an email; the backend streams an event for every step, so the screen fills in as "
        "the analysis happens. The console was restyled for long sessions: colour appears only on evidence, "
        "such as the risk bar against the decision line and route edges coloured by the sign of their SHAP "
        "impact. Whenever an engine runs a stand-in model, the screen says so next to the score.",
    )


def globe_slide(prs: Deck) -> None:
    slide = content_slide(prs, 9, "State-Driven 3D Globe: WebGL Cinematography", [
        Point("Three.js globe", "(React Three Fiber) beside the list of hops it plots"),
        Point("Reacts to WebSocket state:", "spins up on upload, settles on the verdict"),
        Point("Damped camera:", "pushes in and turns the route's centre to face the viewer"),
        Point("Arcs in the risk colour;", "dashed where a hop's position is only estimated"),
        Point("Private addresses never leave the host;", "VITE_GEO_LOOKUP=off keeps every lookup local"),
    ])
    height = 4.7
    width = height * 312 / 414
    x = RIGHT_X + (RIGHT_W - width) / 2
    _picture(slide, ASSETS / "route_geography.png", x, CONTENT_TOP + 0.05, h=height)
    _caption(slide, RIGHT_X, CONTENT_TOP + height + 0.2, RIGHT_W, "Route geography panel after the demo lure: two located hops, one private.")
    _notes(
        slide,
        "The globe is state-driven: it reads the store inside the render loop, spins up when an email is "
        "uploaded, and when the verdict and hop locations arrive the camera pushes in and turns the route to "
        "face the viewer. Arcs take the colour of the risk score; a hop that could not be geolocated, a "
        "private address or a failed lookup, is drawn dashed and listed as estimated.",
    )


def conclusion_slide(prs: Deck) -> None:
    slide = content_slide(
        prs, 10, "Conclusion & Future Scope",
        [
            Point("Per-hop ASN node attributes,", "so the MemAE sees forged hops, not just route size"),
            Point("Retrain on modern labelled mail", "with authentication headers, and measure false positives"),
            Point("Monotonic constraints", "so spoofing and route anomalies can only raise risk"),
            Point("A real vision model and local SLM", "in place of today's labelled stand-ins"),
        ],
        dark=True,
        body=(MARGIN, 4.05, SLIDE_W - 2 * MARGIN, 2.75),
    )
    gap = 0.3
    width = (SLIDE_W - 2 * MARGIN - 3 * gap) / 4
    stats = (
        ("0.953", "OOF ROC-AUC, 12 features, five folds"),
        ("61.4%", "of unseen 2023–25 phishing caught (10-feature model: 48.8%)"),
        ("12", "features behind every verdict, each explained with exact SHAP"),
        (f"~4{NBSP}s", "full assessment on a laptop CPU, all inference local"),
    )
    for index, (figure, label) in enumerate(stats):
        _stat(slide, MARGIN + index * (width + gap), CONTENT_TOP, width, 1.75, figure, label, dark=True)
    heading = _textbox(slide, MARGIN, 3.5, 6.0, 0.45, anchor=MSO_ANCHOR.MIDDLE)
    _run(heading.text_frame.paragraphs[0], "Future scope", size=20, color=ACCENT, bold=True)
    _notes(
        slide,
        "To conclude: Sentinel-Graph moves phishing detection from reading words to examining evidence, "
        "explains every score, and keeps personal data on the host. It generalises only partly to modern "
        "phishing, 61.4% of unseen 2023–25 emails, so the next steps follow from the evaluation: per-hop node "
        "attributes for the graph model, retraining on modern mail with a measured false-positive rate, "
        "monotonic constraints, and real vision and language models. Thank you; I am happy to take questions.",
    )


def build(out: Path) -> Path:
    prs = Presentation()
    prs.slide_width = Emu(Inches(SLIDE_W))
    prs.slide_height = Emu(Inches(SLIDE_H))
    prs.core_properties.title = "Sentinel-Graph (SOC v2): AI-Assisted Hybrid Phishing Detection"
    prs.core_properties.subject = "Capstone defense presentation"
    prs.core_properties.author = "Uday Babasaheb Baviskar"
    for make in (
        title_slide, problem_slide, architecture_slide, features_slide, memae_slide,
        rigor_slide, ablation_slide, frontend_slide, globe_slide, conclusion_slide,
    ):
        make(prs)
    assert len(prs.slides) == TOTAL_SLIDES, f"built {len(prs.slides)} slides, expected {TOTAL_SLIDES}"
    prs.save(str(out))
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--out", type=Path, default=ROOT / "Sentinel_Graph_Defense.pptx", help="output .pptx path")
    path = build(parser.parse_args().out)
    print(f"Wrote {path} ({TOTAL_SLIDES} slides)")


if __name__ == "__main__":
    main()
