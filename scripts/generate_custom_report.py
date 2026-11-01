"""Generate the Sentinel-Graph project report (.docx) in the SIICS project-report format.

    python scripts/generate_custom_report.py --template-pdf "path/to/report format.pdf"
    python scripts/generate_custom_report.py --guide "Prof. A. B. Name" --member "Uday Babasaheb Baviskar|12345"

The layout follows the institute's format: A4 with a 1 pt page border, Times New Roman,
the institute letterhead on the cover, certificate, acknowledgement and index pages, and
the index's nine chapters in its order and wording. The script stops with an error if a
chapter or section of the index is missing or out of order. Front matter is 16 pt, as in
the format; chapter text is 12 pt with 1.5 line spacing.

The letterhead is the institute's branding and is not committed: pass --template-pdf once
(the letterhead image is extracted with PyMuPDF and cached in docs/report/assets/, which
git ignores) or --letterhead with an image file. Diagrams are rendered from
docs/report/diagrams/*.svg with Playwright's Chromium, the screenshots come from
docs/report/snapshots/ and the ROC and loss charts from models/.

On Windows with Microsoft Word installed, Word fills in the index page numbers and exports
a PDF next to the .docx (skip with --no-word); otherwise Word offers to update the page
numbers when the file is opened. Output goes to build/report/ (git-ignored).

Every number in the text is taken from README.md, docs/CAPSTONE_*.md,
models/training_report.json and models_research/ablation_results.md; keep them in step.
"""

import argparse
import re
import sys
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final

try:
    from docx import Document
    from docx.document import Document as DocumentType
    from docx.enum.section import WD_SECTION
    from docx.enum.style import WD_STYLE_TYPE
    from docx.enum.table import WD_CELL_VERTICAL_ALIGNMENT, WD_ROW_HEIGHT_RULE, WD_TABLE_ALIGNMENT
    from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_PARAGRAPH_ALIGNMENT, WD_TAB_ALIGNMENT
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn
    from docx.oxml.xmlchemy import BaseOxmlElement
    from docx.shared import Inches, Length, Mm, Pt
    from docx.table import Table, _Cell, _Row
    from docx.text.paragraph import Paragraph
except ImportError:  # pragma: no cover - guidance for a missing optional dependency
    sys.exit("python-docx is required: python -m pip install python-docx")

ROOT: Final = Path(__file__).resolve().parents[1]
REPORT_DIR: Final = ROOT / "docs" / "report"
DIAGRAMS: Final = REPORT_DIR / "diagrams"
SNAPSHOTS: Final = REPORT_DIR / "snapshots"
ASSETS: Final = REPORT_DIR / "assets"
MODELS: Final = ROOT / "models"
OUT_DIR: Final = ROOT / "build" / "report"
OUT_NAME: Final = "Sentinel-Graph_Project_Report"

TITLE: Final = "Sentinel-Graph: Multimodal AI-Assisted Phishing and Threat Intelligence Detection"
CLASS_LINE: Final = "(SYBSC CDS)"
SEMESTER: Final = "IV"
ACADEMIC_YEAR: Final = "2025 – 2026"
DOTS: Final = "……………………………"

FONT: Final = "Times New Roman"
CODE_FONT: Final = "Consolas"
FRONT_PT: Final = 16
BODY_PT: Final = 12
TEXT_WIDTH_PT: Final = 458  # A4 (595 pt) less 1.0 in left and 0.9 in right margins
LETTERHEAD_INDENT_PT: Final = (-45, -41)  # the format's letterhead runs into both margins
LETTERHEAD_WIDTH_PT: Final = 544

# The format's index, in order and in its wording. Every entry must be written, in order.
INDEX: Final[tuple[tuple[str, str], ...]] = (
    ("1", "Introduction to System"),
    ("1.1", "Motivation"),
    ("1.2", "Problem Statement"),
    ("1.3", "Purpose Of System"),
    ("1.4", "Objectives Of System"),
    ("1.5", "Literature Survey"),
    ("2", "System Analysis"),
    ("2.1", "Existing System"),
    ("2.2", "Scope and Limitations of Existing System"),
    ("2.3", "Project Perspective and Features"),
    ("2.4", "Stakeholders"),
    ("2.5", "Requirement Analysis"),
    ("2.6", "Feasibility Study"),
    ("3", "System Design"),
    ("3.1", "Design Constraints"),
    ("3.2", "System Model : Using OOSE"),
    ("3.2.1", "Entity Relationship Diagram"),
    ("3.2.2", "Class Diagram"),
    ("3.2.3", "Use Case Diagram"),
    ("3.2.4", "Activity Diagram"),
    ("3.2.5", "Deployment Diagram"),
    ("4", "Implementation Details"),
    ("4.1", "Software/Hardware Specifications"),
    ("5", "Snapshots"),
    ("6", "Implementation and Testing"),
    ("6.1", "Testing Approach"),
    ("6.2", "Unit Testing"),
    ("6.3", "Integration Testing"),
    ("7", "Conclusion"),
    ("8", "Future Scope"),
    ("9", "References"),
)

# **bold**, `code`, ^{superscript} and _{subscript} inside report text.
MARKUP: Final = re.compile(r"(\*\*.+?\*\*|`[^`]+`|\^\{[^}]+\}|_\{[^}]+\})")
LONG_TOKEN: Final = re.compile(r"\S{16,}")
ZERO_WIDTH_SPACE: Final = "​"


def breakable(text: str) -> str:
    """Let Word wrap long identifiers and paths after ``_`` and ``/`` instead of stretching justified lines."""
    return LONG_TOKEN.sub(
        lambda match: re.sub(r"([_/])", rf"\1{ZERO_WIDTH_SPACE}", match.group(0)).rstrip(ZERO_WIDTH_SPACE),
        text,
    )


@dataclass(frozen=True)
class Member:
    name: str
    seat_no: str = ""


def bookmark_name(number: str) -> str:
    return "sec_" + number.replace(".", "_")


# --------------------------------------------------------------------------- low-level XML


def force_font(rpr: BaseOxmlElement, name: str) -> None:
    """Point every script slot of ``rpr`` at ``name`` (theme fonts would otherwise win)."""
    fonts = rpr.find(qn("w:rFonts"))
    if fonts is None:
        fonts = OxmlElement("w:rFonts")
        rpr.insert(0, fonts)
    for attr in ("w:ascii", "w:hAnsi", "w:cs", "w:eastAsia"):
        fonts.set(qn(attr), name)
    for attr in ("w:asciiTheme", "w:hAnsiTheme", "w:cstheme", "w:eastAsiaTheme"):
        fonts.attrib.pop(qn(attr), None)


def black(rpr: BaseOxmlElement) -> None:
    color = rpr.find(qn("w:color"))
    if color is None:
        color = OxmlElement("w:color")
        rpr.append(color)
    color.set(qn("w:val"), "000000")
    for attr in ("w:themeColor", "w:themeShade", "w:themeTint"):
        color.attrib.pop(qn(attr), None)


def add_field(paragraph: Paragraph, instruction: str, placeholder: str = "") -> None:
    """Append a Word field (PAGE, PAGEREF …); Word computes its value."""
    for kind, text in (("begin", None), ("instr", instruction), ("separate", None), ("text", placeholder), ("end", None)):
        run = paragraph.add_run()
        if kind == "instr":
            node = OxmlElement("w:instrText")
            node.set(qn("xml:space"), "preserve")
            node.text = f" {text} "
            run._r.append(node)
        elif kind == "text":
            run.text = text or ""
        else:
            node = OxmlElement("w:fldChar")
            node.set(qn("w:fldCharType"), kind)
            run._r.append(node)


def add_page_border(sect_pr: BaseOxmlElement) -> None:
    """The format's border: a single 1 pt line 24 pt inside each page edge."""
    if sect_pr.find(qn("w:pgBorders")) is not None:
        return
    borders = OxmlElement("w:pgBorders")
    borders.set(qn("w:offsetFrom"), "page")
    for side in ("top", "left", "bottom", "right"):
        line = OxmlElement(f"w:{side}")
        line.set(qn("w:val"), "single")
        line.set(qn("w:sz"), "8")
        line.set(qn("w:space"), "24")
        line.set(qn("w:color"), "000000")
        borders.append(line)
    sect_pr.find(qn("w:pgMar")).addnext(borders)


def restart_page_numbers(sect_pr: BaseOxmlElement) -> None:
    numbering = OxmlElement("w:pgNumType")
    numbering.set(qn("w:start"), "1")
    sect_pr.find(qn("w:pgBorders")).addnext(numbering)


def shade(cell: _Cell, fill: str) -> None:
    tc_pr = cell._tc.get_or_add_tcPr()
    shading = OxmlElement("w:shd")
    shading.set(qn("w:val"), "clear")
    shading.set(qn("w:color"), "auto")
    shading.set(qn("w:fill"), fill)
    tc_pr.append(shading)


def fixed_layout(table: Table) -> None:
    layout = OxmlElement("w:tblLayout")
    layout.set(qn("w:type"), "fixed")
    table._tbl.tblPr.append(layout)


def keep_row_together(row: _Row) -> None:
    tr_pr = row._tr.get_or_add_trPr()
    tr_pr.append(OxmlElement("w:cantSplit"))


def repeat_as_header(row: _Row) -> None:
    tr_pr = row._tr.get_or_add_trPr()
    tr_pr.append(OxmlElement("w:tblHeader"))


# --------------------------------------------------------------------------- assets


def cached_letterhead() -> Path | None:
    found = sorted(ASSETS.glob("letterhead.*"))
    return found[0] if found else None


def extract_letterhead(pdf_path: Path) -> Path:
    """Copy the largest image on the format PDF's first page (the letterhead) into ASSETS."""
    try:
        import pymupdf
    except ImportError:
        sys.exit("--template-pdf needs PyMuPDF: python -m pip install pymupdf")
    with pymupdf.open(pdf_path) as pdf:  # type: ignore[no-untyped-call]
        images = pdf[0].get_images(full=True)
        if not images:
            sys.exit(f"{pdf_path} has no image on its first page to use as the letterhead")
        xref = max(images, key=lambda image: image[2] * image[3])[0]
        image = pdf.extract_image(xref)
    ASSETS.mkdir(parents=True, exist_ok=True)
    for old in ASSETS.glob("letterhead.*"):
        old.unlink()
    target = ASSETS / f"letterhead.{image['ext']}"
    target.write_bytes(image["image"])
    return target


def render_diagrams(out_dir: Path) -> dict[str, Path]:
    """Render docs/report/diagrams/*.svg to 2x PNGs (about 290 dpi at full text width)."""
    from playwright.sync_api import sync_playwright

    rendered: dict[str, Path] = {}
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page(device_scale_factor=2)
        for svg in sorted(DIAGRAMS.glob("*.svg")):
            page.set_content(
                "<!doctype html><html><body style='margin:0;background:#fff'>"
                f"{svg.read_text(encoding='utf-8')}</body></html>"
            )
            target = out_dir / f"{svg.stem}.png"
            page.locator("svg").first.screenshot(path=str(target))
            rendered[svg.stem] = target
        browser.close()
    return rendered


def image_aspect(path: Path) -> float:
    from PIL import Image

    with Image.open(path) as image:
        width, height = image.size
    return height / width


# --------------------------------------------------------------------------- document builder


class Report:
    def __init__(self, letterhead: Path | None, figures: dict[str, Path]) -> None:
        self.doc: DocumentType = Document()
        self.letterhead_path = letterhead
        self.figures = figures
        self._index_position = 0
        self._bookmark_id = 0
        self._chapter = "0"
        self._figure_no = 0
        self._table_no = 0
        self._setup_styles()
        self._setup_first_section()

    # ---- setup

    def _setup_styles(self) -> None:
        styles = self.doc.styles
        normal = styles["Normal"]
        normal.font.size = Pt(BODY_PT)
        force_font(normal.element.get_or_add_rPr(), FONT)
        normal.paragraph_format.space_after = Pt(6)
        normal.paragraph_format.line_spacing = 1.5

        for name, size, align, before, after in (
            ("Heading 1", 18, WD_ALIGN_PARAGRAPH.CENTER, 0, 18),
            ("Heading 2", 14, WD_ALIGN_PARAGRAPH.LEFT, 14, 6),
            ("Heading 3", 12, WD_ALIGN_PARAGRAPH.LEFT, 10, 4),
        ):
            style = styles[name]
            style.font.size = Pt(size)
            style.font.bold = True
            style.font.italic = False
            rpr = style.element.get_or_add_rPr()
            force_font(rpr, FONT)
            black(rpr)
            fmt = style.paragraph_format
            fmt.alignment = align
            fmt.space_before = Pt(before)
            fmt.space_after = Pt(after)
            fmt.line_spacing = 1.15
            fmt.keep_with_next = True

        label = styles.add_style("Chapter Label", WD_STYLE_TYPE.PARAGRAPH)
        label.base_style = normal
        label.font.size = Pt(14)
        label.font.bold = True
        fmt = label.paragraph_format
        fmt.alignment = WD_ALIGN_PARAGRAPH.CENTER
        fmt.page_break_before = True
        fmt.keep_with_next = True
        fmt.space_before = Pt(0)
        fmt.space_after = Pt(6)

        caption = styles.add_style("Report Caption", WD_STYLE_TYPE.PARAGRAPH)
        caption.base_style = normal
        caption.font.size = Pt(11)
        caption.font.bold = True
        fmt = caption.paragraph_format
        fmt.alignment = WD_ALIGN_PARAGRAPH.CENTER
        fmt.line_spacing = 1.0
        fmt.space_before = Pt(4)
        fmt.space_after = Pt(12)

        cell = styles.add_style("Table Text", WD_STYLE_TYPE.PARAGRAPH)
        cell.base_style = normal
        cell.font.size = Pt(11)
        fmt = cell.paragraph_format
        fmt.line_spacing = 1.0
        fmt.space_before = Pt(2)
        fmt.space_after = Pt(2)

        bullet = styles["List Bullet"]
        bullet.paragraph_format.space_after = Pt(3)
        bullet.paragraph_format.line_spacing = 1.5

    def _setup_first_section(self) -> None:
        section = self.doc.sections[0]
        section.page_width, section.page_height = Mm(210), Mm(297)
        section.top_margin, section.bottom_margin = Inches(0.9), Inches(0.8)
        section.left_margin, section.right_margin = Inches(1.0), Inches(0.9)
        section.header_distance = section.footer_distance = Inches(0.45)
        add_page_border(section._sectPr)

    # ---- index bookkeeping

    def _claim(self, number: str, title: str) -> None:
        expected = INDEX[self._index_position] if self._index_position < len(INDEX) else None
        if expected != (number, title):
            raise SystemExit(f"report heading {number} {title!r} does not match the format's index entry {expected}")
        self._index_position += 1

    def _bookmark(self, paragraph: Paragraph, name: str) -> None:
        self._bookmark_id += 1
        start = OxmlElement("w:bookmarkStart")
        start.set(qn("w:id"), str(self._bookmark_id))
        start.set(qn("w:name"), name)
        end = OxmlElement("w:bookmarkEnd")
        end.set(qn("w:id"), str(self._bookmark_id))
        p_pr = paragraph._p.pPr
        if p_pr is not None:
            p_pr.addnext(start)
        else:
            paragraph._p.insert(0, start)
        paragraph._p.append(end)

    def check_complete(self) -> None:
        if self._index_position != len(INDEX):
            missing = ", ".join(f"{n} {t}" for n, t in INDEX[self._index_position :])
            raise SystemExit(f"the report is missing index entries: {missing}")

    # ---- text helpers

    def rich(self, paragraph: Paragraph, text: str, *, size: float | None = None, bold: bool | None = None) -> None:
        for part in MARKUP.split(text):
            if not part:
                continue
            if part.startswith("**") and part.endswith("**"):
                run = paragraph.add_run(breakable(part[2:-2]))
                run.bold = True
            elif part.startswith("`") and part.endswith("`"):
                run = paragraph.add_run(breakable(part[1:-1]))
                force_font(run._r.get_or_add_rPr(), CODE_FONT)
                run.font.size = Pt((size or BODY_PT) - 2)
                if bold:
                    run.bold = True
                continue
            elif part.startswith("^{"):
                run = paragraph.add_run(part[2:-1])
                run.font.superscript = True
            elif part.startswith("_{"):
                run = paragraph.add_run(part[2:-1])
                run.font.subscript = True
            else:
                run = paragraph.add_run(breakable(part))
                if bold:
                    run.bold = True
            if size:
                run.font.size = Pt(size)

    def para(
        self,
        text: str,
        *,
        align: WD_PARAGRAPH_ALIGNMENT = WD_ALIGN_PARAGRAPH.JUSTIFY,
        italic: bool = False,
        indent: float = 0,
    ) -> Paragraph:
        paragraph = self.doc.add_paragraph()
        paragraph.alignment = align
        if indent:
            paragraph.paragraph_format.left_indent = Inches(indent)
            paragraph.paragraph_format.right_indent = Inches(indent)
        self.rich(paragraph, text)
        if italic:
            for run in paragraph.runs:
                run.italic = True
        return paragraph

    def bullets(self, items: list[str]) -> None:
        for item in items:
            paragraph = self.doc.add_paragraph(style="List Bullet")
            paragraph.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
            self.rich(paragraph, item)

    def numbered(self, items: list[str]) -> None:
        for number, item in enumerate(items, 1):
            paragraph = self.doc.add_paragraph()
            paragraph.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
            fmt = paragraph.paragraph_format
            fmt.left_indent = Inches(0.4)
            fmt.first_line_indent = Inches(-0.4)
            fmt.space_after = Pt(3)
            fmt.tab_stops.add_tab_stop(Inches(0.4))
            self.rich(paragraph, f"{number}.\t{item}")

    # ---- front matter (16 pt, as in the format)

    def letterhead(self, *, new_page: bool) -> None:
        paragraph = self.doc.add_paragraph()
        fmt = paragraph.paragraph_format
        fmt.page_break_before = new_page
        fmt.left_indent, fmt.right_indent = (Pt(value) for value in LETTERHEAD_INDENT_PT)
        fmt.space_before, fmt.space_after = Pt(0), Pt(6)
        fmt.line_spacing = 1.0
        paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
        if self.letterhead_path is not None:
            paragraph.add_run().add_picture(str(self.letterhead_path), width=Pt(LETTERHEAD_WIDTH_PT))

    def front(
        self,
        text: str,
        *,
        bold: bool = False,
        size: float = FRONT_PT,
        align: WD_PARAGRAPH_ALIGNMENT = WD_ALIGN_PARAGRAPH.CENTER,
        before: float = 0,
        after: float = 8,
    ) -> Paragraph:
        paragraph = self.doc.add_paragraph()
        paragraph.alignment = align
        fmt = paragraph.paragraph_format
        fmt.space_before, fmt.space_after = Pt(before), Pt(after)
        fmt.line_spacing = 1.08
        self.rich(paragraph, text, size=size, bold=bold)
        return paragraph

    def cover(self, members: list[Member], guide: str) -> None:
        self.letterhead(new_page=False)
        tight = 4 if len(members) > 2 else 8
        lines: list[tuple[str, bool]] = [
            ("A PROJECT REPORT ON", True),
            (TITLE, False),
            ("SUBMITTED BY", True),
            *((member.name, False) for member in members),
            (CLASS_LINE, True),
            ("Under The Guidance of", False),
            (guide or DOTS, False),
            ("SUBMITTED TO", False),
            ("SAVITRIBAI PHULE PUNE UNIVERSITY", True),
            ("In Partial Fulfilment of", False),
            ("BACHELOR OF SCIENCE", False),
            ("(CYBER AND DIGITAL SCIENCE)", False),
            ("SURYADATTA INTERNATIONAL INSTITUTE OF", True),
            ("CYBER SECURITY", True),
            ("(SIICS)", False),
            (ACADEMIC_YEAR, False),
            ("PUNE – 411021", False),
        ]
        for position, (text, bold) in enumerate(lines):
            self.front(text, bold=bold, before=24 if position == 0 else 0, after=tight)

    def certificate(self, member: Member) -> None:
        self.letterhead(new_page=True)
        self.front("CERTIFICATE", before=36, after=10)
        body = self.front(
            f"This is to certify that **{member.name}**, a student of B.Sc. Cyber and Digital Science, "
            f"Semester {SEMESTER}, having seat no. {member.seat_no or '…………'}, at Suryadatta International "
            "Institute of Cyber Security (SIICS), Pune, has successfully completed the assigned project titled "
            f"“{TITLE}” as per the norms of Savitribai Phule Pune University during the academic year "
            f"{ACADEMIC_YEAR}.",
            align=WD_ALIGN_PARAGRAPH.JUSTIFY,
        )
        body.paragraph_format.line_spacing = 1.15
        for left, right, before in (("Internal Examiner", "External Examiner", 84), ("Project Guide", "Principal", 72)):
            line = self.front(f"{left}\t{right}", align=WD_ALIGN_PARAGRAPH.LEFT, before=before)
            line.paragraph_format.tab_stops.add_tab_stop(Pt(TEXT_WIDTH_PT), WD_TAB_ALIGNMENT.RIGHT)
        self.front("Place : Pune", align=WD_ALIGN_PARAGRAPH.LEFT, before=12)
        self.front("Date :", align=WD_ALIGN_PARAGRAPH.LEFT)

    def acknowledgement(self, members: list[Member], guide: str) -> None:
        self.letterhead(new_page=True)
        self.front("ACKNOWLEDGEMENT", bold=True, before=24, after=12)
        solo = len(members) == 1
        name = f"**{guide or DOTS}**"
        if solo:
            paragraphs = [
                "The success and final outcome of this project required a great deal of guidance and assistance "
                "from many people, and I am extremely privileged to have received it throughout the completion "
                "of my project. All that I have done is only due to such supervision and assistance, and I would "
                "not forget to thank them.",
                f"I respect and thank my project guide {name} for providing me an opportunity to do this project "
                "work and for giving me all the support and guidance that helped me complete it. I am extremely "
                "thankful for such good support and guidance.",
                "I wish to record my appreciation to all my friends and others who helped me throughout the "
                "project work, directly or indirectly.",
                f"I owe a deep gratitude to my project guide {name} for taking a keen interest in my project work "
                "and guiding me all along, till its completion, by providing all the necessary information for "
                "developing a good system.",
                "I am thankful to, and fortunate enough to have received, constant encouragement, support and "
                "guidance from all the teaching staff of SIICS, which helped me in successfully completing my "
                "project work.",
            ]
        else:
            paragraphs = [
                "The success and final outcome of this project required a great deal of guidance and assistance "
                "from many people, and we are extremely privileged to have received it throughout the completion "
                "of our project. All that we have done is only due to such supervision and assistance, and we "
                "would not forget to thank them.",
                f"We respect and thank our project guide {name} for providing us an opportunity to do this project "
                "work and for giving us all the support and guidance that helped us complete it. We are extremely "
                "thankful for such good support and guidance.",
                "We wish to record our appreciation to all our friends and others who helped us throughout the "
                "project work, directly or indirectly.",
                f"We owe a deep gratitude to our project guide {name} for taking a keen interest in our project "
                "work and guiding us all along, till its completion, by providing all the necessary information "
                "for developing a good system.",
                "We are thankful to, and fortunate enough to have received, constant encouragement, support and "
                "guidance from all the teaching staff of SIICS, which helped us in successfully completing our "
                "project work.",
            ]
        for text in paragraphs:
            paragraph = self.front(text, align=WD_ALIGN_PARAGRAPH.JUSTIFY, after=10)
            paragraph.paragraph_format.line_spacing = 1.15
        self.front("Thank You", align=WD_ALIGN_PARAGRAPH.LEFT, before=20)
        for member in members:
            self.front(member.name, align=WD_ALIGN_PARAGRAPH.LEFT, after=2)

    def index_page(self) -> None:
        self.letterhead(new_page=True)
        self.front("INDEX", size=20, before=18, after=6)
        widths = (Pt(63), Pt(284), Pt(60))
        table = self.doc.add_table(rows=1, cols=3)
        table.style = "Table Grid"
        table.alignment = WD_TABLE_ALIGNMENT.CENTER
        table.autofit = False
        fixed_layout(table)

        def fill(
            cell: _Cell, width: Length, text: str | None = None, *, bold: bool = False, field: str | None = None
        ) -> None:
            cell.width = width
            cell.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER
            paragraph = cell.paragraphs[0]
            paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
            fmt = paragraph.paragraph_format
            fmt.space_before, fmt.space_after, fmt.line_spacing = Pt(5), Pt(5), 1.0
            if field:
                add_field(paragraph, field)
                for run in paragraph.runs:
                    run.font.size = Pt(FRONT_PT)
            else:
                self.rich(paragraph, text or "", size=FRONT_PT, bold=bold)

        for cell, width, text in zip(table.rows[0].cells, widths, ("SR No.", "TITLE", "Page No")):
            fill(cell, width, text, bold=True)
        for number, title in INDEX:
            row = table.add_row()
            row.height = Pt(30)
            row.height_rule = WD_ROW_HEIGHT_RULE.AT_LEAST
            keep_row_together(row)
            cells = row.cells
            fill(cells[0], widths[0], number)
            fill(cells[1], widths[1], title)
            fill(cells[2], widths[2], field=f"PAGEREF {bookmark_name(number)} \\h")

    # ---- body (12 pt)

    def start_body(self) -> None:
        section = self.doc.add_section(WD_SECTION.NEW_PAGE)
        section.top_margin, section.bottom_margin = Inches(1.0), Inches(0.9)
        add_page_border(section._sectPr)
        restart_page_numbers(section._sectPr)
        footer = section.footer
        footer.is_linked_to_previous = False
        paragraph = footer.paragraphs[0]
        paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
        add_field(paragraph, "PAGE", "1")
        for run in paragraph.runs:
            run.font.size = Pt(11)

    def chapter(self, number: str, title: str) -> None:
        self._claim(number, title)
        self._chapter, self._figure_no, self._table_no = number, 0, 0
        self.doc.add_paragraph(f"CHAPTER {number}", style="Chapter Label")
        heading = self.doc.add_paragraph(title.upper(), style="Heading 1")
        self._bookmark(heading, bookmark_name(number))

    def section(self, number: str, title: str) -> None:
        self._claim(number, title)
        level = 2 if number.count(".") == 1 else 3
        heading = self.doc.add_paragraph(f"{number}  {title}", style=f"Heading {level}")
        self._bookmark(heading, bookmark_name(number))

    def figure(self, image: Path, caption: str, *, width: float = 6.2, max_height: float = 7.4) -> None:
        if not image.exists():
            raise SystemExit(f"missing figure: {image}")
        height = width * image_aspect(image)
        if height > max_height:
            width = max_height / image_aspect(image)
        picture = self.doc.add_paragraph()
        picture.alignment = WD_ALIGN_PARAGRAPH.CENTER
        fmt = picture.paragraph_format
        fmt.keep_with_next = True
        fmt.space_before, fmt.space_after, fmt.line_spacing = Pt(8), Pt(2), 1.0
        picture.add_run().add_picture(str(image), width=Inches(width))
        self._figure_no += 1
        self.doc.add_paragraph(f"Figure {self._chapter}.{self._figure_no}: {caption}", style="Report Caption")

    def diagram(self, stem: str, caption: str, **sizing: float) -> None:
        self.figure(self.figures[stem], caption, **sizing)

    def table(
        self,
        caption: str,
        headers: tuple[str, ...],
        rows: Sequence[tuple[str, ...]],
        widths: tuple[float, ...],
        *,
        center: tuple[int, ...] = (),
        keep_together: bool | None = None,
    ) -> None:
        """A captioned grid. Short tables stay on one page; long ones never strand their header row."""
        if keep_together is None:
            keep_together = len(rows) <= 12
        self._table_no += 1
        title = self.doc.add_paragraph(f"Table {self._chapter}.{self._table_no}: {caption}", style="Report Caption")
        title.paragraph_format.keep_with_next = True
        title.paragraph_format.space_before, title.paragraph_format.space_after = Pt(10), Pt(4)
        table = self.doc.add_table(rows=1, cols=len(headers))
        table.style = "Table Grid"
        table.alignment = WD_TABLE_ALIGNMENT.CENTER
        table.autofit = False
        fixed_layout(table)
        repeat_as_header(table.rows[0])
        for column, (cell, header) in enumerate(zip(table.rows[0].cells, headers)):
            cell.width = Inches(widths[column])
            shade(cell, "D9D9D9")
            paragraph = cell.paragraphs[0]
            paragraph.style = self.doc.styles["Table Text"]
            paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
            paragraph.paragraph_format.keep_with_next = True
            self.rich(paragraph, header, size=11, bold=True)
        for position, values in enumerate(rows):
            row = table.add_row()
            keep_row_together(row)
            last = position == len(rows) - 1
            for column, (cell, value) in enumerate(zip(row.cells, values)):
                cell.width = Inches(widths[column])
                paragraph = cell.paragraphs[0]
                paragraph.style = self.doc.styles["Table Text"]
                paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER if column in center else WD_ALIGN_PARAGRAPH.LEFT
                paragraph.paragraph_format.keep_with_next = (keep_together and not last) or position == 0
                self.rich(paragraph, value, size=11)
        spacer = self.doc.add_paragraph()
        spacer.paragraph_format.space_after = Pt(4)
        spacer.paragraph_format.line_spacing = 1.0

    def references(self, entries: list[str]) -> None:
        for number, entry in enumerate(entries, 1):
            paragraph = self.doc.add_paragraph()
            paragraph.alignment = WD_ALIGN_PARAGRAPH.LEFT
            fmt = paragraph.paragraph_format
            fmt.left_indent, fmt.first_line_indent = Inches(0.45), Inches(-0.45)
            fmt.line_spacing, fmt.space_after = 1.15, Pt(6)
            fmt.tab_stops.add_tab_stop(Inches(0.45))
            self.rich(paragraph, f"[{number}]\t{entry}")

    def save(self, path: Path, *, members: list[Member]) -> None:
        props = self.doc.core_properties
        props.title = TITLE
        props.author = ", ".join(member.name for member in members)
        props.subject = "Project report, B.Sc. Cyber and Digital Science (SIICS, SPPU)"
        props.keywords = "phishing detection, graph neural networks, MemAE, SHAP, SOC"
        path.parent.mkdir(parents=True, exist_ok=True)
        self.doc.save(str(path))

    def ask_word_to_update_fields(self) -> None:
        flag = OxmlElement("w:updateFields")
        flag.set(qn("w:val"), "true")
        self.doc.settings.element.append(flag)


# --------------------------------------------------------------------------- chapters


def chapter_1(r: Report) -> None:
    r.chapter("1", "Introduction to System")
    r.para(
        "Email remains the channel through which most organisations are first attacked. A single convincing "
        "message can lead an employee to surrender credentials, approve a fraudulent payment or open a malicious "
        "document. Security Operations Centre (SOC) analysts are expected to triage such messages quickly, but "
        "doing it properly means reading raw headers, checking sender authentication, tracing the delivery path, "
        "opening the link safely and weighing all of that evidence together — work that takes minutes per email "
        "when done by hand."
    )
    r.para(
        "**Sentinel-Graph** is a multimodal, AI-assisted phishing and threat-intelligence detection system that "
        "performs this triage in seconds. It analyses a raw email (`.eml` file) the way an analyst would: it "
        "verifies the sender's authentication results, models the delivery route as a graph and scores it for "
        "anomalies, detonates the email's first link in a sandboxed browser, asks a local language model to "
        "reason about the evidence, and fuses everything into a single risk score that is explained feature by "
        "feature with SHAP. Every step streams live to a web dashboard over a WebSocket, and every verdict is "
        "stored with its indicators (IP addresses, URLs and sender domains), so an analyst can pivot from one "
        "indicator to every scan that contained it."
    )
    r.para(
        "The system is written in Python (FastAPI, PyTorch, PyTorch Geometric, ONNX Runtime, scikit-learn and "
        "Playwright) with a React and Three.js front end, runs entirely on a CPU-only laptop and is verified by "
        "372 automated tests. Its two trained models — a memory-augmented graph autoencoder for delivery routes "
        "and a Random Forest fusion model — reach an out-of-fold ROC-AUC of **0.953** on a public research "
        "corpus and detect **61.4%** of unseen phishing emails from 2023–25."
    )

    r.section("1.1", "Motivation")
    r.para(
        "Phishing remains among the most common ways attackers gain initial access to organisations, a pattern "
        "documented quarter after quarter by industry bodies such as the Anti-Phishing Working Group [1]. "
        "Defences have improved, yet three trends keep eroding the classic approach of classifying an email by "
        "its words:"
    )
    r.bullets(
        [
            "**Generated text.** Large language models let an attacker write a fluent, unique lure for every "
            "target, so there is no repeated wording for a text classifier or a signature to learn.",
            "**Obfuscation.** Brand names are spelt with look-alike Unicode characters (homoglyphs), split by "
            "invisible zero-width characters or hidden in image-only bodies, which defeats keyword and "
            "bag-of-words models.",
            "**Opaque verdicts.** Many filters return a bare label. An analyst who cannot see why a message was "
            "flagged can neither justify blocking it nor learn from a false alarm, and alert fatigue grows.",
        ]
    )
    r.para(
        "What an attacker cannot change as cheaply is how the message is delivered and what its link does when "
        "it is opened. Every email carries a chain of `Received` headers written by the mail servers that relayed "
        "it and the authentication results stamped by the receiving server; every lure link leads to a page "
        "that must eventually render. Sentinel-Graph is built around that observation: it treats the delivery "
        "route as a graph, renders the link in an isolated browser, and combines those signals with protocol and "
        "content evidence."
    )
    r.para(
        "A further motivation is privacy. Emails contain personal data, and sending them to a cloud "
        "language-model API raises obligations under data-protection law such as India's Digital Personal Data "
        "Protection Act, 2023 [2]. Running every model on the analyst's own machine keeps that data local."
    )

    r.section("1.2", "Problem Statement")
    r.para(
        "Existing email defences and manual triage leave a gap between a fast but opaque filter verdict and a "
        "slow but thorough analyst investigation. The problem addressed by this project is stated as follows:"
    )
    r.para(
        "To design and implement a system that accepts a raw RFC 5322 [24] email message and, within seconds and "
        "entirely on the analyst's own machine, (i) extracts and verifies protocol-level evidence, (ii) models the "
        "delivery route as a graph and scores it for anomalies without labelled examples of attacks, (iii) safely "
        "renders the email's first link in an isolated browser, (iv) reasons over the evidence with a local "
        "language model, and (v) fuses all evidence into one phishing-risk score whose every contribution is "
        "explained — streaming each step to an analyst dashboard and recording indicators for later "
        "investigation.",
        italic=True,
        indent=0.4,
    )
    r.para(
        "The system must stay robust against hostile input — malformed MIME, forged headers, prompt injection and "
        "server-side request forgery through the sandbox — and must report its own limitations honestly, flagging "
        "every engine that runs without trained weights."
    )

    r.section("1.3", "Purpose Of System")
    r.para(
        "The purpose of Sentinel-Graph is to give a SOC analyst an evidence-backed first verdict on a suspicious "
        "email in seconds, and to show exactly how that verdict was reached. Specifically, the system is meant to:"
    )
    r.bullets(
        [
            "reduce triage time by automating header analysis, route analysis and safe link detonation, which an "
            "analyst would otherwise perform by hand;",
            "make the evidence visible: the delivery route is drawn hop by hop on a 3D globe and as a graph, and "
            "the final score is broken into per-feature SHAP contributions;",
            "keep sensitive email content on the analyst's machine by running every model locally;",
            "build institutional memory: every scan and its indicators are stored, so a new email can be linked to "
            "earlier campaigns through a shared IP address, URL or domain;",
            "serve as a reproducible research platform, with out-of-fold evaluation, an out-of-time test and an "
            "ablation study that measure what each component contributes.",
        ]
    )

    r.section("1.4", "Objectives Of System")
    r.para("The objectives set for, and met by, the project are:")
    r.numbered(
        [
            "**Hostile-input parsing** — unpack malformed MIME without crashing, recording each defect instead of "
            "raising, and extract links the way a browser reads them.",
            "**Identity verification** — read SPF, DKIM, DMARC and ARC results from the trusted "
            "`Authentication-Results` header only, and detect display-name brand spoofing after homoglyph, "
            "zero-width and leetspeak folding.",
            "**Route forensics** — analyse the sender-side `Received` chain for hop count, private addresses "
            "between public hops and timestamps that run backwards.",
            "**Content heuristics** — score the randomness (Shannon entropy) of each link's registrable domain "
            "label and the presence of coercive, urgency-inducing phrases.",
            "**Topology anomaly detection** — model each delivery route as a directed acyclic graph and score it "
            "with a memory-augmented graph autoencoder trained on legitimate mail only, with a calibrated "
            "zero-day threshold.",
            "**Safe detonation** — render the first link in headless Chromium with JavaScript disabled, behind an "
            "egress proxy that can reach only public internet addresses.",
            "**Local reasoning** — build an injection-hardened prompt for a local small language model, stream its "
            "reasoning and extract a verdict that can escalate but never downgrade.",
            "**Explainable fusion** — combine twelve features from five subsystems in a Random Forest and "
            "attribute every score exactly with TreeSHAP.",
            "**Live analyst interface** — stream every step over a WebSocket to a React dashboard with a 3D globe, "
            "a route graph, an ML-forensics page, scan history with indicator pivots, and JSON/CSV export.",
            "**Honest evaluation** — measure performance out of fold and out of time, run a drop-column ablation "
            "study, and flag every stand-in model in each response.",
        ]
    )

    r.section("1.5", "Literature Survey")
    r.para(
        "This section reviews the work Sentinel-Graph builds on, grouped by the problem each line of work "
        "addresses. Table 1.1 summarises it."
    )
    r.para(
        "**Machine-learning phishing detection.** Fette, Sadeh and Tomasic [3] showed that a small set of "
        "structural features — such as links that use IP addresses, mismatched link text and the number of "
        "linked domains — fed to a Random Forest detects phishing email accurately (the PILFER system). "
        "Abu-Nimeh et al. [4] compared logistic regression, classification trees, Random Forests, support vector "
        "machines and neural networks on phishing email and found no single learner dominant, which points to the "
        "features rather than the model as the lever. Both rely on content and URL features of the message and "
        "do not model the delivery path."
    )
    r.para(
        "**Email authentication.** SPF [5], DKIM [6], DMARC [7] and ARC [8] let a receiving server verify that a "
        "message was sent by a server authorised for its domain, and RFC 8601 [9] defines the "
        "`Authentication-Results` header in which the verdicts are recorded. These mechanisms are necessary but "
        "not sufficient: an attacker who registers a look-alike domain passes all of them, and headers written "
        "below the receiver's own boundary can be forged. Sentinel-Graph therefore trusts only the "
        "`Authentication-Results` header stamped by its own boundary."
    )
    r.para(
        "**Graph neural networks.** Kipf and Welling [10] introduced the graph convolutional network (GCN), whose "
        "layer-wise propagation rule aggregates each node's neighbourhood; PyTorch Geometric [11] provides "
        "efficient implementations. A delivery route — sender, relays, receiver and links — is naturally a small "
        "graph, so GCN layers can learn a representation of its structure."
    )
    r.para(
        "**Anomaly detection with memory.** Autoencoders flag anomalies by their reconstruction error, but they "
        "often generalise well enough to reconstruct anomalies too. Gong et al. [12] proposed the "
        "memory-augmented autoencoder (MemAE), which rebuilds each latent code from a sparse combination of "
        "learned prototypes of normal data, with hard shrinkage keeping the addressing sparse; anomalies cannot "
        "be expressed by the memory and reconstruct poorly. Sentinel-Graph applies this idea to delivery-route "
        "graphs, trained on legitimate mail only."
    )
    r.para(
        "**Domain-generation algorithms.** Malware and phishing kits often mint throwaway domains "
        "algorithmically. Antonakakis et al. [13] detected such domain-generation-algorithm (DGA) traffic at "
        "scale, and Woodbridge et al. [14] classified DGA domains with LSTM networks. Character-level Shannon "
        "entropy [15] is the simplest lexical signal of a machine-generated label and is used here as one fusion "
        "feature."
    )
    r.para(
        "**Explainable AI.** Lundberg and Lee [16] unified feature-attribution methods under Shapley values "
        "(SHAP), and TreeSHAP [17] computes them exactly and efficiently for tree ensembles such as Random "
        "Forests [18], which Sentinel-Graph uses as its fusion model."
    )
    r.para(
        "**Small language models and lightweight vision.** Phi-3 [19] showed that a model small enough to run on "
        "a laptop can reason competitively, which makes local, privacy-preserving inference practical; "
        "MobileNetV3 [20] is a compact image backbone of the kind reserved for the screenshot-embedding slot."
    )
    r.para(
        "**Datasets.** The public SpamAssassin corpus [21] and Jose Nazario's phishing corpus [22] are freely "
        "available sources of legitimate and phishing email with intact routing headers. The widely used Enron "
        "corpus was rejected because its public release strips the `Received` headers, so every legitimate email "
        "would have no route and a route model would learn “has headers” instead of phishing."
    )
    r.para(
        "**Research gap.** Prior systems typically use one modality (text or URL features), do not model the "
        "delivery topology, return unexplained labels, or depend on cloud services. Sentinel-Graph combines "
        "protocol, topology, visual and language evidence in one locally deployed pipeline whose every score is "
        "decomposed with exact SHAP values."
    )
    r.table(
        "Summary of the literature survey",
        ("Ref.", "Work", "Approach", "What Sentinel-Graph adds"),
        [
            ("[3]", "Fette et al., 2007", "Structural email and URL features with a Random Forest",
             "Delivery-route graph and exact per-feature explanations"),
            ("[4]", "Abu-Nimeh et al., 2007", "Comparison of six classifiers on phishing email",
             "Fusion of five evidence sources rather than one feature set"),
            ("[5]–[9]", "SPF, DKIM, DMARC, ARC, RFC 8601", "Sender authentication at the receiving server",
             "Trusts only its own boundary's verdicts; adds spoofing and route checks"),
            ("[10], [11]", "Kipf & Welling, 2017; PyG", "Graph convolution", "Applied to email delivery DAGs"),
            ("[12]", "Gong et al., 2019", "Memory-augmented autoencoder",
             "Trained on benign routes to flag zero-day routes"),
            ("[13], [14]", "Antonakakis et al., 2012; Woodbridge et al., 2016", "DGA detection",
             "Registrable-label entropy as one fused feature"),
            ("[16]–[18]", "Lundberg & Lee, 2017; Lundberg et al., 2020; Breiman, 2001",
             "SHAP, TreeSHAP, Random Forest", "Exact attributions shown to the analyst live"),
        ],
        (0.7, 1.55, 1.95, 2.0),
        center=(0,),
    )


def chapter_2(r: Report) -> None:
    r.chapter("2", "System Analysis")
    r.para(
        "System analysis examines how phishing email is handled today, where those methods fall short, and what "
        "Sentinel-Graph must therefore provide."
    )

    r.section("2.1", "Existing System")
    r.para("In a typical organisation, suspicious email is handled by a combination of automated filtering and manual analysis:")
    r.bullets(
        [
            "**Secure email gateways and spam filters** score messages using sender reputation, blocklists of "
            "known-bad IP addresses and domains, signature rules and statistical text classifiers (for example "
            "the rule-and-Bayes scoring of Apache SpamAssassin).",
            "**Authentication at the receiving server** evaluates SPF, DKIM and DMARC and records the results in an "
            "`Authentication-Results` header; failing messages may be quarantined according to the sender's DMARC "
            "policy.",
            "**URL reputation services** check links against lists of known phishing sites, sometimes rewriting the "
            "links so they can be checked again when clicked.",
            "**Manual SOC triage** handles what users report: an analyst reads the raw headers, traces the "
            "`Received` chain, looks up IP addresses, opens the link in an isolated virtual machine or an online "
            "sandbox, and records the indicators in a ticket.",
            "**General-purpose AI assistants** are increasingly used to summarise suspicious emails, usually "
            "through cloud APIs.",
        ]
    )

    r.section("2.2", "Scope and Limitations of Existing System")
    r.para(
        "Existing systems handle bulk spam and known-bad infrastructure well: blocklists and reputation scores "
        "stop large campaigns from recognised senders, and authentication checks stop crude domain spoofing. "
        "Their limitations appear with targeted and novel phishing:"
    )
    r.bullets(
        [
            "**Reactive lists.** Blocklists and reputation services know only infrastructure that has already been "
            "reported, so a freshly registered domain or a new relay is not listed in the first hours of a "
            "campaign.",
            "**Text dependence.** Content classifiers are evaded by model-generated text, homoglyphs, zero-width "
            "characters and image-only bodies.",
            "**Authentication is not intent.** A look-alike domain controlled by the attacker passes SPF, DKIM and "
            "DMARC, while mailing lists and forwarding break SPF for legitimate mail.",
            "**No explanation.** Gateways return a score or a label without a per-evidence breakdown, so analysts "
            "cannot see why a message was flagged.",
            "**Slow manual work.** Reading headers, tracing routes and detonating links by hand takes minutes per "
            "email and does not scale with report volume.",
            "**Data exposure.** Submitting emails or links to online sandboxes and cloud AI services discloses "
            "indicators, and possibly personal data, to third parties.",
            "**Need for labels.** Supervised models learn only attacks that appear in their training data and "
            "cannot flag an unseen delivery pattern.",
        ]
    )

    r.section("2.3", "Project Perspective and Features")
    r.para(
        "Sentinel-Graph is a standalone, locally deployed analyst tool. It does not replace the mail gateway; it "
        "complements it with a deep, explained analysis of any email exported as an `.eml` file. Figure 2.1 shows "
        "the architecture: a FastAPI back end runs four analysis tiers and a fusion stage, streams telemetry to a "
        "React dashboard and stores the results in SQLite. The principal features are:"
    )
    r.bullets(
        [
            "**Live streaming analysis** — every step is pushed to the dashboard over a WebSocket as it completes; "
            "Tier 1 takes about 6 ms and a complete assessment with a live detonation about 4 s on a laptop CPU.",
            "**Four evidence tiers** — protocol forensics, sandboxed vision, delivery topology and local "
            "language-model reasoning.",
            "**Delivery-topology graph with a zero-day flag** — a memory-augmented graph autoencoder trained on "
            "legitimate routes only.",
            "**Twelve-feature explainable fusion** — a Random Forest whose every score is decomposed into exact "
            "SHAP contributions per feature and per subsystem.",
            "**Hardened sandbox** — headless Chromium with JavaScript disabled, downloads refused and an egress "
            "proxy that defeats server-side request forgery and DNS rebinding.",
            "**3D route globe and route graph** — hops geolocated (or clearly marked as estimated) and drawn as "
            "arcs; graph edges coloured by the sign of their subsystem's SHAP impact.",
            "**Threat-intelligence history** — every scan stored with its IP, URL and domain indicators, with a "
            "pivot from an indicator to every scan that saw it.",
            "**ML-forensics page** — each of the twelve features with its value, its SHAP impact and an "
            "explanation.",
            "**Report export** — the current assessment as JSON or CSV and the whole history as CSV, protected "
            "against spreadsheet formula injection.",
            "**Honest model status** — every response states which engines are stand-ins, and the dashboard labels "
            "their scores.",
            "**Reproducible research tooling** — corpus download, training with cross-fitting and out-of-fold "
            "evaluation, and a drop-column ablation study.",
        ]
    )
    r.diagram("architecture", "System architecture of Sentinel-Graph", max_height=7.6)
    r.para(
        "Tier 1 runs first because every later tier needs its output (bodies, URLs and route); the vision and "
        "topology tiers then run concurrently, the language model reasons over all the evidence, and the fusion "
        "model produces the final score. Dashed lines in Figure 2.1 are the telemetry events that reach the "
        "dashboard as each step completes."
    )

    r.section("2.4", "Stakeholders")
    r.para("Table 2.1 lists the stakeholders of the system and their interest in it.")
    r.table(
        "Stakeholders",
        ("Stakeholder", "Role", "Interest in the system"),
        [
            ("SOC analyst", "Primary user", "Fast, explained verdicts; route and indicator context; exportable evidence"),
            ("SOC manager / CISO", "Decision maker", "Shorter triage time; consistent, auditable decisions"),
            ("Incident responder / threat-intelligence team", "Secondary user",
             "Indicator pivots that link scans to one campaign; JSON/CSV exports"),
            ("Email / IT administrator", "Operator",
             "Local deployment, `SOC_` environment settings, health endpoint, NDJSON logs for SIEM ingestion"),
            ("ML engineer / researcher", "Maintainer",
             "Reproducible training, out-of-fold metrics, ablation study, swappable model files"),
            ("Employees (email recipients)", "Protected party",
             "Fewer successful phishing attacks; their mail stays on the organisation's machines"),
            ("Data protection officer", "Compliance",
             "No email content sent to third-party AI providers; optional Geo-IP lookups can be disabled"),
            ("Project guide and examiners", "Academic evaluators",
             "Verifiable results, documented limitations and a working demonstration"),
        ],
        (1.9, 1.35, 2.95),
    )

    r.section("2.5", "Requirement Analysis")
    r.para(
        "Requirements were derived from the problem statement and the limitations of existing systems. "
        "Functional requirements describe what the system does (Table 2.2); non-functional requirements describe "
        "the qualities it must have (Table 2.3)."
    )
    r.table(
        "Functional requirements",
        ("ID", "Requirement"),
        [
            ("FR1", "Accept one raw RFC 5322 email per WebSocket connection as a single binary frame; reject text "
                    "frames and messages larger than 16 MiB."),
            ("FR2", "Unpack MIME bodies and attachments defensively, recording defects instead of failing."),
            ("FR3", "Extract browser-equivalent URLs from the HTML and plain-text bodies."),
            ("FR4", "Report SPF, DKIM, DMARC and ARC results from the trusted Authentication-Results header and "
                    "score display-name brand spoofing."),
            ("FR5", "Analyse the sender-side Received chain for hop count, private-address leaks and timestamp "
                    "regression."),
            ("FR6", "Compute the DGA entropy of link labels and an NLP coercion score."),
            ("FR7", "Build the delivery DAG, compute the MemAE anomaly loss and flag zero-day routes."),
            ("FR8", "Detonate the first URL in the sandbox and embed the screenshot."),
            ("FR9", "Stream local language-model reasoning and extract a verdict."),
            ("FR10", "Compute the 12-feature fusion risk (0–100) with per-feature SHAP attributions."),
            ("FR11", "Stream a telemetry event for every step and a final COMPLETE event with the assessment."),
            ("FR12", "Persist each scan with its indicators and expose paginated history and indicator-pivot APIs."),
            ("FR13", "Show live, history, ML-forensics and export pages in the dashboard."),
            ("FR14", "Export the current assessment (JSON, CSV) and the history (CSV)."),
            ("FR15", "Provide offline scripts for corpus download, training, evaluation and ablation."),
        ],
        (0.7, 5.5),
        center=(0,),
    )
    r.table(
        "Non-functional requirements",
        ("Quality", "Requirement", "How it is met"),
        [
            ("Performance", "Tier 1 in milliseconds; a full assessment within seconds on a laptop CPU",
             "Tier 1 ≈ 6 ms; ≈ 4 s end to end with a live detonation; vision and topology run concurrently"),
            ("Security", "Hostile input must not crash or compromise the system",
             "Defect harvesting, egress proxy, JavaScript off, Origin check, injection-hardened prompt, "
             "`weights_only` model loading"),
            ("Privacy", "Email content stays on the host",
             "Local language model; Geo-IP lookups skip private addresses and can be switched off"),
            ("Reliability", "A failing component must not lose the verdict",
             "Database faults are logged and rolled back; a failed detonation leaves vision empty; parsing never "
             "raises"),
            ("Explainability", "Every score must be decomposable",
             "Exact TreeSHAP: base value + Σ SHAP = predicted probability (to 10^{−6})"),
            ("Honesty", "Stand-in models must be visible", "`model_status` flags in every response and on the dashboard"),
            ("Portability", "Runs on commodity hardware", "CPU only; Windows, Linux and macOS; one-command setup scripts"),
            ("Maintainability", "Changes must be verifiable", "372 automated tests, strict mypy, TypeScript build"),
        ],
        (1.25, 2.15, 2.8),
    )

    r.section("2.6", "Feasibility Study")
    r.para("The feasibility of the project was assessed along four dimensions.")
    r.para(
        "**Technical feasibility.** Every component is built from mature open-source software — FastAPI, PyTorch, "
        "PyTorch Geometric, ONNX Runtime, scikit-learn, SHAP, Playwright, React and Three.js — and all inference "
        "runs on a CPU. The measured latency (about 6 ms for Tier 1 and about 4 s for a full assessment with a "
        "live detonation) confirms that a laptop is sufficient."
    )
    r.para(
        "**Economic feasibility.** All software is free and open source and both training corpora are public, so "
        "the only cost is commodity hardware. A GPU is optional and only speeds up a real language model once "
        "one is installed."
    )
    r.para(
        "**Operational feasibility.** Analysts use a web browser. Setup is automated by `setup.bat` or "
        "`setup.sh`, which install the Python packages, Playwright's Chromium and the front-end modules, and the "
        "trained models ship in the repository, so a fresh clone scores emails as documented without retraining."
    )
    r.para(
        "**Legal and ethical feasibility.** The Nazario corpus is published under CC-BY-4.0 and attributed, and "
        "the SpamAssassin corpus is a public research corpus. The sandbox reaches only public addresses, so "
        "detonating a lure cannot be used to probe internal systems. The demonstration emails use the reserved "
        "`.invalid` domain and cannot contact real sites, and local inference keeps personal data away from "
        "third-party services, in line with the DPDP Act, 2023 [2]."
    )
    r.para("The study concluded that the project is feasible on all four counts.")


def chapter_3(r: Report) -> None:
    r.chapter("3", "System Design")
    r.para(
        "This chapter records the constraints the design had to respect and models the system with "
        "object-oriented software engineering (OOSE) diagrams."
    )

    r.section("3.1", "Design Constraints")
    r.bullets(
        [
            "**Local, CPU-only execution.** All inference runs on the analyst's machine without a GPU or a cloud "
            "service (ONNX Runtime's CPU execution provider and CPU PyTorch).",
            "**Platform versions.** Python 3.12 or later for the back end; Node.js 20.19 or later for the Vite 8 "
            "front end.",
            "**One email per connection.** The WebSocket protocol accepts exactly one binary frame of at most "
            "16 MiB (`SOC_MAX_EMAIL_BYTES`).",
            "**Strict data contracts.** Every tier returns a frozen, strict Pydantic model, so a malformed result "
            "fails loudly instead of propagating.",
            "**Append-only feature order.** The twelve fusion features have fixed names and order; a saved model "
            "receives its columns by name, so a new feature can be added without breaking a deployed model.",
            "**Single-file database.** Scan history uses SQLite through asynchronous SQLAlchemy, which suits a "
            "single-analyst deployment.",
            "**Sandbox isolation.** Detonation runs with Chromium's OS sandbox, JavaScript disabled and all "
            "traffic forced through the egress proxy.",
            "**Trusted model directory.** joblib files are pickles, so `MODELS_DIR` must be as trusted as the "
            "source tree; PyTorch checkpoints load with `weights_only=True`.",
            "**Browser channel security.** CORS does not cover WebSockets, so the server checks the `Origin` "
            "header itself; CORS defaults to the development origins, never to every origin.",
            "**Training-data limits.** The public corpora predate DMARC and carry no `Authentication-Results` "
            "headers, and vision and the language model cannot run per training email; five of the twelve "
            "features are therefore constant during training.",
        ]
    )

    r.section("3.2", "System Model : Using OOSE")
    r.para(
        "Object-Oriented Software Engineering (OOSE), introduced by Jacobson et al. [25], is a use-case-driven "
        "methodology: requirements are captured as use cases, and the analysis and design models are derived "
        "from them and traced back to them. The diagrams below model Sentinel-Graph's data, static structure, "
        "interactions, behaviour and deployment."
    )

    r.section("3.2.1", "Entity Relationship Diagram")
    r.para(
        "Scan history is stored in two tables (Figure 3.1). EMAIL SCAN (`email_scans`) holds one row per "
        "analysed email: an integer primary key, a UTC timestamp, the decoded subject and sender, the final "
        "verdict, the overall risk (constrained to 0–100) and the language model's analyst trace. EXTRACTED "
        "INDICATOR (`extracted_indicators`) holds every distinct IP address, URL and sender-side domain seen in "
        "a scan, with a foreign key to its scan and a malicious flag. One scan extracts many indicators, and "
        "deleting a scan cascades to its indicators. A composite index on (type, value) makes the indicator "
        "pivot — every scan that saw this IP address — a single indexed lookup."
    )
    r.diagram("er_diagram", "Entity relationship diagram of the scan-history database")

    r.section("3.2.2", "Class Diagram")
    r.para(
        "Figure 3.2 shows the principal classes. The `orchestrator` module's `stream_analysis_pipeline` "
        "coordinates an analysis. It receives the engines through the frozen `AnalysisEngines` dataclass, which "
        "is loaded once per process and composes the four engines: `VisualSpoofDetector` (ONNX vision), "
        "`GraphMemAE` (the topology autoencoder, a PyTorch module with a 50 × 16 memory), `FusionMetaModel` (the "
        "Random Forest) and `CognitiveSLM` (the local language model). Telemetry goes through "
        "`ConnectionManager`, which serialises the writes to each socket with a per-connection lock. The result "
        "is a frozen `ThreatAssessment` composed of `HeaderForensics`, an optional `VisionForensics` (absent when "
        "no link could be rendered) and `TopologyForensics`. Persistence uses two SQLAlchemy entities, "
        "`EmailScanRecord` and `ExtractedIndicator`, in a one-to-many composition."
    )
    r.diagram("class_diagram", "Class diagram", max_height=7.6)

    r.section("3.2.3", "Use Case Diagram")
    r.para(
        "Figure 3.3 shows the actors and use cases. The SOC analyst uploads an email, watches the live telemetry, "
        "reads the risk score and verdict, inspects the SHAP explanation, views the delivery route, browses the "
        "history, pivots on indicators and exports reports. Uploading an email includes the “Analyse email” use "
        "case, which in turn includes detonating the first URL — the only use case that touches the lure "
        "website, and only through the egress proxy. Viewing the route includes geolocating its hops through the "
        "optional Geo-IP service. The ML engineer or administrator checks engine health and trains and evaluates "
        "the models; the ablation study extends the evaluation."
    )
    r.diagram("use_case_diagram", "Use case diagram")

    r.section("3.2.4", "Activity Diagram")
    r.para(
        "Figure 3.4 shows the activity flow of one analysis. After the size check, Tier 1 runs; the flow then "
        "forks into the vision branch (detonate the first URL if there is one, and embed the screenshot if one "
        "was captured) and the topology branch (build the DAG, compute the MemAE loss and flag a zero-day "
        "route). After the join, the language model reasons over all the evidence, the fusion model scores the "
        "twelve-feature vector and SHAP explains it, the scan is saved, and the COMPLETE event closes the stream. "
        "A database failure is logged and rolled back without withholding the verdict."
    )
    r.diagram("activity_diagram", "Activity diagram of one email analysis", max_height=8.0)

    r.section("3.2.5", "Deployment Diagram")
    r.para(
        "Figure 3.5 shows the deployment. Everything runs on one analyst workstation. The browser loads the React "
        "single-page application from the Vite development server on port 5173, which proxies `/api` and `/ws` "
        "to the Uvicorn server on port 8000. The Python process hosts the FastAPI application, the inference "
        "engines, the model files, the SQLite database and the Chromium sandbox with its loopback egress proxy. "
        "Only two connections leave the host: the sandbox's request to the lure web server, restricted to "
        "vetted public addresses, and the browser's optional Geo-IP lookups."
    )
    r.diagram("deployment_diagram", "Deployment diagram")


FEATURES: Final = [
    ("0", "`auth_fail_count`", "Protocol forensics", "SPF / DKIM / DMARC / ARC results that are fail"),
    ("1", "`display_name_spoof_risk`", "Protocol forensics", "Brand in the display name (1.0) or only in the subject (0.5)"),
    ("2", "`private_ip_leak`", "Protocol forensics", "A private address between public hops"),
    ("3", "`timestamp_regression`", "Protocol forensics", "A later hop stamped before an earlier one"),
    ("4", "`screenshot_hash_exists`", "Vision", "The lure rendered in the sandbox"),
    ("5", "`visual_spoof_score`", "Vision", "Visual similarity to a protected brand"),
    ("6", "`is_cred_harvester`", "Vision", "The page collects credentials"),
    ("7", "`graph_nodes_count`", "Topology", "Nodes in the delivery DAG"),
    ("8", "`memae_loss`", "Topology (GNN)", "MemAE reconstruction loss of the delivery graph"),
    ("9", "`slm_verdict_severity`", "Cognitive SLM", "Verdict rank, BENIGN 0 … CRITICAL 3"),
    ("10", "`dga_max_entropy`", "Content heuristics", "Highest Shannon entropy of a link's registrable label"),
    ("11", "`nlp_urgency_score`", "Content heuristics", "Coercive-phrase urgency, 0.25 per phrase, capped at 1"),
]


def chapter_4(r: Report) -> None:
    r.chapter("4", "Implementation Details")
    r.para(
        "Sentinel-Graph is implemented as a Python back end (`app/`, `src/` and `scripts/`) and a TypeScript and "
        "React front end (`frontend/`). Table 4.1 maps each stage of the pipeline to its module; the paragraphs "
        "that follow describe the key algorithms."
    )
    r.table(
        "Modules and their outputs",
        ("Stage", "Module", "Output"),
        [
            ("MIME unpacking", "`src/extractors/mime_parser.py`",
             "Text and HTML bodies and attachments from hostile MIME"),
            ("URL extraction", "`src/extractors/url_extractor.py`",
             "Browser-equivalent URLs (zero-width, bidi and backslash obfuscation removed)"),
            ("Identity", "`src/forensics/auth_analyzer.py`",
             "SPF / DKIM / DMARC / ARC verdicts, sender domains, display-name spoofing"),
            ("Route", "`src/forensics/route_analyzer.py`",
             "Hop count, private-IP leak between public hops, timestamp regression"),
            ("Content heuristics", "`src/forensics/dga_detector.py`, `nlp_heuristics.py`",
             "DGA entropy of link labels; NLP coercion score"),
            ("Sandbox", "`src/vision/sandbox.py`, `egress_proxy.py`", "1024 × 768 screenshot, JavaScript disabled"),
            ("Vision", "`src/vision/brand_detector.py`", "SHA-256, L2-normalised embedding, VisionForensics"),
            ("Topology", "`src/topology/graph_builder.py`, `memae_model.py`",
             "Delivery DAG, MemAE anomaly loss, zero-day flag"),
            ("Reasoning", "`src/cognitive/prompt_engineer.py`, `slm_inference.py`",
             "Injection-hardened prompt, streamed reasoning, verdict"),
            ("Fusion", "`src/fusion/meta_scorer.py`, `xai_engine.py`",
             "Phishing probability and exact per-feature SHAP attribution"),
            ("Streaming", "`src/core/orchestrator.py`, `app/main.py`", "Fan-out pipeline and WebSocket API"),
            ("Persistence", "`src/core/database.py`, `src/models/db_models.py`", "Scan records and pivotable indicators"),
            ("History", "`src/api/routers/history.py`", "Paginated scan log and indicator pivots"),
            ("Dashboard", "`frontend/src/pages/`, `components/`, `lib/`",
             "Live, history, ML-forensics and export pages; globe; exports"),
        ],
        (1.25, 2.55, 2.4),
    )
    r.para(
        "**Tier 1 — protocol forensics.** The MIME parser uses Python's `email` package with `policy.default`, "
        "which records defects on each part instead of raising; Sentinel-Graph harvests those defects, limits "
        "nesting depth and part counts, truncates oversized attachments to 2 MB and falls back through a chain "
        "of character sets when a declared charset is wrong. URLs are normalised by the WHATWG URL rules [26], so "
        "zero-width characters, bidirectional controls and backslashes that a browser silently discards cannot "
        "hide or split a link. The identity analyser trusts only the `Authentication-Results` header written by "
        "the organisation's own boundary (`SOC_TRUSTED_AUTHSERV_IDS`) or, failing that, the topmost one, and "
        "blanks comments and quoted strings before parsing it. Display names are folded — NFKC normalisation, "
        "homoglyph mapping [27], zero-width removal and leetspeak substitution — and matched token by token "
        "against 38 high-risk brand keywords: a brand in the display name sent from a domain the brand does not "
        "own scores 1.0, and a brand only in the subject scores 0.5."
    )
    r.para(
        "**Route forensics and receiver normalisation.** `Received` headers are evaluated oldest first. The "
        "receiving provider adds its own internal hops after accepting a message, and these describe the "
        "recipient's mailbox rather than the sender; left in, they would let a model learn which mailbox a "
        "training email came from. The analyser therefore strips every hop whose receiving host and verified "
        "reverse-DNS name lie in the receiver's own registered domain, keeping the receiver's entry hop, whose "
        "client IP is the last address the sender side presented; HELO names are never trusted. On the remaining "
        "sender-side path it counts hops, flags a private (RFC 1918 [23]) address between public hops, and flags "
        "a timestamp regression when a later hop is stamped more than 60 seconds before an earlier one."
    )
    r.para(
        "**Content heuristics.** `dga_max_entropy` is the highest Shannon entropy, H = Σ p·log_{2}(1/p), of any "
        "link's registrable label — the part left of the public suffix (`login.xkqjfhzyw.co.uk` → `xkqjfhzyw`, "
        "3.17 bits; `google`, 1.92 bits). Subdomains are ignored as free attacker padding and IP-literal hosts "
        "are skipped. `nlp_urgency_score` adds 0.25 for each of eight pressure phrases (such as “immediate "
        "action”, “account suspended” and “verify your identity”), capped at 1.0, matched in their natural "
        "inflections after NFKC folding with invisible characters removed; the inflected forms fire on 20.3% of "
        "2004–06 phishing, 7.2% of 2023–25 phishing and 0.1% of legitimate mail."
    )
    r.para(
        "**Tier 2 — sandboxed vision.** The first URL — the lure in almost every campaign — is opened in a fresh "
        "headless Chromium instance with JavaScript disabled, downloads refused and route interception that "
        "aborts executables, archives and heavy media. Every connection, including redirect hops that "
        "Playwright's routing never sees, is forced through a loopback egress proxy that resolves each host "
        "itself and connects only to the exact public address it vetted, which defeats server-side request "
        "forgery (for example `http://169.254.169.254/`) and DNS rebinding. The 1024 × 768 screenshot is hashed "
        "(SHA-256) and embedded by an ONNX model slot designed for a quantised MobileNetV3. The deployed slot "
        "holds an untrained placeholder with the same input and output contract, and the system flags it as such."
    )
    r.para(
        "**Tier 3 — delivery topology and MemAE.** Each email becomes a directed acyclic graph: sender → relay "
        "hops (oldest first) → receiver, plus sender → each URL, with every edge pointing from a lower to a "
        "higher node index. Node features x ∈ ℝ^{N×5} are a one-hot node type concatenated with the path "
        "position or, for URL nodes, the URL's character entropy. GraphMemAE then works in four steps:"
    )
    r.numbered(
        [
            "**Encoder.** Two GCN layers (5 → 32 → 16) apply H′ = σ(D̂^{−1/2} Â D̂^{−1/2} H W), giving each node "
            "a latent vector z_{i} that reflects its neighbourhood.",
            "**Memory addressing.** A learned memory M ∈ ℝ^{50×16} stores prototypes of normal routing; each latent "
            "addresses it by cosine similarity and a sharpened softmax, w_{i} = softmax(cos(z_{i}, M) / τ) with "
            "τ = 0.1.",
            "**Hard shrinkage.** ŵ = ReLU(w − λ) · w / (|w − λ| + ε) with λ = 0.05, followed by L1 "
            "re-normalisation, so each node is rebuilt from a sparse mix of prototypes — a median of 2 active "
            "memory slots per node (at most 6).",
            "**Decoder and score.** ẑ = ŵM and Â_{pred} = σ(ẑẑ^{T}); the anomaly score is the off-diagonal binary "
            "cross-entropy, computed on logits, against the real undirected adjacency.",
        ]
    )
    r.para(
        "MemAE is trained on legitimate mail only, so it needs no labelled attacks. The zero-day threshold is the "
        "99th percentile of out-of-fold losses on legitimate mail: **1.10**. The loss is computed on logits and "
        "gradients are clipped: an earlier version clamped probabilities before the loss, which has zero gradient "
        "once saturated, and two training folds diverged until this was corrected."
    )
    r.para(
        "**Tier 4 — local language model.** The prompt builder folds every attacker-influenced string (the payload "
        "and telemetry such as the subject) onto one line, truncates the payload to 500 characters and "
        "neutralises anything that could forge the template's section markers, a `VERDICT:` line or chat-role "
        "tokens. The engine targets Phi-3-mini through ONNX Runtime GenAI with greedy decoding, so the same "
        "evidence always yields the same deduction, and streams tokens over the same WebSocket. Verdict "
        "extraction can escalate but never downgrade when outputs conflict. Without Phi-3 model files the engine "
        "runs a scripted stand-in that always answers CRITICAL; it is flagged in every response, and the fusion "
        "model was trained with this feature held constant."
    )
    r.para(
        "**Fusion and explanation.** The twelve features of Table 4.2 form one row per email. A Random Forest "
        "(100 trees, maximum depth 6) outputs the phishing probability, which is scaled to a 0–100 risk score. "
        "`shap.TreeExplainer` computes exact Shapley values: the base value plus the twelve SHAP values equals "
        "the predicted probability (checked in the test suite to 10^{−6}). Contributions are reported per feature "
        "and aggregated per subsystem."
    )
    r.table(
        "The twelve-feature fusion space",
        ("#", "Feature", "Subsystem", "What it measures"),
        FEATURES,
        (0.35, 2.05, 1.4, 2.4),
        center=(0,),
    )
    r.para(
        "**API, streaming and persistence.** FastAPI exposes the WebSocket endpoint "
        "`/ws/api/v1/stream-analysis`, the REST history endpoints under `/api/v1/history` (paginated scans, "
        "newest first, and indicator pivots) and `/api/v1/health`, which reports the model-status flags. Every "
        "telemetry event carries the analysis identifier, which is also the log correlation identifier, and the "
        "elapsed time; the events are RECEIVED, TIER_1, VISION, TOPOLOGY, SLM_REASONING, SLM_VERDICT and "
        "COMPLETE, or an error event. Blocking work runs in the thread pool so the event loop stays responsive, "
        "logs are written as NDJSON for SIEM ingestion, and scans and indicators are saved with asynchronous "
        "SQLAlchemy over aiosqlite."
    )
    r.para(
        "**Dashboard.** The front end uses React 19, TypeScript, Vite 8 and Tailwind CSS 3 in a glassmorphism "
        "theme of translucent stone, rose and plum panels over the globe. A Zustand store receives the "
        "telemetry; React Flow draws the route graph with edges coloured by the sign of their subsystem's SHAP "
        "impact; Three.js, through React Three Fiber, renders a wireframe globe with hop-to-hop arcs and "
        "state-driven camera movement. Hop IP addresses are geolocated at ipapi.co with a 4-second timeout; "
        "private and reserved addresses are never sent, a failed lookup falls back to a stable FNV-1a hash "
        "position drawn as a dashed arc, and `VITE_GEO_LOOKUP=off` disables lookups entirely. The export page "
        "builds the JSON and CSV files in the browser and prefixes any CSV text cell that begins with =, +, −, @ "
        "or a tab with an apostrophe, so attacker-controlled subjects cannot run as spreadsheet formulas."
    )
    r.para(
        "**Training pipeline.** `fetch_modern_corpus.py` downloads and deduplicates the research corpus. "
        "`train_orchestrator.py` streams labelled emails lazily through the same extractors used in production, "
        "cross-fits MemAE so that each email's loss comes from a model that never saw it, evaluates the fusion "
        "model on stratified five-fold out-of-fold predictions, and writes candidates to `models_research/`, so "
        "the deployed models are replaced only by a deliberate promotion. `run_ablation_study.py` retrains the "
        "fusion model without each feature group on the same folds."
    )

    r.section("4.1", "Software/Hardware Specifications")
    r.para(
        "Tables 4.3 and 4.4 list the software and hardware used to build and run the system. Versions are those "
        "pinned in `requirements.txt` and `frontend/package.json` and verified by the test suite."
    )
    r.table(
        "Software specifications",
        ("Component", "Technology", "Version"),
        [
            ("Operating system", "Windows 11 (tested); Linux and macOS supported", "—"),
            ("Back-end language", "Python", "3.12+ (tested 3.14.6)"),
            ("Web framework and server", "FastAPI · Uvicorn", "0.162.0 · 0.40.0"),
            ("Data validation", "Pydantic · pydantic-settings", "2.13.4 · 2.14.2"),
            ("Database", "SQLite through SQLAlchemy (async) · aiosqlite", "2.0.51 · 0.22.1"),
            ("Graph learning", "PyTorch (CPU) · PyTorch Geometric", "2.15.0 · 2.8.1"),
            ("Inference runtime", "ONNX Runtime", "1.31.1"),
            ("Machine learning and XAI", "scikit-learn · SHAP", "1.9.0 · 0.54.1"),
            ("Sandbox", "Playwright with headless Chromium", "1.64.1"),
            ("Parsing", "Beautiful Soup · tldextract", "4.15.0 · 5.4.0"),
            ("Testing and typing", "pytest · pytest-asyncio · mypy", "9.0.3 · 1.4.1 · 1.20.2"),
            ("Front-end runtime", "Node.js", "20.19+ (tested 24.22 LTS)"),
            ("Front end", "React · TypeScript · Vite", "19.3 · 6.0 · 8.3"),
            ("Styling and state", "Tailwind CSS · Zustand", "3.4 · 5.0"),
            ("Visualisation", "Three.js · React Three Fiber · React Flow", "0.186 · 9.8 · 11.11"),
            ("Optional", "ONNX Runtime GenAI with Phi-3-mini (int4, about 2.5 GB)", "—"),
        ],
        (1.75, 2.85, 1.6),
    )
    r.table(
        "Hardware specifications",
        ("Resource", "Requirement", "Notes"),
        [
            ("Processor", "4 cores, x86-64", "Developed and tested on a Windows 11 laptop, CPU only"),
            ("Memory", "8 GB RAM", "A real Phi-3-mini needs about 4 GB of RAM or VRAM more"),
            ("Storage", "About 3 GB free", "PyTorch, Chromium and the models"),
            ("GPU", "Not required", "An NVIDIA RTX 3050-class GPU (4–8 GB) only speeds up a real language model"),
            ("Display", "A WebGL-capable browser", "The route globe is rendered with WebGL"),
            ("Network", "Not required for analysis", "Only for optional Geo-IP lookups and the corpus download"),
        ],
        (1.2, 1.85, 3.15),
    )


def chapter_5(r: Report) -> None:
    r.chapter("5", "Snapshots")
    r.para(
        "The screenshots below were captured from the running system (back end on port 8000, dashboard on port "
        "5173) after analysing the three demonstration emails in the `samples/` folder. These emails are "
        "synthetic and use the reserved `.invalid` domain, so the sandbox never contacts a real site. The "
        "language-model panel shows the scripted stand-in, which always answers CRITICAL; the risk score comes "
        "from the trained fusion model."
    )
    shots = [
        ("live_lure.png", "Live scan of the Apple ID lure (risk 61/100)",
         "Figure 5.1 shows the live view after scanning the Apple ID lure. The telemetry panel lists every "
         "pipeline event with its elapsed time; the route graph shows the sender, three relay hops, the receiver "
         "and the URL node; the globe draws the hop-to-hop arcs. The risk gauge shows 61/100 and warns that the "
         "vision and language models are stand-ins and that one of three hop locations is estimated. The "
         "content-heuristics panel shows no coercive phrase and a link-label entropy of 3.32 bits."),
        ("live_coercive.png", "Live scan of the coercive multi-hop email (risk 90/100)",
         "In Figure 5.2, the coercive multi-hop email's three public relay hops are drawn as arcs on the globe, "
         "four or more coercive phrases fill the NLP meter, and the random-looking link label `xkqjfhzyw` scores "
         "3.17 bits, outside the band in which most legitimate labels sit."),
        ("live_benign.png", "Live scan of the benign meeting-minutes email (risk 39/100)",
         "For the benign meeting-minutes email (Figure 5.3), authentication passes, the route has a single hop and "
         "the email contains no link, so no detonation takes place; the score stays below 50."),
        ("ml_forensics.png", "ML forensics page: SHAP attribution for the lure",
         "The ML-forensics page (Figure 5.4) lists each of the twelve features with its value and SHAP impact. "
         "For the lure, display-name spoofing adds +0.310, graph size +0.089, the clock regression +0.064 and "
         "the MemAE loss +0.044, while the private hop lowers the score by 0.243 (the mailing-list confound "
         "discussed in Chapter 6). The side panels explain the NLP, DGA and MemAE features."),
        ("history.png", "Threat-intelligence history",
         "The history page (Figure 5.5) stores every scan with its verdict, risk score and indicators; selecting "
         "an indicator lists every scan that contained it."),
        ("export.png", "Reports and export page",
         "The export page (Figure 5.6) downloads the current assessment as a full JSON report or a one-row CSV of "
         "the twelve features, and the whole history as CSV. The files are built in the browser, and text cells "
         "that could run as spreadsheet formulas are neutralised."),
    ]
    for name, caption, text in shots:
        r.para(text).paragraph_format.keep_with_next = True
        r.figure(SNAPSHOTS / name, caption, width=6.25)


def chapter_6(r: Report) -> None:
    r.chapter("6", "Implementation and Testing")
    r.para(
        "Testing covered both the software — does each component behave correctly, including on hostile "
        "input? — and the models — how well do they detect phishing, and what does each feature contribute?"
    )

    r.section("6.1", "Testing Approach")
    r.para("A layered strategy was used:")
    r.bullets(
        [
            "**Unit, property and adversarial tests** for every tier, written with pytest, including hostile inputs "
            "such as malformed MIME, forged headers, zero-width obfuscation and prompt-injection attempts.",
            "**Real-browser sandbox tests** that launch Chromium through Playwright against local test servers to "
            "prove that JavaScript, downloads, private-address egress and redirects into private space are "
            "blocked.",
            "**Integration tests** that drive the pipeline through the WebSocket API with FastAPI's test client, "
            "including persistence and the history API.",
            "**End-to-end tests** (`tests/e2e/`) that load the real engines and the deployed models and follow an "
            "email from ingestion to the history API.",
            "**Static checks** — mypy in strict mode over `src`, `tests`, `scripts` and `app`, and a TypeScript "
            "build of the front end (`tsc -b && vite build`).",
            "**Statistical validation of the models** — stratified five-fold out-of-fold evaluation, cross-fitted "
            "MemAE losses, an out-of-time test on unseen 2023–25 phishing, and a drop-column ablation study.",
        ]
    )
    r.para(
        "The suite of 372 tests runs with `python -m pytest`. In the final run, **371 tests passed and 1 was "
        "skipped** — the optional live-internet detonation, enabled with `SOC_LIVE_NETWORK_TESTS=1` — in 73 "
        "seconds on the development laptop."
    )

    r.section("6.2", "Unit Testing")
    r.para(
        "Unit tests exercise each module in isolation, with real inputs where possible. Table 6.1 lists the "
        "module-level suites; Table 6.2 shows representative test cases from them."
    )
    r.table(
        "Module-level test suites",
        ("Suite", "Tests", "What it verifies"),
        [
            ("test_mime_parser", "15", "Hostile MIME, charset fallbacks, attachment limits"),
            ("test_url_extractor", "23", "WHATWG normalisation, zero-width stripping, de-duplication"),
            ("test_auth_analyzer", "46", "Authentication-Results parsing, trusted authserv-id, display-name spoofing"),
            ("test_route_analyzer", "20", "Hop count, private-IP leak, timestamp regression, clock skew"),
            ("test_receiver_normalisation", "17", "Stripping receiver-side hops; spoofed HELO names"),
            ("test_forensics", "5", "Tier 1 end to end: IP order, forged DKIM, malformed MIME"),
            ("test_advanced_forensics", "34", "Shannon entropy, registrable labels, DGA and NLP coercion scores"),
            ("test_graph_builder", "13", "DAG construction, node features, URL entropy"),
            ("test_memae", "11", "Sparse memory addressing, hard shrinkage, gradients, placeholder checkpoint"),
            ("test_meta_scorer", "28", "Fusion scoring, feature contract, neutralised missing values"),
            ("test_brand_detector", "14", "ONNX vision placeholder, unit-length deterministic embeddings"),
            ("test_onnx_engines", "7", "Vision and language-model engines through ONNX Runtime"),
            ("test_prompt_engineer", "11", "Prompt template, truncation, injection neutralisation"),
            ("test_cognitive_slm", "20", "Streaming stand-in, escalate-only verdict extraction"),
            ("test_sandbox", "18", "Real Chromium: JavaScript off, blocked downloads, egress proxy"),
            ("test_schemas", "7", "Strict, frozen data contracts"),
            ("test_train_orchestrator", "12", "Lazy ingestion, labels, concurrent extraction"),
            ("test_ablation_study", "18", "Feature groups, shared folds, out-of-time scoring"),
            ("test_fetch_modern_corpus", "11", "Corpus builder, de-duplication, attribution"),
            ("**Total**", "**330**", ""),
        ],
        (2.1, 0.65, 3.45),
        center=(1,),
    )
    r.table(
        "Representative unit test cases",
        ("ID", "Test", "Input or condition", "Expected result", "Result"),
        [
            ("TC-01", "test_misdeclared_charset_falls_back_to_windows_1252", "Body declared UTF-8 but encoded "
             "Windows-1252", "Body decodes correctly; defect recorded", "Pass"),
            ("TC-02", "test_zero_width_obfuscation_is_stripped_and_logged", "Link split by zero-width characters",
             "URL recovered as a browser reads it", "Pass"),
            ("TC-03", "test_attacker_text_in_comments_and_values_is_ignored", "Forged “pass” text inside header "
             "comments", "Comments ignored; real results used", "Pass"),
            ("TC-04", "test_four_hops_with_injected_private_ip_and_time_travel", "Private hop between public hops "
             "and a backwards clock", "Private-IP leak and timestamp regression flagged", "Pass"),
            ("TC-05", "test_clock_skew_tolerance_is_sixty_seconds", "Later hop stamped slightly earlier",
             "Regression flagged only beyond 60 s of skew", "Pass"),
            ("TC-06", "test_dga_scores_only_the_registrable_label", "Random subdomain on a common domain",
             "Only the registrable label is scored", "Pass"),
            ("TC-07", "test_forward_shapes_and_sparse_memory_addressing", "Graph through GraphMemAE",
             "Correct shapes; sparse memory weights", "Pass"),
            ("TC-08", "test_highly_suspicious_email_scores_above_half", "Spoofed, failing, anomalous feature row",
             "Phishing probability above 0.5", "Pass"),
            ("TC-09", "test_payload_cannot_forge_template_lines_verdicts_or_chat_tokens", "Email text with a forged "
             "VERDICT line and chat tokens", "Markers neutralised in the prompt", "Pass"),
            ("TC-10", "test_missing_verdict_falls_back_to_suspicious", "Reasoning without a verdict line",
             "Verdict SUSPICIOUS", "Pass"),
            ("TC-11", "test_redirect_into_private_space_is_blocked", "Public URL redirecting to a private address",
             "Blocked by the egress proxy", "Pass"),
            ("TC-12", "test_contracts_are_frozen", "Attempt to modify an assessment", "Rejected", "Pass"),
        ],
        (0.55, 1.85, 1.55, 1.65, 0.6),
        center=(0, 4),
    )

    r.section("6.3", "Integration Testing")
    r.para("Integration tests exercise components together through their real interfaces (Table 6.3).")
    r.table(
        "Integration and end-to-end test suites",
        ("Suite", "Tests", "Scope"),
        [
            ("test_orchestrator", "11", "Event order and one analysis id, concurrent branches, skipped or failed "
             "detonation, prompt contents, a valid COMPLETE payload"),
            ("test_ws_manager", "7", "WebSocket protocol: binary frames only, size limit, error events, Origin "
             "refusal, health endpoint"),
            ("test_database", "8", "Insert and query, cascade delete, foreign keys, risk range, UTC timestamps"),
            ("test_history_api", "11", "Newest-first listing, paging and filters, IP and URL pivots"),
            ("e2e/test_full_system", "3", "Real engines: phishing detonation over the WebSocket, benign below "
             "phishing, logs in the configured directory"),
            ("e2e/test_capstone_defense", "2", "Deployed models: WebSocket to database; history API persistence"),
            ("**Total**", "**42**", ""),
        ],
        (2.0, 0.65, 3.55),
        center=(1,),
    )
    r.para(
        "**Model validation.** The fusion model was evaluated on the era-matched research corpus: 4,211 "
        "legitimate emails (SpamAssassin, 2002–03) and 2,361 phishing emails (Nazario, 2004–06), all with intact "
        "`Received` chains. Every prediction was made out of fold by a model that never saw the email, and each "
        "email's MemAE loss came from a MemAE trained on the other folds' legitimate mail. The language-model "
        "verdict was held constant during training: mapping legitimate mail to BENIGN and phishing to CRITICAL "
        "would have handed the model the label and produced a meaningless AUC of 1.0. Table 6.4 and Figure 6.1 "
        "give the results."
    )
    r.table(
        "Out-of-fold results on the research corpus (5-fold stratified)",
        ("Metric", "12 features (deployed)", "10 features (previous)"),
        [
            ("ROC-AUC", "**0.953**", "0.926"),
            ("Phishing precision / recall / F1 at 0.5", "0.779 / 0.898 / **0.834**", "0.772 / 0.875 / 0.820"),
            ("Legitimate precision / recall", "0.937 / 0.857", "0.924 / 0.855"),
            ("Accuracy", "0.872", "0.862"),
            ("Unseen 2023–25 phishing detected at 0.5 (n = 1,000)", "**61.4%**", "48.8%"),
            ("MemAE zero-day threshold (99th percentile of out-of-fold benign loss)", "1.10", "1.10"),
        ],
        (3.0, 1.6, 1.6),
        center=(1, 2),
    )
    r.figure(MODELS / "roc_auc_curve.png", "Out-of-fold ROC curve of the fusion model (AUC = 0.953)", width=4.6)
    r.para(
        "**Out-of-time test.** On 1,000 phishing emails from 2023–25 that no model was trained on, the deployed "
        "model detects 61.4% at a threshold of 0.5 (median phishing probability 0.55), against 48.8% for the "
        "ten-feature model and 41.1% for the 2002 baseline. Recall falls from 89.8% in distribution to 61.4% two "
        "decades later, so the cross-validated AUC describes 2004–06 phishing rather than today's. No modern "
        "legitimate mail was available, so the out-of-time false-positive rate is unmeasured."
    )
    r.para("**Ablation study.** Table 6.5 retrains the fusion model without each feature group on the same five folds.")
    r.table(
        "Drop-column ablation study",
        ("Configuration", "OOF ROC-AUC", "F1 at 0.5", "AUC loss", "2023–25 caught"),
        [
            ("Baseline (all 12 features)", "0.953", "0.834", "—", "61.4%"),
            ("No content heuristics (DGA + NLP)", "0.926", "0.820", "2.86%", "48.8%"),
            ("No DGA entropy", "0.935", "0.819", "1.99%", "50.5%"),
            ("No NLP coercion", "0.950", "0.833", "0.41%", "57.2%"),
            ("No GNN routing (MemAE loss)", "0.953", "0.839", "0.00%", "71.6%"),
            ("No topology (MemAE loss + graph size)", "0.936", "0.774", "1.87%", "37.6%"),
            ("No protocol forensics (4 features)", "0.934", "0.791", "2.08%", "47.2%"),
        ],
        (2.55, 0.95, 0.8, 0.85, 1.05),
        center=(1, 2, 3, 4),
    )
    r.para(
        "Removing the MemAE loss leaves the AUC unchanged at 0.953 and raises 2023–25 recall to 71.6%: the "
        "topology signal the forest uses is the graph's size, because route nodes carry only their type and "
        "position. Removing size and loss together costs 1.87% of AUC and drops 2023–25 recall to 37.6%. DGA "
        "entropy is the stronger content feature (1.99% of AUC lost without it, against 0.41% for NLP coercion), "
        "and protocol forensics carry the most in-distribution signal (2.08%). The MemAE loss was nevertheless "
        "kept in the deployed model: the in-distribution AUC is tied, and the 71.6% comes from a phishing-only "
        "set whose false-positive cost is unmeasured."
    )
    r.figure(MODELS / "training_loss.png", "MemAE training and validation loss per fold", width=4.8)
    r.para(
        "All five MemAE folds converge: training loss falls from about 0.25 to 0.11–0.14 and held-out validation "
        "loss settles between 0.09 and 0.16 (Figure 6.2)."
    )
    r.para(
        "**Demonstration emails.** Table 6.6 lists the three demonstration emails scored end to end by the "
        "deployed system; the same scores appear in the snapshots of Chapter 5."
    )
    r.table(
        "Demonstration emails scored by the deployed system",
        ("Email", "What it contains", "Risk"),
        [
            ("01_phishing_apple_lure.eml", "Apple display-name spoof, SPF and DMARC failures, a private hop between "
             "public relays, a backwards clock", "61/100"),
            ("02_benign_meeting_minutes.eml", "Authentication passes, one hop, no link", "39/100"),
            ("03_coercive_multi_hop.eml", "Three public relays, four coercive phrases, a random-looking link label "
             "(3.17 bits)", "90/100"),
        ],
        (2.3, 3.1, 0.8),
        center=(2,),
    )
    r.para(
        "For the lure, SHAP attributes +0.310 to display-name spoofing, +0.089 to graph size, +0.064 to the clock "
        "regression and +0.044 to the MemAE loss, while the private hop lowers the score by 0.243. That last "
        "value exposes a dataset confound: two-thirds of the SpamAssassin legitimate mail is mailing-list traffic "
        "relayed through private corporate addresses, so `private_ip_leak` fires on 66.8% of legitimate mail but "
        "only 3.0% of phishing, and the forest learned that a private hop indicates legitimate mail. Monotonic "
        "constraints, listed under future scope, would forbid this inversion."
    )


def chapter_7(r: Report) -> None:
    r.chapter("7", "Conclusion")
    r.para(
        "Sentinel-Graph shows that phishing triage can be made both fast and explainable on an ordinary laptop. "
        "The system analyses a raw email through four evidence tiers — protocol forensics, sandboxed vision, "
        "delivery topology and local language-model reasoning — and fuses twelve features into one risk score "
        "whose every contribution is shown to the analyst with exact SHAP values. A complete assessment takes "
        "about four seconds, and every step streams live to a dashboard with a 3D route globe, scan history with "
        "indicator pivots, and report export."
    )
    r.para(
        "The trained fusion model reaches an out-of-fold ROC-AUC of **0.953** (phishing F1 0.834) on the "
        "era-matched research corpus and detects **61.4%** of unseen 2023–25 phishing, up from 48.8% before the "
        "DGA-entropy and NLP-coercion features were added. The system is hardened against the hostile input it "
        "processes — malformed MIME, forged headers, prompt injection and request forgery through the sandbox — "
        "and is verified by 372 automated tests."
    )
    r.para(
        "The project also reports its limitations honestly. The vision and language-model engines run as clearly "
        "flagged stand-ins; five of the twelve features were constant during training; the ablation study shows "
        "that the MemAE loss adds nothing beyond graph size with today's position-only node features; and "
        "`private_ip_leak` is learned inverted because of a mailing-list confound in the legitimate corpus. These "
        "findings were measured rather than assumed, and they define the most valuable next steps."
    )


def chapter_8(r: Report) -> None:
    r.chapter("8", "Future Scope")
    r.para("The following extensions would remove the current limitations and broaden the system's reach:")
    r.bullets(
        [
            "**Modern training data.** Retrain on a labelled 2020s corpus that carries `Authentication-Results` "
            "headers, and run vision and the language model during training so that their features carry signal.",
            "**Benign mail for the modern corpus.** The 2023–25 phishing half is in place; a consented, exported "
            "legitimate mailbox would complete it and make the out-of-time false-positive rate measurable.",
            "**Monotonic fusion.** Constrain the spoofing, private-IP-leak and timestamp-regression features to "
            "only raise risk (for example `HistGradientBoostingClassifier` with monotonic constraints), so "
            "out-of-distribution mail cannot invert them as `private_ip_leak` is inverted today.",
            "**Richer graph nodes.** Give each hop node its own attributes — private or bogon flag, change of "
            "autonomous system from the previous hop, clock delta, reverse-DNS agreement — so the MemAE can see a "
            "forged hop rather than only the route's shape and earn its place in the fusion score.",
            "**A stronger DGA signal.** Raw label entropy is length-confounded; a character n-gram model of "
            "legitimate domain names is the standard upgrade.",
            "**Real vision and language models.** Train a MobileNetV3 brand classifier with brand centroids for "
            "`visual_spoof_score`, add credential-form detection, and install Phi-3-mini for real local "
            "reasoning.",
            "**Throughput.** A pre-warmed browser pool, a URL-result cache and a job queue in front of the "
            "sandbox for high report volumes.",
            "**Integration and contracts.** Generate the TypeScript types from the Pydantic schema, add continuous "
            "integration, and connect the system to mail-gateway quarantines and SIEM platforms.",
        ]
    )


REFERENCES: Final = [
    "Anti-Phishing Working Group (APWG), “Phishing Activity Trends Reports,” published quarterly. [Online]. "
    "Available: https://apwg.org/trendsreports/",
    "Government of India, “The Digital Personal Data Protection Act, 2023,” Act No. 22 of 2023.",
    "I. Fette, N. Sadeh and A. Tomasic, “Learning to detect phishing emails,” in Proc. 16th Int. Conf. World "
    "Wide Web (WWW), 2007, pp. 649–656.",
    "S. Abu-Nimeh, D. Nappa, X. Wang and S. Nair, “A comparison of machine learning techniques for phishing "
    "detection,” in Proc. Anti-Phishing Working Group eCrime Researchers Summit, 2007, pp. 60–69.",
    "S. Kitterman, “Sender Policy Framework (SPF) for Authorizing Use of Domains in Email, Version 1,” "
    "RFC 7208, IETF, 2014.",
    "D. Crocker, T. Hansen and M. Kucherawy, “DomainKeys Identified Mail (DKIM) Signatures,” RFC 6376, IETF, 2011.",
    "M. Kucherawy and E. Zwicky, “Domain-based Message Authentication, Reporting, and Conformance (DMARC),” "
    "RFC 7489, IETF, 2015.",
    "K. Andersen, B. Long, S. Blank and M. Kucherawy, “The Authenticated Received Chain (ARC) Protocol,” "
    "RFC 8617, IETF, 2019.",
    "M. Kucherawy, “Message Header Field for Indicating Message Authentication Status,” RFC 8601, IETF, 2019.",
    "T. N. Kipf and M. Welling, “Semi-Supervised Classification with Graph Convolutional Networks,” in Proc. "
    "Int. Conf. Learning Representations (ICLR), 2017.",
    "M. Fey and J. E. Lenssen, “Fast Graph Representation Learning with PyTorch Geometric,” in ICLR Workshop on "
    "Representation Learning on Graphs and Manifolds, 2019.",
    "D. Gong, L. Liu, V. Le, B. Saha, M. R. Mansour, S. Venkatesh and A. van den Hengel, “Memorizing Normality "
    "to Detect Anomaly: Memory-augmented Deep Autoencoder for Unsupervised Anomaly Detection,” in Proc. IEEE/CVF "
    "Int. Conf. Computer Vision (ICCV), 2019, pp. 1705–1714.",
    "M. Antonakakis, R. Perdisci, Y. Nadji, N. Vasiloglou, S. Abu-Nimeh, W. Lee and D. Dagon, “From Throw-Away "
    "Traffic to Bots: Detecting the Rise of DGA-Based Malware,” in Proc. 21st USENIX Security Symposium, 2012.",
    "J. Woodbridge, H. S. Anderson, A. Ahuja and D. Grant, “Predicting Domain Generation Algorithms with Long "
    "Short-Term Memory Networks,” arXiv:1611.00791, 2016.",
    "C. E. Shannon, “A Mathematical Theory of Communication,” Bell System Technical Journal, vol. 27, no. 3, "
    "pp. 379–423, 1948.",
    "S. M. Lundberg and S.-I. Lee, “A Unified Approach to Interpreting Model Predictions,” in Advances in Neural "
    "Information Processing Systems (NeurIPS), vol. 30, 2017.",
    "S. M. Lundberg, G. Erion, H. Chen, A. DeGrave, J. M. Prutkin, B. Nair, R. Katz, J. Himmelfarb, N. Bansal "
    "and S.-I. Lee, “From local explanations to global understanding with explainable AI for trees,” Nature "
    "Machine Intelligence, vol. 2, pp. 56–67, 2020.",
    "L. Breiman, “Random Forests,” Machine Learning, vol. 45, no. 1, pp. 5–32, 2001.",
    "M. Abdin et al., “Phi-3 Technical Report: A Highly Capable Language Model Locally on Your Phone,” "
    "arXiv:2404.14219, 2024.",
    "A. Howard et al., “Searching for MobileNetV3,” in Proc. IEEE/CVF Int. Conf. Computer Vision (ICCV), 2019, "
    "pp. 1314–1324.",
    "The Apache SpamAssassin Project, “SpamAssassin Public Corpus” (2002–03 releases). [Online]. Available: "
    "https://spamassassin.apache.org/old/publiccorpus/",
    "J. Nazario, “Phishing Corpus,” CC-BY-4.0. [Online]. Available: https://monkey.org/~jose/phishing/",
    "Y. Rekhter, B. Moskowitz, D. Karrenberg, G. J. de Groot and E. Lear, “Address Allocation for Private "
    "Internets,” RFC 1918, IETF, 1996.",
    "P. Resnick, Ed., “Internet Message Format,” RFC 5322, IETF, 2008.",
    "I. Jacobson, M. Christerson, P. Jonsson and G. Övergaard, Object-Oriented Software Engineering: A Use Case "
    "Driven Approach. Addison-Wesley, 1992.",
    "WHATWG, “URL Living Standard.” [Online]. Available: https://url.spec.whatwg.org/",
    "The Unicode Consortium, “Unicode Technical Standard #39: Unicode Security Mechanisms.” [Online]. Available: "
    "https://www.unicode.org/reports/tr39/",
]


def chapter_9(r: Report) -> None:
    r.chapter("9", "References")
    r.references(REFERENCES)


# --------------------------------------------------------------------------- Word finishing


def finish_with_word(docx_path: Path, pdf_path: Path) -> bool:
    """Let Word paginate, fill the index page numbers, save, and export a PDF. False if unavailable."""
    try:
        import pythoncom
        import win32com.client
    except ImportError:
        return False
    pythoncom.CoInitialize()
    word = None
    try:
        word = win32com.client.DispatchEx("Word.Application")  # a private instance, never the user's
        word.Visible = False
        word.DisplayAlerts = 0
        document = word.Documents.Open(str(docx_path), False, False, False)
        try:
            document.Repaginate()
            document.Fields.Update()
            document.Save()
            document.ExportAsFixedFormat(str(pdf_path), 17)  # wdExportFormatPDF
        finally:
            document.Close(0)
        return True
    except Exception as exc:  # COM errors carry no common base class worth naming
        print(f"Word automation failed ({exc}); the page numbers update when the file is opened in Word")
        return False
    finally:
        if word is not None:
            word.Quit()
        pythoncom.CoUninitialize()


# --------------------------------------------------------------------------- entry point


def parse_member(value: str) -> Member:
    name, _, seat = value.partition("|")
    if not name.strip():
        raise argparse.ArgumentTypeError("--member needs a name, optionally followed by |seat-number")
    return Member(name.strip(), seat.strip())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--template-pdf", type=Path, help="the institute's report-format PDF (letterhead source)")
    source.add_argument("--letterhead", type=Path, help="letterhead image to use instead")
    parser.add_argument(
        "--member",
        type=parse_member,
        action="append",
        help='team member as "Name" or "Name|SeatNo" (repeat per member; default: Uday Babasaheb Baviskar)',
    )
    parser.add_argument("--guide", default="", help="project guide's name (default: a dotted blank)")
    parser.add_argument("--out", type=Path, default=OUT_DIR / f"{OUT_NAME}.docx", help="output .docx path")
    parser.add_argument("--no-word", action="store_true", help="skip Word (page numbers update on opening)")
    args = parser.parse_args(argv)

    members = args.member or [Member("Uday Babasaheb Baviskar")]
    if args.template_pdf:
        letterhead: Path | None = extract_letterhead(args.template_pdf)
    elif args.letterhead:
        letterhead = args.letterhead
    else:
        letterhead = cached_letterhead()
    if letterhead is None:
        print("No letterhead: pass --template-pdf once to extract it from the format PDF")

    with tempfile.TemporaryDirectory(prefix="report-figures-") as scratch:
        figures = render_diagrams(Path(scratch))
        report = Report(letterhead, figures)
        report.cover(members, args.guide)
        for member in members:
            report.certificate(member)
        report.acknowledgement(members, args.guide)
        report.index_page()
        report.start_body()
        for write in (chapter_1, chapter_2, chapter_3, chapter_4, chapter_5, chapter_6, chapter_7, chapter_8, chapter_9):
            write(report)
        report.check_complete()
        out: Path = args.out.resolve()
        updated_by_word = False
        if args.no_word:
            report.ask_word_to_update_fields()
        report.save(out, members=members)
        if not args.no_word:
            updated_by_word = finish_with_word(out, out.with_suffix(".pdf"))
            if not updated_by_word:
                report.ask_word_to_update_fields()
                report.save(out, members=members)

    print(f"Wrote {out}")
    if updated_by_word:
        print(f"Wrote {out.with_suffix('.pdf')} (index page numbers filled in by Word)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
