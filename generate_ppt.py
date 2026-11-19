"""Generate the ProvenanceX project review deck (python-pptx).

Every figure on these slides is copied from files in this repository:
docs/HANDOFF.md (verified runs), ml/reports/evaluation_report.md (synthetic evaluation),
backend/requirements*.txt, frontend/package.json and contracts/package.json (versions).

Run: python3 generate_ppt.py  ->  Project_Review_Presentation.pptx
"""

from pathlib import Path

from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_CONNECTOR, MSO_SHAPE
from pptx.enum.text import MSO_ANCHOR, PP_ALIGN
from pptx.oxml.ns import qn
from pptx.util import Inches, Pt
from lxml import etree

OUT = Path(__file__).resolve().parent / "Project_Review_Presentation.pptx"

# ---------------------------------------------------------------- design tokens
NAVY = RGBColor(0x0F, 0x17, 0x2A)
NAVY_CARD = RGBColor(0x1E, 0x29, 0x3B)
NAVY_LINE = RGBColor(0x33, 0x41, 0x55)
OFFWHITE = RGBColor(0xF8, 0xFA, 0xFC)
WHITE = RGBColor(0xFF, 0xFF, 0xFF)
BORDER = RGBColor(0xE2, 0xE8, 0xF0)
TEXT = RGBColor(0x1E, 0x29, 0x3B)
MUTED = RGBColor(0x64, 0x74, 0x8B)
ACCENT = RGBColor(0x25, 0x63, 0xEB)
ACCENT_SOFT = RGBColor(0xEF, 0xF4, 0xFF)
ON_DARK_MUTED = RGBColor(0x94, 0xA3, 0xB8)
ON_DARK_ACCENT = RGBColor(0x93, 0xB4, 0xFD)
# Muted decision tones, always paired with the decision word
OK = RGBColor(0x15, 0x80, 0x3D)
WARN = RGBColor(0xB4, 0x53, 0x09)
BAD = RGBColor(0xB9, 0x1C, 0x1C)

FONT = "Calibri"
SLIDE_W, SLIDE_H = 13.333, 7.5
MARGIN = 0.6
PAD = 0.3
PROJECT = "ProvenanceX"

TEAM = [("Sanjay.C", "1BM24IC048"), ("Manu K N", "1BM25IC405"), ("Prathik", "1BM24IC037")]
DEPT = "Department of CSE (IoT & Cybersecurity including Blockchain Technology)"


# ---------------------------------------------------------------- primitives
def _no_shadow(shape):
    shape.shadow.inherit = False


def box(slide, x, y, w, h, fill=WHITE, line=BORDER, radius=0.06, shape=MSO_SHAPE.ROUNDED_RECTANGLE):
    """Rounded card with hairline border and no theme shadow."""
    s = slide.shapes.add_shape(shape, Inches(x), Inches(y), Inches(w), Inches(h))
    if shape == MSO_SHAPE.ROUNDED_RECTANGLE:
        s.adjustments[0] = radius
    s.fill.solid()
    s.fill.fore_color.rgb = fill
    if line is None:
        s.line.fill.background()
    else:
        s.line.color.rgb = line
        s.line.width = Pt(0.75)
    _no_shadow(s)
    s.text_frame.text = ""
    return s


def _set_bullet(paragraph, color):
    pPr = paragraph._p.get_or_add_pPr()
    pPr.set("marL", str(Inches(0.2)))
    pPr.set("indent", str(-Inches(0.2)))
    for tag in ("a:buNone", "a:buChar", "a:buAutoNum", "a:buClr"):
        for el in pPr.findall(qn(tag)):
            pPr.remove(el)
    buClr = etree.SubElement(pPr, qn("a:buClr"))
    clr = etree.SubElement(buClr, qn("a:srgbClr"))
    clr.set("val", str(color))
    buFont = etree.SubElement(pPr, qn("a:buFont"))
    buFont.set("typeface", "Arial")
    bu = etree.SubElement(pPr, qn("a:buChar"))
    bu.set("char", "▪")


def fill_text(tf, paras, *, margin=PAD, anchor=MSO_ANCHOR.TOP, margins=None):
    """Write paragraphs into a text frame.

    paras: list of dicts {runs: [(text, opts)], align, space_after, space_before, bullet, bullet_color}
    opts: size, bold, color, italic, spacing (char spacing in points)
    """
    tf.word_wrap = True
    tf.vertical_anchor = anchor
    l, t, r, b = margins if margins else (margin, margin, margin, margin)
    tf.margin_left, tf.margin_top, tf.margin_right, tf.margin_bottom = (
        Inches(l), Inches(t), Inches(r), Inches(b),
    )
    for i, p in enumerate(paras):
        para = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        para.alignment = p.get("align", PP_ALIGN.LEFT)
        para.space_after = Pt(p.get("space_after", 0))
        para.space_before = Pt(p.get("space_before", 0))
        if p.get("line_spacing"):
            para.line_spacing = p["line_spacing"]
        if p.get("bullet"):
            _set_bullet(para, p.get("bullet_color", ACCENT))
        for text, o in p["runs"]:
            run = para.add_run()
            run.text = text
            f = run.font
            f.name = FONT
            f.size = Pt(o.get("size", 14))
            f.bold = o.get("bold", False)
            f.italic = o.get("italic", False)
            f.color.rgb = o.get("color", TEXT)
            if o.get("spacing"):
                run._r.get_or_add_rPr().set("spc", str(int(o["spacing"] * 100)))
    return tf


def text(slide, x, y, w, h, paras, **kw):
    tb = slide.shapes.add_textbox(Inches(x), Inches(y), Inches(w), Inches(h))
    kw.setdefault("margin", 0)
    fill_text(tb.text_frame, paras, **kw)
    return tb


def P(*runs, **kw):
    """Paragraph shorthand: P(("text", {opts}), ..., space_after=4)."""
    return {"runs": list(runs), **kw}


def R(t, size=14, bold=False, color=TEXT, **kw):
    return (t, {"size": size, "bold": bold, "color": color, **kw})


def arrow(slide, x1, y1, x2, y2, color=ACCENT, width=1.5):
    c = slide.shapes.add_connector(MSO_CONNECTOR.STRAIGHT, Inches(x1), Inches(y1), Inches(x2), Inches(y2))
    c.line.color.rgb = color
    c.line.width = Pt(width)
    ln = c.line._get_or_add_ln()
    tail = etree.SubElement(ln, qn("a:tailEnd"))
    tail.set("type", "triangle")
    tail.set("w", "med")
    tail.set("h", "med")
    return c


def background(slide, color):
    bg = slide.background.fill
    bg.solid()
    bg.fore_color.rgb = color


def header(slide, tracker, title):
    """10pt uppercase tracker above a 26pt title, top-left."""
    text(slide, MARGIN, 0.24, 9.5, 0.24, [P(R(tracker.upper(), 10, True, ACCENT, spacing=1.5))])
    text(slide, MARGIN, 0.5, 12.1, 0.55, [P(R(title, 26, True, TEXT))])


def footer(slide, number):
    text(slide, MARGIN, 7.0, 6, 0.25, [P(R(f"{PROJECT}  |  Project Review", 10, False, MUTED))])
    text(
        slide, SLIDE_W - MARGIN - 1.0, 7.0, 1.0, 0.25,
        [P(R(f"{number:02d}", 10, True, MUTED), align=PP_ALIGN.RIGHT)],
    )


def content_slide(prs, number, tracker, title):
    s = prs.slides.add_slide(prs.slide_layouts[6])
    background(s, OFFWHITE)
    header(s, tracker, title)
    footer(s, number)
    return s


def tag(slide, x, y, label, fill=ACCENT_SOFT, color=ACCENT, w=None, size=10):
    w = w or (0.12 * len(label) + 0.35)
    t = box(slide, x, y, w, 0.28, fill=fill, line=None, radius=0.5)
    fill_text(
        t.text_frame, [P(R(label, size, True, color, spacing=0.5), align=PP_ALIGN.CENTER)],
        margin=0, anchor=MSO_ANCHOR.MIDDLE,
    )
    return t


def card(slide, x, y, w, h, title, paras, *, kicker=None, title_size=15):
    c = box(slide, x, y, w, h)
    head = []
    if kicker:
        head.append(P(R(kicker.upper(), 10, True, ACCENT, spacing=1.0), space_after=3))
    head.append(P(R(title, title_size, True, TEXT), space_after=6))
    fill_text(c.text_frame, head + paras)
    return c


def table(slide, x, y, w, col_w, rows, *, row_h=0.36, size=12, header_fill=NAVY, first_col_bold=True,
          cell_colors=None):
    """Clean table: navy header, white body, hairline row borders, no theme banding."""
    n_rows, n_cols = len(rows), len(rows[0])
    gt = slide.shapes.add_table(n_rows, n_cols, Inches(x), Inches(y), Inches(w), Inches(row_h * n_rows))
    tbl = gt.table
    # disable built-in banding/style
    tblPr = tbl._tbl.tblPr
    tblPr.set("firstRow", "0")
    tblPr.set("bandRow", "0")
    for i, cw in enumerate(col_w):
        tbl.columns[i].width = Inches(cw)
    for r in range(n_rows):
        tbl.rows[r].height = Inches(row_h)
        for c in range(n_cols):
            cell = tbl.cell(r, c)
            cell.fill.solid()
            cell.fill.fore_color.rgb = header_fill if r == 0 else WHITE
            val = rows[r][c]
            color = WHITE if r == 0 else TEXT
            if r and cell_colors and (r, c) in cell_colors:
                color = cell_colors[(r, c)]
            bold = r == 0 or (c == 0 and first_col_bold) or (r and cell_colors and (r, c) in cell_colors)
            fill_text(
                cell.text_frame, [P(R(val, size, bold, color))],
                margins=(0.12, 0.04, 0.12, 0.04), anchor=MSO_ANCHOR.MIDDLE,
            )
            _cell_borders(cell)
    return gt


def _cell_borders(cell):
    tcPr = cell._tc.get_or_add_tcPr()
    for edge in ("a:lnL", "a:lnR", "a:lnT", "a:lnB"):
        ln = etree.SubElement(tcPr, qn(edge))
        if edge in ("a:lnL", "a:lnR"):
            ln.set("w", "0")
            etree.SubElement(ln, qn("a:noFill"))
        else:
            ln.set("w", str(Pt(0.75)))
            sf = etree.SubElement(ln, qn("a:solidFill"))
            clr = etree.SubElement(sf, qn("a:srgbClr"))
            clr.set("val", str(BORDER))
    # schema order: borders must precede fill in tcPr
    fill = tcPr.find(qn("a:solidFill"))
    if fill is not None:
        tcPr.remove(fill)
        tcPr.append(fill)


# ---------------------------------------------------------------- slides
def slide_title(prs):
    s = prs.slides.add_slide(prs.slide_layouts[6])
    background(s, NAVY)
    text(s, MARGIN, 0.8, 12, 0.3, [P(R("PROJECT REVIEW  |  " + DEPT.upper(), 10, True, ON_DARK_ACCENT, spacing=1.5))])
    text(s, MARGIN, 1.45, 12, 1.1, [P(R(PROJECT, 54, True, WHITE))])
    text(
        s, MARGIN, 2.6, 10.5, 1.0,
        [P(R("Supply-chain risk scanning for software packages and AI/ML model artifacts: "
             "multi-layer evidence, explainable 0–1 risk score, ALLOW / REVIEW / BLOCK policy, "
             "and evidence hashes anchored on a local blockchain.", 18, False, ON_DARK_MUTED),
           line_spacing=1.1)],
    )
    # stack chips
    cx = MARGIN
    for label in ["FastAPI", "PostgreSQL", "Syft + OSV/NVD", "scikit-learn + SHAP", "Solidity + Hardhat", "React"]:
        w = 0.105 * len(label) + 0.45
        tag(s, cx, 3.95, label, fill=NAVY_CARD, color=ON_DARK_ACCENT, w=w)
        cx += w + 0.15

    text(s, MARGIN, 4.75, 6, 0.3, [P(R("TEAM", 10, True, ON_DARK_ACCENT, spacing=1.5))])
    gap = 0.3
    cw = (SLIDE_W - 2 * MARGIN - 2 * gap) / 3
    for i, (name, usn) in enumerate(TEAM):
        x = MARGIN + i * (cw + gap)
        c = box(s, x, 5.1, cw, 1.6, fill=NAVY_CARD, line=NAVY_LINE)
        fill_text(c.text_frame, [
            P(R(f"MEMBER {i + 1:02d}", 10, True, ON_DARK_MUTED, spacing=1.0), space_after=6),
            P(R(name, 20, True, WHITE), space_after=4),
            P(R("USN  ", 13, False, ON_DARK_MUTED), R(usn, 13, True, ON_DARK_ACCENT)),
        ], anchor=MSO_ANCHOR.MIDDLE)


def slide_overview(prs):
    s = content_slide(prs, 2, "Overview", "Problem statement and proposed system")
    top, h = 1.4, 5.3
    lw = 5.75
    bul = dict(bullet=True, space_after=7)
    card(s, MARGIN, top, lw, h, "Why supply-chain artifacts need multi-layer checks", [
        P(R("Projects pull dependencies from GitHub and pretrained models, LoRA adapters and datasets "
            "from Hugging Face, usually with no integrity or provenance check.", 13), **bul),
        P(R("Risk sits in several layers at once: known CVEs, missing provenance, changed hashes, "
            "unsafe pickle serialization, model custom code, install scripts, runtime behavior.", 13), **bul),
        P(R("CVE-only scanners miss provenance and model-specific risk, and their results are not "
            "tamper-evident after the fact.", 13), **bul),
        P(R("OBJECTIVE", 10, True, ACCENT, spacing=1.0), space_before=8, space_after=4),
        P(R("Take a repo/package or model artifact, collect evidence from every layer, return an "
            "explainable 0–1 risk score and an ALLOW / REVIEW / BLOCK decision, and anchor "
            "compact evidence hashes on-chain so the result can be re-verified later.", 13)),
    ], kicker="Problem and objective")

    rx = MARGIN + lw + 0.3
    rw = SLIDE_W - MARGIN - rx
    c = box(s, rx, top, rw, h)
    fill_text(c.text_frame, [
        P(R("PROPOSED SYSTEM", 10, True, ACCENT, spacing=1.0), space_after=3),
        P(R("Four-tier pipeline, 22 ordered stages", 15, True)),
    ])
    tiers = [
        ("1  Ingest", "GitHub / Hugging Face URL (https allowlist) or ZIP upload; safe workspace; SHA-256 content digest"),
        ("2  Evidence", "SBOM (Syft/CycloneDX) or AI-BOM, NetworkX graph, OSV/NVD, provenance, static analysis, optional Docker sandbox"),
        ("3  Score", "Feature vector → Random Forest + Isolation Forest → rule-layer fusion → policy → SHAP factors"),
        ("4  Trust & output", "PostgreSQL persistence, anchor on Hardhat via web3.py, /verify endpoint, React dashboard, CI gate"),
    ]
    ty = top + 1.05
    th = 0.9
    for i, (name, desc) in enumerate(tiers):
        y = ty + i * (th + 0.13)
        b = box(s, rx + PAD, y, rw - 2 * PAD, th, fill=ACCENT_SOFT if i % 2 == 0 else OFFWHITE, line=BORDER)
        fill_text(b.text_frame, [
            P(R(name, 13, True, ACCENT), space_after=2),
            P(R(desc, 12.5, False, TEXT)),
        ], margins=(0.2, 0.08, 0.2, 0.06), anchor=MSO_ANCHOR.MIDDLE)


def slide_progress(prs):
    s = content_slide(prs, 3, "Implementation progress", "All 10 planned phases are complete and committed")
    # phase tracker
    phases = ["P0 Base", "P1 Ingest", "P2 SBOM", "P3 AI/ML", "P4 Static", "P5 ML", "P6 Fusion",
              "P7 Chain", "P8 UI", "P9 CI gate"]
    n = len(phases)
    tw = SLIDE_W - 2 * MARGIN
    seg = tw / n
    y = 1.35
    for i, label in enumerate(phases):
        x = MARGIN + i * seg
        b = box(s, x + 0.03, y, seg - 0.06, 0.42, fill=ACCENT, line=None, radius=0.3)
        fill_text(b.text_frame, [P(R(label, 11, True, WHITE), align=PP_ALIGN.CENTER)],
                  margin=0, anchor=MSO_ANCHOR.MIDDLE)
    text(s, MARGIN, y + 0.5, tw, 0.25, [P(
        R("33 commits on main  |  phase scope: 10 / 10 complete (100%)  |  source: docs/HANDOFF.md", 11, False, MUTED))])

    rows = [
        ["Component", "Phase", "Scope", "Verification status"],
        ["Ingestion, validation, SHA-256", "0–1", "100%", "Traversal, bomb, symlink and SSRF tests"],
        ["SBOM, OSV/NVD, dependency graph", "2", "100%", "pallets/flask: 117 components, 52 findings"],
        ["AI-BOM, lineage, pickle scan", "3", "100%", "HF tiny-random-gpt2: 10/10 files verified"],
        ["Static analysis, Docker sandbox", "4", "100%", "35 sandbox tests, local only (not in CI)"],
        ["Dataset, RF / XGB / IF models", "5", "100%", "Synthetic data only; see ml/reports/"],
        ["Fusion, policy, SHAP", "6", "100%", "Weights hand-set, not tuned on test data"],
        ["Contract, anchoring, /verify", "7", "100%", "32 Hardhat tests; VERIFIED/MISMATCH"],
        ["React dashboard (10 pages)", "8", "100%", "483 Vitest tests incl. jest-axe"],
        ["CI gate, e2e fixtures, demo", "9", "100%", "e2e 6/6; gate not yet run on GitHub"],
    ]
    tx, ty = MARGIN, 2.3
    col_w = [3.0, 0.75, 0.75, 3.75]
    table(s, tx, ty, sum(col_w), col_w, rows, row_h=0.43, size=11.5,
          cell_colors={(r, 2): OK for r in range(1, len(rows))})

    rx = MARGIN + sum(col_w) + 0.3
    rw = SLIDE_W - MARGIN - rx
    card(s, rx, ty, rw, 1.85, "Active development", [
        P(R("Scan progress modal with live per-stage status (uncommitted working tree).", 12.5)),
    ], kicker="In progress", title_size=14)
    card(s, rx, ty + 2.05, rw, 2.25, "Remaining validation", [
        P(R("Gate workflow run on GitHub", 12.5), bullet=True, space_after=3),
        P(R("Fresh-clone reproduction", 12.5), bullet=True, space_after=3),
        P(R("Full network/sandbox/chain suites", 12.5), bullet=True, space_after=3),
        P(R("Real-world labelled evaluation", 12.5), bullet=True),
    ], kicker="Not yet run", title_size=14)


def slide_modules(prs):
    s = content_slide(prs, 4, "Architecture", "Developed modules and how they integrate")
    mods = [
        ("api/", "FastAPI routers: scans, findings, graph, risk, evidence, anchor, verify"),
        ("security/ + pipeline/", "URL allowlist, safe workspace, staged runner with per-stage status"),
        ("scanners/", "Syft SBOM, OSV/NVD, Hugging Face fetch, pickletools, static, sandbox"),
        ("graph/ + provenance/", "NetworkX dependency and lineage graphs; hash and lineage checks"),
        ("ml/", "Feature schema, synthetic dataset, training, evaluation, ablation"),
        ("risk/", "Model runtime, rule-layer fusion, policy config, SHAP explanation"),
        ("blockchain/ + contracts/", "web3.py adapter, ProvenanceEvidence.sol, verification"),
        ("db/ + frontend/", "SQLAlchemy models, Alembic migrations; React dashboard"),
    ]
    cols, gap = 4, 0.25
    cw = (SLIDE_W - 2 * MARGIN - (cols - 1) * gap) / cols
    ch = 1.25
    for i, (name, desc) in enumerate(mods):
        r, c = divmod(i, cols)
        x = MARGIN + c * (cw + gap)
        y = 1.35 + r * (ch + 0.2)
        b = box(s, x, y, cw, ch)
        fill_text(b.text_frame, [
            P(R(name, 13.5, True, ACCENT), space_after=3),
            P(R(desc, 12, False, TEXT)),
        ], margins=(0.22, 0.16, 0.22, 0.12))

    # flow diagram
    fy = 4.4
    text(s, MARGIN, fy, 8, 0.25, [P(R("DATA FLOW  (backend/app/pipeline/stages.py order)", 10, True, ACCENT, spacing=1.0))])
    steps = [
        ("Input", "GitHub / HF URL\nor ZIP upload"),
        ("Ingest", "safe workspace,\nSHA-256 digest"),
        ("Evidence", "SBOM / AI-BOM,\ngraph, OSV/NVD,\nprovenance,\nstatic, sandbox"),
        ("Risk", "features,\nRF + IF models,\nfusion, policy,\nSHAP"),
        ("Persist", "PostgreSQL\n9 entity tables"),
        ("Anchor", "web3.py →\nHardhat contract"),
        ("Output", "React dashboard,\n/verify, CI gate"),
    ]
    n = len(steps)
    agap = 0.32
    bw = (SLIDE_W - 2 * MARGIN - (n - 1) * agap) / n
    bh = 1.75
    by = fy + 0.4
    for i, (name, desc) in enumerate(steps):
        x = MARGIN + i * (bw + agap)
        dark = i in (0, n - 1)
        b = box(s, x, by, bw, bh, fill=NAVY if dark else WHITE, line=None if dark else BORDER)
        fill_text(b.text_frame, [
            P(R(name, 13.5, True, WHITE if dark else ACCENT), space_after=4, align=PP_ALIGN.CENTER),
            P(R(desc, 11, False, ON_DARK_MUTED if dark else TEXT), align=PP_ALIGN.CENTER),
        ], margins=(0.08, 0.1, 0.08, 0.1), anchor=MSO_ANCHOR.MIDDLE)
        if i < n - 1:
            arrow(s, x + bw + 0.04, by + bh / 2, x + bw + agap - 0.04, by + bh / 2)


def slide_tools(prs):
    s = content_slide(prs, 5, "Tools and technologies", "Stack, pinned versions, and where each is used")
    cats = [
        ("Backend and data", [
            ("Python 3.12 + FastAPI 0.115", "REST API; scans return 202 and run as background tasks"),
            ("Pydantic 2 + pydantic-settings", "request validation; all config from environment variables"),
            ("SQLAlchemy 2.0 + Alembic + PostgreSQL 16", "9 entities; CI fails on migration drift"),
            ("NetworkX 3.4", "dependency and lineage graphs; depth and centrality features"),
        ]),
        ("ML and explainability", [
            ("scikit-learn 1.9.1", "Random Forest (primary classifier), Isolation Forest (anomaly)"),
            ("XGBoost 3.4.1", "comparison model, evaluated on the same family split"),
            ("SHAP 0.54.1", "top contributing features for each scan's RF prediction"),
            ("skops 0.16.0", "model files saved and loaded without pickle"),
        ]),
        ("Supply chain and blockchain", [
            ("Syft 1.57.0 (CycloneDX)", "SBOM generation; binary SHA-256-pinned in the API image"),
            ("OSV + NVD APIs (httpx)", "advisory lookup; NVD fills missing CVSS scores"),
            ("Solidity 0.8.28 + Hardhat 2.29.1", "ProvenanceEvidence contract on a local chain"),
            ("web3.py 8.0.0", "anchors 8 evidence fields; reads them back for /verify"),
        ]),
        ("Frontend, testing and DevOps", [
            ("React 18.3 + Vite 6.4 (plain JS)", "10 dashboard pages; dagre for graph layout"),
            ("Vitest 3.2 + jest-axe", "component and accessibility tests"),
            ("pytest 8 + ruff", "unit, integration, security and e2e suites; lint gate"),
            ("Docker Compose + GitHub Actions", "local stack, hardened sandbox, CI and gate workflow"),
        ]),
    ]
    gap = 0.3
    cw = (SLIDE_W - 2 * MARGIN - gap) / 2
    ch = 2.6
    for i, (title, items) in enumerate(cats):
        r, c = divmod(i, 2)
        x = MARGIN + c * (cw + gap)
        y = 1.35 + r * (ch + 0.25)
        paras = []
        for j, (name, why) in enumerate(items):
            paras.append(P(R(name, 13, True, TEXT), space_after=0))
            paras.append(P(R(why, 12, False, MUTED), space_after=0 if j == len(items) - 1 else 6))
        b = box(s, x, y, cw, ch)
        fill_text(b.text_frame, [P(R(title.upper(), 10, True, ACCENT, spacing=1.0), space_after=6)] + paras,
                  margins=(PAD, 0.22, PAD, 0.18))


def slide_results(prs):
    s = content_slide(prs, 6, "Preliminary results", "Test results, live scans and synthetic model evaluation")
    stats = [
        ("2,616", "backend tests passed", "pytest, 0 failed, 0 skipped"),
        ("483", "frontend tests passed", "Vitest + jest-axe, 10 pages"),
        ("32", "contract tests passing", "Hardhat, ABI check matches"),
        ("6 / 6", "end-to-end cases passed", "make e2e, live OSV + chain"),
    ]
    gap = 0.25
    sw = (SLIDE_W - 2 * MARGIN - 3 * gap) / 4
    for i, (num, label, sub) in enumerate(stats):
        x = MARGIN + i * (sw + gap)
        b = box(s, x, 1.3, sw, 1.15)
        fill_text(b.text_frame, [
            P(R(num, 30, True, ACCENT), space_after=0),
            P(R(label, 13, True, TEXT), space_after=0),
            P(R(sub, 11, False, MUTED)),
        ], margins=(0.25, 0.12, 0.2, 0.1), anchor=MSO_ANCHOR.MIDDLE)

    # model table
    ty = 2.7
    text(s, MARGIN, ty, 7.6, 0.25, [P(R("BENIGN VS. ANY RISK  |  PRIMARY TEST SPLIT (356 RECORDS)", 10, True, ACCENT, spacing=1.0))])
    rows = [
        ["Model", "Precision", "Recall", "F1", "ROC-AUC", "FPR"],
        ["Random Forest (primary)", "0.910", "0.944", "0.927", "0.960", "0.284"],
        ["XGBoost (comparison)", "0.898", "0.951", "0.924", "0.966", "0.330"],
        ["Isolation Forest (anomaly)", "0.750", "0.045", "0.085", "0.514", "0.045"],
        ["Rules-only baseline", "0.856", "0.910", "0.882", "0.771", "0.466"],
        ["Vulnerability-only baseline", "1.000", "0.444", "0.615", "0.722", "0.000"],
    ]
    col_w = [2.75, 1.05, 0.85, 0.75, 1.0, 0.75]
    table(s, MARGIN, ty + 0.32, sum(col_w), col_w, rows, row_h=0.38, size=12)
    warn = box(s, MARGIN, ty + 0.32 + 0.38 * 6 + 0.15, sum(col_w), 0.72, fill=RGBColor(0xFF, 0xF7, 0xED),
               line=RGBColor(0xFE, 0xD7, 0xAA))
    fill_text(warn.text_frame, [P(
        R("SYNTHETIC DATA  ", 10.5, True, WARN),
        R("2,333 generated records, 200 families, split by family. Shows the pipeline recovers injected "
          "signals; it is not real-world detection accuracy. No real malware was used.", 11, False, TEXT))],
        margins=(0.2, 0.06, 0.2, 0.06), anchor=MSO_ANCHOR.MIDDLE)

    rx = MARGIN + sum(col_w) + 0.3
    rw = SLIDE_W - MARGIN - rx
    card(s, rx, ty, rw, 4.05, "Technical observations", [
        P(R("Live scan of pallets/flask: ", 12.5, True), R("117 components, 52 OSV findings.", 12.5), bullet=True, space_after=5),
        P(R("Ablation: ", 12.5, True), R("removing the vulnerability layer cuts RF F1 by 0.054, provenance by 0.046.", 12.5), bullet=True, space_after=5),
        P(R("False positives: ", 12.5, True), R("RF flagged 19 of 26 benign records with no prior hash, so ML only moves the score inside the rule-based band.", 12.5), bullet=True, space_after=5),
        P(R("Tamper check: ", 12.5, True), R("editing an anchored file makes /verify return MISMATCH; "
          "restoring it returns VERIFIED.", 12.5), bullet=True),
    ], kicker="Observed behavior", title_size=14)


def slide_demo(prs):
    s = content_slide(prs, 7, "Live demonstration", "Execution workflow the panel will see")
    steps = [
        ("01", "Setup", ["make demo", "Compose builds Postgres 16, API, Hardhat and UI",
                         "Deploys contract, seeds 5 fixtures", "UI on 127.0.0.1:15173"]),
        ("02", "Trigger", ["New Scan page, or", "POST /api/v1/scans/software", "GitHub URL or ZIP upload",
                           "Returns 202 + scan_id"]),
        ("03", "Pipeline runs", ["queued → running → completed", "SBOM, graph, OSV/NVD, provenance,",
                                 "static, features, ML, fusion,", "policy, SHAP; persisted"]),
        ("04", "Output and verify", ["Scan Details: score, decision,", "findings, graph, SHAP factors",
                                     "Anchor → POST /verify = VERIFIED", "Edit file → MISMATCH"]),
    ]
    n = len(steps)
    agap = 0.4
    bw = (SLIDE_W - 2 * MARGIN - (n - 1) * agap) / n
    bh = 2.7
    by = 1.3
    for i, (num, name, lines) in enumerate(steps):
        x = MARGIN + i * (bw + agap)
        b = box(s, x, by, bw, bh)
        paras = [P(R(num, 22, True, ACCENT), space_after=0), P(R(name, 15, True), space_after=6)]
        for ln in lines:
            mono = ln.startswith(("make", "POST"))
            paras.append(P(R(ln, 12.5, mono, ACCENT if mono else TEXT), space_after=2))
        fill_text(b.text_frame, paras, margins=(0.25, 0.2, 0.2, 0.15))
        if i < n - 1:
            arrow(s, x + bw + 0.06, by + bh / 2, x + bw + agap - 0.06, by + bh / 2)

    ty = 4.25
    text(s, MARGIN, ty, 9, 0.25, [P(R("SEEDED DEMO CASES  |  RECORDED RUN, 2026-11-09  |  ALL ANCHORED, ALL VERIFIED",
                                      10, True, ACCENT, spacing=1.0))])
    rows = [
        ["Fixture", "Decision", "Score", "Confidence", "Layers not evaluated"],
        ["software_clean", "REVIEW", "0.478", "0.630", "behavioral"],
        ["software_risky_config", "REVIEW", "0.529", "0.630", "behavioral"],
        ["model_clean", "REVIEW", "0.350", "0.488", "vulnerability, behavioral"],
        ["model_risky_config", "REVIEW", "0.495", "0.488", "vulnerability, behavioral"],
        ["model_dangerous_global", "BLOCK", "0.721", "0.488", "vulnerability, behavioral"],
    ]
    col_w = [2.25, 1.0, 0.85, 1.15, 2.35]
    colors = {(r, 1): WARN for r in range(1, 5)}
    colors[(5, 1)] = BAD
    table(s, MARGIN, ty + 0.32, sum(col_w), col_w, rows, row_h=0.36, size=12, cell_colors=colors)

    rx = MARGIN + sum(col_w) + 0.3
    rw = SLIDE_W - MARGIN - rx
    card(s, rx, ty, rw, 2.48, "Reading the results", [
        P(R("REVIEW at score ≥ 0.35; BLOCK at ≥ 0.70 or on a hard rule.", 12.5),
          bullet=True, space_after=4),
        P(R("Clean fixtures get REVIEW: unevaluated layers lower confidence.", 12.5),
          bullet=True, space_after=4),
        P(R("BLOCK case: pickle opcodes (GLOBAL os.system), parsed, never loaded.", 12.5),
          bullet=True),
    ], kicker="Wiring checks, not detection", title_size=14)


def slide_thanks(prs):
    s = prs.slides.add_slide(prs.slide_layouts[6])
    background(s, NAVY)
    text(s, MARGIN, 1.7, 12, 0.3, [P(R(PROJECT.upper() + "  |  PROJECT REVIEW", 10, True, ON_DARK_ACCENT, spacing=1.5))])
    text(s, MARGIN, 2.1, 12, 1.0, [P(R("Thank You", 48, True, WHITE))])
    text(s, MARGIN, 3.1, 12, 0.6, [P(R("Questions & Discussion", 24, False, ON_DARK_MUTED))])
    text(s, MARGIN, 4.2, 12, 0.3, [P(R(DEPT, 13, False, ON_DARK_MUTED))])
    gap = 0.3
    cw = (SLIDE_W - 2 * MARGIN - 2 * gap) / 3
    for i, (name, usn) in enumerate(TEAM):
        x = MARGIN + i * (cw + gap)
        c = box(s, x, 5.3, cw, 1.0, fill=NAVY_CARD, line=NAVY_LINE)
        fill_text(c.text_frame, [P(R(name, 17, True, WHITE), R("   " + usn, 13, False, ON_DARK_ACCENT))],
                  anchor=MSO_ANCHOR.MIDDLE)


def main():
    prs = Presentation()
    prs.slide_width = Inches(SLIDE_W)
    prs.slide_height = Inches(SLIDE_H)
    for build in (slide_title, slide_overview, slide_progress, slide_modules, slide_tools,
                  slide_results, slide_demo, slide_thanks):
        build(prs)
    prs.core_properties.title = f"{PROJECT} Project Review"
    prs.save(OUT)
    print(f"Wrote {OUT}")


if __name__ == "__main__":
    main()
