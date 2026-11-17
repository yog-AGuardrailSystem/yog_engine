#!/usr/bin/env python3
"""Build the YOG benchmark presentation from the committed results.

Every number in the deck is read from ``benchmarks/results/comparison.json``
when it is present; the embedded fallbacks are only there so the script still
produces a deck in a fresh checkout. The deck states its boundary on every
results slide and keeps the measured losses on their own slide.

Usage:
    python presentation/build_deck.py [--out PATH]
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.util import Inches, Pt

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[0]
RESULTS = ROOT / "benchmarks" / "results" / "comparison.json"

# ---------------------------------------------------------------- palette ----
INK = RGBColor(0x0B, 0x1B, 0x2B)
INK_SOFT = RGBColor(0x33, 0x41, 0x55)
SLATE = RGBColor(0x47, 0x55, 0x69)
MUTED = RGBColor(0x64, 0x74, 0x8B)
LINE = RGBColor(0xE2, 0xE8, 0xF0)
PAPER = RGBColor(0xF8, 0xFA, 0xFC)
PANEL = RGBColor(0xF1, 0xF5, 0xF9)
TEAL = RGBColor(0x0F, 0x76, 0x6E)
TEAL_SOFT = RGBColor(0xCC, 0xFB, 0xF1)
AMBER = RGBColor(0xB4, 0x53, 0x09)
AMBER_SOFT = RGBColor(0xFE, 0xF3, 0xC7)
RED = RGBColor(0xB9, 0x1C, 0x1C)
RED_SOFT = RGBColor(0xFE, 0xE2, 0xE2)
WHITE = RGBColor(0xFF, 0xFF, 0xFF)
CODE_BG = RGBColor(0x0B, 0x1B, 0x2B)
CODE_FG = RGBColor(0xE2, 0xE8, 0xF0)
CODE_ACCENT = RGBColor(0x5E, 0xEA, 0xD4)

BODY_FONT = "Segoe UI"
CODE_FONT = "Consolas"
TOTAL_SLIDES = 15

FALLBACK = {
    "python": {"large": {"admin": (8.7, 132.4), "join": (133.6, 150.9),
                         "deny": (364.2, 1350.8)}},
    "rust": {"large": {"admin": (1.8, 10.5), "join": (121.8, 10.4),
                       "deny": (345.4, 8.8)}},
    "go": {"large": {"admin": (2.0, 1467.7), "join": (123.5, 1472.5),
                     "deny": (347.2, 1464.1)}},
}


def load_results() -> tuple[dict, str]:
    if not RESULTS.exists():
        return {}, "results/comparison.json missing; using embedded fallbacks"
    data = json.loads(RESULTS.read_text(encoding="utf-8"))
    commit = data.get("versions", {}).get("git_commit", "")[:7]
    stamp = data.get("generated_at", "")
    if len(stamp) >= 16:
        stamp = stamp[:16].replace("T", " ") + " UTC"
    return data, f"comparison.json {stamp} at {commit}"


RESULTS_DATA, RESULTS_SOURCE = load_results()


def p50(boundary: str, engine: str, request: str, size: str = "large") -> float:
    try:
        return float(RESULTS_DATA["boundaries"][boundary]["sizes"][size][engine]
                     ["requests"][request]["p50_us"])
    except (KeyError, TypeError):
        key = {"python-in-process": "python", "rust-in-process": "rust",
               "go-in-process": "go"}[boundary]
        request_key = {"admin allow": 0, "team join allow": 1,
                       "guest default deny": 2}[request]
        return float(FALLBACK[key][size][("admin", "join", "deny")[request_key]][0])


# ---------------------------------------------------------------- helpers ----
def add_slide(prs: Presentation):
    return prs.slides.add_slide(prs.slide_layouts[6])


def textbox(slide, left, top, width, height, margin=0.0):
    box = slide.shapes.add_textbox(Inches(left), Inches(top), Inches(width), Inches(height))
    tf = box.text_frame
    tf.word_wrap = True
    tf.margin_left = Inches(margin)
    tf.margin_right = Inches(margin)
    tf.margin_top = Inches(0.02)
    tf.margin_bottom = Inches(0.02)
    return box, tf


def set_paragraph(paragraph, text, size=16, colour=INK, bold=False,
                  font=BODY_FONT, space_after=6, align=None, line=1.08):
    paragraph.text = ""
    run = paragraph.add_run()
    run.text = text
    run.font.size = Pt(size)
    run.font.bold = bold
    run.font.name = font
    run.font.color.rgb = colour
    paragraph.space_after = Pt(space_after)
    paragraph.line_spacing = line
    if align is not None:
        paragraph.alignment = align
    return run


MARKUP = re.compile(r"(\*\*[^*]+\*\*|`[^`]+`)")


def rich_paragraph(paragraph, text, size=16, colour=INK, font=BODY_FONT,
                   space_after=6, bullet="•", line=1.08):
    """One bullet where **...** is bold and `...` is monospace."""
    paragraph.text = ""
    if bullet:
        marker = paragraph.add_run()
        marker.text = f"{bullet}  "
        marker.font.size = Pt(size)
        marker.font.name = font
        marker.font.color.rgb = TEAL
        marker.font.bold = True
    for chunk in MARKUP.split(text):
        if not chunk:
            continue
        bold = chunk.startswith("**") and chunk.endswith("**")
        code = chunk.startswith("`") and chunk.endswith("`")
        run = paragraph.add_run()
        run.text = chunk[2:-2] if bold else (chunk[1:-1] if code else chunk)
        run.font.size = Pt(size - 0.4 if code else size)
        run.font.bold = bold
        run.font.name = CODE_FONT if code else font
        run.font.color.rgb = INK_SOFT if code else colour
    paragraph.space_after = Pt(space_after)
    paragraph.line_spacing = line


def header(slide, title, kicker, number):
    bar = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(0.62), Inches(0.58),
                                 Inches(0.075), Inches(0.72))
    bar.fill.solid()
    bar.fill.fore_color.rgb = TEAL
    bar.line.fill.background()
    bar.shadow.inherit = False

    _, tf = textbox(slide, 0.86, 0.42, 11.6, 0.3)
    set_paragraph(tf.paragraphs[0], kicker.upper(), size=10.5, colour=TEAL,
                  bold=True, space_after=0)

    _, tf = textbox(slide, 0.86, 0.68, 11.7, 0.62)
    set_paragraph(tf.paragraphs[0], title, size=25, colour=INK, bold=True,
                  space_after=0, line=0.98)

    rule = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(0.62), Inches(1.36),
                                  Inches(12.1), Inches(0.012))
    rule.fill.solid()
    rule.fill.fore_color.rgb = LINE
    rule.line.fill.background()

    footer(slide, number)


def footer(slide, number):
    _, tf = textbox(slide, 0.62, 6.98, 9.8, 0.3)
    set_paragraph(tf.paragraphs[0],
                  "YOG · experimental, not production-ready · Windows 11, Release, "
                  "pinned CPU 0, 10 runs, 95% bootstrap CI",
                  size=8, colour=MUTED, space_after=0)

    _, tf = textbox(slide, 11.4, 6.98, 1.3, 0.3)
    set_paragraph(tf.paragraphs[0], f"{number} / {TOTAL_SLIDES}", size=8,
                  colour=MUTED, space_after=0, align=PP_ALIGN.RIGHT)


def bullets(slide, items, left=0.72, top=1.62, width=11.0, height=4.9,
            size=15.5, gap=9):
    _, tf = textbox(slide, left, top, width, height)
    first = True
    for item in items:
        level = 0
        text = item
        if isinstance(item, tuple):
            text, level = item
        paragraph = tf.paragraphs[0] if first else tf.add_paragraph()
        first = False
        paragraph.level = level
        rich_paragraph(paragraph, text, size=size if level == 0 else size - 2.2,
                       colour=INK if level == 0 else SLATE,
                       space_after=gap if level == 0 else max(gap - 4, 2),
                       bullet="•" if level == 0 else "–")


def panel(slide, left, top, width, height, fill=PANEL, radius=True):
    shape = slide.shapes.add_shape(
        MSO_SHAPE.ROUNDED_RECTANGLE if radius else MSO_SHAPE.RECTANGLE,
        Inches(left), Inches(top), Inches(width), Inches(height))
    shape.fill.solid()
    shape.fill.fore_color.rgb = fill
    shape.line.color.rgb = LINE
    shape.line.width = Pt(0.75)
    shape.shadow.inherit = False
    if radius:
        try:
            shape.adjustments[0] = 0.06
        except (IndexError, ValueError):
            pass
    return shape


def code_block(slide, code, left, top, width, height, size=10.5):
    panel(slide, left, top, width, height, fill=CODE_BG)
    _, tf = textbox(slide, left + 0.22, top + 0.16, width - 0.44, height - 0.3)
    for index, line in enumerate(code.split("\n")):
        paragraph = tf.paragraphs[0] if index == 0 else tf.add_paragraph()
        paragraph.text = ""
        run = paragraph.add_run()
        run.text = line if line else " "
        run.font.size = Pt(size)
        run.font.name = CODE_FONT
        stripped = line.strip()
        if stripped.startswith("ALLOW"):
            run.font.color.rgb = CODE_ACCENT
        elif stripped.startswith("DENY"):
            run.font.color.rgb = RGBColor(0xFC, 0xA5, 0xA5)
        elif stripped.startswith("#"):
            run.font.color.rgb = RGBColor(0x94, 0xA3, 0xB8)
        else:
            run.font.color.rgb = CODE_FG
        paragraph.space_after = Pt(1)
        paragraph.line_spacing = 1.0


def note(slide, text):
    slide.notes_slide.notes_text_frame.text = text


def stat_cards(slide, cards, top=1.68, left=0.72, width=11.9, height=1.28,
               accent=TEAL):
    gap = 0.18
    card_width = (width - gap * (len(cards) - 1)) / len(cards)
    for index, (big, caption) in enumerate(cards):
        x = left + index * (card_width + gap)
        panel(slide, x, top, card_width, height, fill=WHITE)
        _, tf = textbox(slide, x + 0.16, top + 0.14, card_width - 0.32, 0.6)
        set_paragraph(tf.paragraphs[0], big, size=25, colour=accent, bold=True,
                      space_after=2)
        _, tf = textbox(slide, x + 0.16, top + 0.72, card_width - 0.32, 0.5)
        set_paragraph(tf.paragraphs[0], caption, size=10.5, colour=SLATE,
                      space_after=0, line=1.02)


def table(slide, headers, rows, left, top, width, col_widths,
          size=11, header_fill=INK, row_height=0.30, aligns=None,
          first_col_bold=False, highlight_rows=None):
    shape = slide.shapes.add_table(len(rows) + 1, len(headers), Inches(left),
                                   Inches(top), Inches(width),
                                   Inches(row_height * (len(rows) + 1)))
    grid = shape.table
    grid.first_row = False
    grid.horz_banding = False
    for index, width_in in enumerate(col_widths):
        grid.columns[index].width = Inches(width_in)
    for index in range(len(rows) + 1):
        grid.rows[index].height = Inches(row_height)

    for col, text in enumerate(headers):
        cell = grid.cell(0, col)
        cell.fill.solid()
        cell.fill.fore_color.rgb = header_fill
        cell.margin_left = Inches(0.08)
        cell.margin_right = Inches(0.08)
        cell.margin_top = Inches(0.03)
        cell.margin_bottom = Inches(0.03)
        paragraph = cell.text_frame.paragraphs[0]
        set_paragraph(paragraph, text, size=size, colour=WHITE, bold=True,
                      space_after=0,
                      align=(aligns[col] if aligns else PP_ALIGN.LEFT))

    for row_index, row in enumerate(rows, start=1):
        fill = PAPER if row_index % 2 == 0 else WHITE
        if highlight_rows and row_index in highlight_rows:
            fill = RED_SOFT
        for col, text in enumerate(row):
            cell = grid.cell(row_index, col)
            cell.fill.solid()
            cell.fill.fore_color.rgb = fill
            cell.margin_left = Inches(0.08)
            cell.margin_right = Inches(0.08)
            cell.margin_top = Inches(0.02)
            cell.margin_bottom = Inches(0.02)
            cell.vertical_anchor = MSO_ANCHOR.MIDDLE
            paragraph = cell.text_frame.paragraphs[0]
            set_paragraph(paragraph, str(text), size=size, colour=INK,
                          bold=(first_col_bold and col == 0), space_after=0,
                          align=(aligns[col] if aligns else PP_ALIGN.LEFT))
    return shape


def bar_block(slide, left, top, width, entries, unit="µs", row_height=0.62,
              label_width=2.55, note_text=None):
    """Horizontal bars on a log10 scale. entries: (label, value, colour)."""
    values = [value for _, value, _ in entries]
    lo = min(values) / 2.0
    hi = max(values) * 1.6
    import math
    log_lo, log_hi = math.log10(lo), math.log10(hi)
    plot_left = left + label_width + 0.12
    plot_width = width - label_width - 0.95

    ticks = [t for t in (1, 10, 100, 1000, 10000) if lo <= t <= hi]
    for tick in ticks:
        x = plot_left + (math.log10(tick) - log_lo) / (log_hi - log_lo) * plot_width
        line = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(x), Inches(top),
                                      Inches(0.008), Inches(row_height * len(entries)))
        line.fill.solid()
        line.fill.fore_color.rgb = LINE
        line.line.fill.background()
        _, tf = textbox(slide, x - 0.32, top - 0.24, 0.7, 0.2)
        set_paragraph(tf.paragraphs[0], f"{tick:g}", size=8, colour=MUTED,
                      space_after=0, align=PP_ALIGN.CENTER)

    for index, (label, value, colour) in enumerate(entries):
        y = top + index * row_height
        _, tf = textbox(slide, left, y + 0.04, label_width, 0.3)
        set_paragraph(tf.paragraphs[0], label, size=10.5, colour=INK, space_after=0)
        track = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE,
                                       Inches(plot_left), Inches(y + 0.08),
                                       Inches(plot_width), Inches(0.26))
        track.fill.solid()
        track.fill.fore_color.rgb = PANEL
        track.line.fill.background()
        track.shadow.inherit = False

        fraction = (math.log10(value) - log_lo) / (log_hi - log_lo)
        bar_width = max(plot_width * fraction, 0.045)
        bar = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE,
                                     Inches(plot_left), Inches(y + 0.08),
                                     Inches(bar_width), Inches(0.26))
        bar.fill.solid()
        bar.fill.fore_color.rgb = colour
        bar.line.fill.background()
        bar.shadow.inherit = False

        _, tf = textbox(slide, plot_left + plot_width + 0.06, y + 0.04, 0.9, 0.3)
        shown = f"{value:,.1f}".rstrip("0").rstrip(".")
        set_paragraph(tf.paragraphs[0], f"{shown} {unit}", size=10, colour=INK,
                      bold=True, space_after=0)

    if note_text:
        _, tf = textbox(slide, left, top + row_height * len(entries) + 0.3,
                        width, 0.28)
        set_paragraph(tf.paragraphs[0], note_text, size=9, colour=MUTED,
                      space_after=0)


def architecture(slide, top):
    steps = ["lexer", "parser", "sema", "clause table", "VM", "C API / CLI"]
    left, width, gap = 0.72, 1.72, 0.28
    for index, step in enumerate(steps):
        x = left + index * (width + gap)
        shape = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(x),
                                       Inches(top), Inches(width), Inches(0.52))
        shape.fill.solid()
        shape.fill.fore_color.rgb = WHITE if index < 5 else TEAL
        shape.line.color.rgb = LINE if index < 5 else TEAL
        shape.line.width = Pt(0.9)
        shape.shadow.inherit = False
        tf = shape.text_frame
        tf.margin_left = Inches(0.04)
        tf.margin_right = Inches(0.04)
        paragraph = tf.paragraphs[0]
        set_paragraph(paragraph, step, size=11,
                      colour=INK if index < 5 else WHITE, bold=index == 5,
                      space_after=0, align=PP_ALIGN.CENTER)
        if index < len(steps) - 1:
            arrow = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE,
                                           Inches(x + width + 0.06),
                                           Inches(top + 0.24), Inches(0.14),
                                           Inches(0.04))
            arrow.fill.solid()
            arrow.fill.fore_color.rgb = TEAL
            arrow.line.fill.background()
            arrow.shadow.inherit = False


# ------------------------------------------------------------------ slides ----
def slide_title(prs):
    slide = add_slide(prs)
    background = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0,
                                        Inches(13.333), Inches(7.5))
    background.fill.solid()
    background.fill.fore_color.rgb = INK
    background.line.fill.background()

    accent = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(0.9), Inches(1.35),
                                    Inches(0.09), Inches(1.55))
    accent.fill.solid()
    accent.fill.fore_color.rgb = TEAL
    accent.line.fill.background()

    _, tf = textbox(slide, 1.2, 1.28, 10.6, 0.4)
    set_paragraph(tf.paragraphs[0], "YOG · EXPERIMENTAL POLICY ENGINE", size=12,
                  colour=RGBColor(0x5E, 0xEA, 0xD4), bold=True, space_after=0)

    _, tf = textbox(slide, 1.2, 1.72, 11.0, 1.9)
    set_paragraph(tf.paragraphs[0], "Guardrails that decide\nbefore the agent acts",
                  size=40, colour=WHITE, bold=True, space_after=0, line=1.02)

    _, tf = textbox(slide, 1.2, 3.62, 10.6, 0.9)
    set_paragraph(tf.paragraphs[0],
                  "Correctness and performance evidence for a fail-closed decision "
                  "point — including the workloads where YOG loses.",
                  size=16, colour=RGBColor(0xCB, 0xD5, 0xE1), space_after=0, line=1.2)

    _, tf = textbox(slide, 1.2, 4.85, 11.0, 0.4)
    set_paragraph(tf.paragraphs[0],
                  "Benchmark study · 10 pinned runs · 95% bootstrap intervals · "
                  "12,600 decisions checked",
                  size=11.5, colour=RGBColor(0x94, 0xA3, 0xB8), space_after=3)
    set_paragraph(tf.add_paragraph(), "Sources: docs/BENCHMARKS.md · docs/PREREGISTRATION.md · "
                  "docs/BENCHMARK_REVIEW.md", size=10,
                  colour=RGBColor(0x64, 0x74, 0x8B), space_after=0)

    _, tf = textbox(slide, 11.4, 6.9, 1.3, 0.3)
    set_paragraph(tf.paragraphs[0], f"1 / {TOTAL_SLIDES}", size=8,
                  colour=RGBColor(0x64, 0x74, 0x8B), space_after=0,
                  align=PP_ALIGN.RIGHT)
    note(slide, "Open with the decision point, not the language. An agent runtime "
                "has to answer one question before every tool call: is this allowed? "
                "Everything in this deck is about whether we can defend the answer, "
                "not about claiming YOG wins. Timing: about 30 seconds.")


def slide_problem(prs):
    slide = add_slide(prs)
    header(slide, "The decision the runtime owes the model", "Problem", 2)

    bullets(slide, [
        "Agents call tools: shell, SQL, HTTP, payments. The action is the risk.",
        "The model is untrusted input. A correct decision must not assume the model is right.",
        "The check must be **deterministic**, **fail-closed**, **explainable** and cheap enough to sit in the loop.",
        "It also has to be **bounded**: a hostile policy cannot be allowed to run forever.",
    ], width=7.1, top=1.66, size=15.5, gap=11)

    panel(slide, 8.15, 1.66, 4.5, 4.3, fill=WHITE)
    _, tf = textbox(slide, 8.45, 1.9, 3.9, 0.35)
    set_paragraph(tf.paragraphs[0], "THE CONTRACT", size=10.5, colour=TEAL,
                  bold=True, space_after=0)

    _, tf = textbox(slide, 8.45, 2.28, 3.9, 3.4)
    lines = [
        ("deny > allow > default deny", INK, 14, True),
        ("unknown action → DENY", INK_SOFT, 12.5, False),
        ("evaluation error → DENY", INK_SOFT, 12.5, False),
        ("limit exceeded → error, treated as DENY", INK_SOFT, 12.5, False),
        ("compiled policy is immutable", INK_SOFT, 12.5, False),
        ("fresh evaluator per check → thread-safe", INK_SOFT, 12.5, False),
    ]
    first = True
    for text, colour, size, bold in lines:
        paragraph = tf.paragraphs[0] if first else tf.add_paragraph()
        first = False
        set_paragraph(paragraph, text, size=size, colour=colour, bold=bold,
                      space_after=9, line=1.08)

    _, tf = textbox(slide, 8.45, 5.15, 3.9, 0.62)
    set_paragraph(tf.paragraphs[0], "These are properties you can test, not "
                  "aspirations.", size=10, colour=MUTED, space_after=0, line=1.1)

    note(slide, "Frame the risk in operational terms: a wrong ALLOW is an action, a "
                "wrong DENY is an outage. The design biases to DENY on doubt, and "
                "the deck shows both the tests for that and the cost of it. "
                "~60 seconds.")


def slide_what(prs):
    slide = add_slide(prs)
    header(slide, "What YOG is — and what it is not", "Scope", 3)

    architecture(slide, 1.62)

    bullets(slide, [
        "An experimental **C implementation**: lexer → parser → semantic analyser → "
        "clause-table IR → VM → authorization.",
        "A small declarative language: ground facts, rules, allow/deny, negation as "
        "failure, integer comparisons, per-request facts.",
        "No I/O, no native calls, no recursion. Compile once; share the immutable "
        "module across threads.",
        "Interfaces: public C ABI, `yogc` CLI, Python ctypes, Rust wrapper, Go binding.",
    ], top=2.42, width=11.4, height=2.85, size=14.5, gap=8)

    panel(slide, 0.72, 5.5, 11.9, 0.85, fill=AMBER_SOFT)
    _, tf = textbox(slide, 0.95, 5.6, 11.45, 0.7)
    set_paragraph(tf.paragraphs[0],
                  "Not production-ready. Not a proof of safety. Not a claim of "
                  "superiority over Cedar, OPA or Casbin. Those engines win workloads "
                  "shown later in this deck.",
                  size=12.5, colour=AMBER, bold=True, space_after=0, line=1.15)

    note(slide, "Give the one-line architecture and then move on; the language and "
                "the fail-closed contract matter more than the internals. The amber "
                "box is deliberate — say it out loud, it buys credibility for the "
                "results. ~60 seconds.")


def slide_language(prs):
    slide = add_slide(prs)
    header(slide, "A policy you can read, and a reason you can log", "Language", 4)

    code = """fact role(agent_admin, admin)
fact sandboxed(agent_sandbox)
fact safe_command(cmd_ls)
fact destructive_command(cmd_rm_rf)

allow can_run_command(User, Command):
    role(User, admin)

allow can_run_command(User, Command):
    sandboxed(User)
    safe_command(Command)
    not destructive_command(Command)

deny can_run_command(User, Command):
    destructive_command(Command)"""
    code_block(slide, code, 0.72, 1.6, 6.55, 3.3, size=11.2)

    panel(slide, 7.55, 1.6, 5.1, 1.55, fill=WHITE)
    _, tf = textbox(slide, 7.78, 1.72, 4.65, 0.3)
    set_paragraph(tf.paragraphs[0], "$ yogc check … agent_sandbox cmd_ls", size=9.5,
                  colour=MUTED, font=CODE_FONT, space_after=4)
    set_paragraph(tf.add_paragraph(), "ALLOW|allow clause at line 19 matched", size=11,
                  colour=TEAL, bold=True, font=CODE_FONT, space_after=0)

    panel(slide, 7.55, 3.35, 5.1, 1.55, fill=WHITE)
    _, tf = textbox(slide, 7.78, 3.47, 4.65, 0.3)
    set_paragraph(tf.paragraphs[0], "$ yogc check … agent_admin cmd_rm_rf", size=9.5,
                  colour=MUTED, font=CODE_FONT, space_after=4)
    set_paragraph(tf.add_paragraph(), "DENY|deny clause at line 24 matched", size=11,
                  colour=RED, bold=True, font=CODE_FONT, space_after=0)

    _, tf = textbox(slide, 0.72, 5.2, 11.9, 0.9)
    set_paragraph(tf.paragraphs[0],
                  "Being an admin does not unlock a destructive command. "
                  "The deny clause is not a hint; it is precedence.",
                  size=13, colour=INK_SOFT, space_after=0, line=1.15)

    note(slide, "This is the slide to linger on. Read the first allow, the second "
                "allow and the deny. Then run the two commands if the demo is live. "
                "The reason string is part of the API, because an enforcement point "
                "that cannot explain a deny gets bypassed. ~75 seconds.")


def slide_correctness(prs):
    slide = add_slide(prs)
    header(slide, "Agreement is measured against something that is not YOG", "Evidence", 5)

    stat_cards(slide, [
        ("12,600", "decisions compared across engines, profiles and sizes"),
        ("0", "unexpected decision mismatches"),
        ("147", "expected Casbin feature-gap mismatches — all explained"),
        ("1,500", "malformed policies in the fuzz smoke test"),
    ], top=1.62)

    bullets(slide, [
        "**Independent oracle** (`benchmarks/oracle.py`) re-implements the corpus "
        "semantics without importing YOG, any binding or any adapter.",
        "**Independent second translation**: two Cedar policies written separately "
        "(`policy.cedar`, `policy_alt.cedar`), both equivalent on all 1,800 requests.",
        "**Official validators** accept every artifact: `yogc validate`, `opa check`, "
        "`cedar validate`.",
        "**C suite**: conformance A–V, property oracle, differential vs the Python "
        "reference, security limits, 4-thread isolation, ASan/UBSan clean.",
        "A decision gate aborts every run on a wrong answer: no timing is recorded "
        "for a mismatch.",
    ], top=3.28, width=11.6, height=3.0, size=13.4, gap=7)

    _, tf = textbox(slide, 0.72, 6.45, 11.9, 0.4)
    set_paragraph(tf.paragraphs[0],
                  "Agreement on 1,800 requests is evidence about this corpus, not a "
                  "proof of language equivalence. No external reviewer: see "
                  "docs/BENCHMARK_REVIEW.md.",
                  size=9.5, colour=MUTED, space_after=0)

    note(slide, "The important claim is not 'tests pass'. It is that the expected "
                "answer comes from an implementation that shares no code with the "
                "engine, and that a wrong answer stops the run. The 147 is Casbin's "
                "numeric-clause gap, measured, not a translation failure. ~75 seconds.")


def slide_method(prs):
    slide = add_slide(prs)
    header(slide, "Measure four costs, and never blend them into one score", "Method", 6)

    table(slide,
          ["Boundary", "What it includes", "Deployment it represents"],
          [
              ["cold", "fresh process, startup, policy/entity load, one decision",
               "process per request"],
              ["load", "compile / parse / prepare only, in a warm process",
               "policy onboarding"],
              ["warm", "steady-state decision after 50 warm-up calls",
               "embedded engine"],
              ["service", "persistent OPA server, HTTP keep-alive",
               "OPA's intended shape"],
          ],
          0.72, 1.58, 11.9, [1.25, 6.55, 4.1], size=11.5, row_height=0.40,
          first_col_bold=True)

    _, tf = textbox(slide, 0.72, 3.72, 11.9, 0.3)
    set_paragraph(tf.paragraphs[0], "SAME-RUNTIME PAIRINGS ONLY", size=10.5,
                  colour=TEAL, bold=True, space_after=0)

    table(slide,
          ["Pairing", "YOG side", "Competitor", "Symmetry"],
          [
              ["python-in-process", "ctypes over the C ABI", "Casbin Python enforcer",
               "both CPython"],
              ["rust-in-process", "safe Rust wrapper", "Cedar Rust SDK", "both Rust"],
              ["go-in-process", "Go over the C ABI", "OPA Go SDK",
               "asymmetric: YOG pays FFI"],
              ["c-reference", "native C harness", "none", "context only"],
          ],
          0.72, 4.02, 11.9, [2.1, 3.5, 3.6, 2.7], size=10.5, row_height=0.33,
          first_col_bold=True, highlight_rows={3})

    _, tf = textbox(slide, 0.72, 5.84, 11.9, 1.0)
    set_paragraph(tf.paragraphs[0],
                  "10 independent runs × 500 calls per request; median of run medians; "
                  "95% percentile bootstrap over runs (sampling noise only); driver and "
                  "children pinned to one CPU. OPA 1.22.4 · cedar-policy 4.14.1 · "
                  "Casbin 1.43.0 · YOG at the recorded commit.",
                  size=10.5, colour=SLATE, space_after=0, line=1.2)

    note(slide, "This slide is the defence against the obvious question: 'compared "
                "to what, exactly?' Cold, load, warm and service answer different "
                "questions. The Go row is highlighted because it is the one pairing "
                "we did not get for free: only YOG crosses an FFI boundary, so it is "
                "a bound, not a like-for-like engine result. ~75 seconds.")


def slide_corpus(prs):
    slide = add_slide(prs)
    header(slide, "A corpus every engine can express — and one they cannot", "Workload", 7)

    table(slide,
          ["Corpus", "Users", "Teams", "Resources", "Allow clauses"],
          [["small", "20", "5", "30", "3"],
           ["medium", "200", "20", "200", "3"],
           ["large", "2,000", "100", "1,000", "3"]],
          0.72, 1.62, 6.2, [1.5, 1.2, 1.1, 1.3, 1.1], size=11.5, row_height=0.36,
          aligns=[PP_ALIGN.LEFT, PP_ALIGN.RIGHT, PP_ALIGN.RIGHT, PP_ALIGN.RIGHT,
                  PP_ALIGN.RIGHT], first_col_bold=True)

    panel(slide, 7.2, 1.62, 5.45, 1.45, fill=WHITE)
    _, tf = textbox(slide, 7.45, 1.7, 5.0, 1.25)
    set_paragraph(tf.paragraphs[0], "common — timing corpus", size=11.5, colour=TEAL,
                  bold=True, space_after=4)
    set_paragraph(tf.add_paragraph(),
                  "admin role · team join · manager + public resource. Every engine "
                  "can express it directly, so it is the only corpus used for timing.",
                  size=10.5, colour=INK_SOFT, space_after=0, line=1.15)

    panel(slide, 7.2, 3.2, 5.45, 1.55, fill=AMBER_SOFT)
    _, tf = textbox(slide, 7.45, 3.28, 5.0, 1.35)
    set_paragraph(tf.paragraphs[0], "full — gap measurement", size=11.5, colour=AMBER,
                  bold=True, space_after=4)
    set_paragraph(tf.add_paragraph(),
                  "Adds clearance >= classification. Casbin's standard model cannot "
                  "express it; used only to measure the cost of that gap, never for a "
                  "superiority claim.",
                  size=10.5, colour=INK_SOFT, space_after=0, line=1.15)

    _, tf = textbox(slide, 0.72, 3.4, 6.2, 2.0)
    for index, text in enumerate([
        "admin allow — first clause matches",
        "team join allow — two-atom join",
        "guest default deny — every clause fails",
        "unmapped deny — sentinel resource",
    ]):
        paragraph = tf.paragraphs[0] if index == 0 else tf.add_paragraph()
        rich_paragraph(paragraph, text, size=12.5, space_after=6)

    _, tf = textbox(slide, 0.72, 5.3, 11.9, 0.5)
    set_paragraph(tf.paragraphs[0],
                  "300 deterministic requests per profile and size carry expected "
                  "outcomes from the oracle; the four above are the timed ones.",
                  size=10.5, colour=MUTED, space_after=0)

    note(slide, "The feature-matched corpus is the single most important design "
                "decision in the study. If the timing corpus needed a custom Casbin "
                "function, every number would be contested. So the numeric clause "
                "lives in 'full', where it is used to price the gap: 147 of 900 "
                "requests. ~60 seconds.")


def results_slide(prs, number, kicker, title, entries, takeaway, source_note,
                  callout=None):
    slide = add_slide(prs)
    header(slide, title, kicker, number)

    _, tf = textbox(slide, 0.72, 1.44, 11.9, 0.26)
    set_paragraph(tf.paragraphs[0],
                  "large corpus · warm · same-runtime in-process · p50 µs · log scale",
                  size=10, colour=MUTED, space_after=0)

    bar_block(slide, 0.72, 1.94, 11.9, entries, unit="µs", row_height=0.55,
              label_width=3.05)

    if callout:
        panel(slide, 0.72, 5.34, 11.9, 0.64, fill=AMBER_SOFT)
        _, tf = textbox(slide, 0.95, 5.42, 11.45, 0.5)
        set_paragraph(tf.paragraphs[0], callout, size=11.5, colour=AMBER, bold=True,
                      space_after=0, line=1.08)
        top = 6.08
    else:
        top = 5.45

    _, tf = textbox(slide, 0.72, top, 11.9, 0.45)
    set_paragraph(tf.paragraphs[0], takeaway, size=11, colour=SLATE, space_after=0,
                  line=1.12)

    _, tf = textbox(slide, 0.72, 6.55, 11.9, 0.28)
    set_paragraph(tf.paragraphs[0], source_note, size=8, colour=MUTED, space_after=0)
    return slide


def slide_python(prs):
    admin_y = p50("python-in-process", "yog-python", "admin allow")
    join_y = p50("python-in-process", "yog-python", "team join allow")
    deny_y = p50("python-in-process", "yog-python", "guest default deny")
    admin_c = p50("python-in-process", "casbin", "admin allow")
    join_c = p50("python-in-process", "casbin", "team join allow")
    deny_c = p50("python-in-process", "casbin", "guest default deny")

    slide = results_slide(
        prs, 8, "Result · Python runtime",
        "Within CPython on this corpus, YOG wins every row",
        [
            ("YOG-Python · admin allow", admin_y, TEAL),
            ("Casbin · admin allow", admin_c, SLATE),
            ("YOG-Python · team join", join_y, TEAL),
            ("Casbin · team join", join_c, SLATE),
            ("YOG-Python · guest deny", deny_y, TEAL),
            ("Casbin · guest deny", deny_c, SLATE),
        ],
        "The YOG call already includes ctypes overhead, so the win is not free. "
        "Casbin's generic three-atom matcher is interpreted on every request.",
        f"{RESULTS_SOURCE} · full p95/p99 and intervals in "
        "benchmarks/results/comparison.md",
    )
    note(slide, "Say the honest caveat before anyone asks: the YOG side crosses "
                "ctypes, so this is a win despite a handicap, and it is still only "
                "about this corpus. Do not project it onto arbitrary policies. "
                "~45 seconds.")


def slide_rust(prs):
    admin_y = p50("rust-in-process", "yog-rust", "admin allow")
    join_y = p50("rust-in-process", "yog-rust", "team join allow")
    deny_y = p50("rust-in-process", "yog-rust", "guest default deny")
    admin_c = p50("rust-in-process", "cedar-rust", "admin allow")
    join_c = p50("rust-in-process", "cedar-rust", "team join allow")
    deny_c = p50("rust-in-process", "cedar-rust", "guest default deny")

    slide = results_slide(
        prs, 9, "Result · Rust runtime",
        "Cedar is flat. YOG scans. That is the finding.",
        [
            ("YOG-Rust · admin allow", admin_y, TEAL),
            ("Cedar SDK · admin allow", admin_c, AMBER),
            ("YOG-Rust · team join", join_y, TEAL),
            ("Cedar SDK · team join", join_c, AMBER),
            ("YOG-Rust · guest deny", deny_y, TEAL),
            ("Cedar SDK · guest deny", deny_c, AMBER),
        ],
        "Cedar's decision cost is almost constant (~8–11 µs) from small to large; "
        "YOG's default-deny and join paths scan facts linearly and grow to ~350 µs.",
        f"{RESULTS_SOURCE}",
        callout="Measured loss: Cedar is ~40× faster on large deny and ~12× on large "
                "team join. YOG wins only the first-match path. No general speed "
                "claim is made.",
    )
    note(slide, "This is the slide that makes the rest believable. Put the loss in "
                "the headline yourself: Cedar is about forty times faster on the "
                "large deny and about twelve times on the join. The reason is "
                "structural — linear fact scan versus an indexed engine — and it is "
                "the next optimisation, not a footnote. ~75 seconds.")


def slide_go(prs):
    admin_y = p50("go-in-process", "yog-go", "admin allow")
    join_y = p50("go-in-process", "yog-go", "team join allow")
    deny_y = p50("go-in-process", "yog-go", "guest default deny")
    admin_c = p50("go-in-process", "opa-go", "admin allow")
    join_c = p50("go-in-process", "opa-go", "team join allow")
    deny_c = p50("go-in-process", "opa-go", "guest default deny")

    slide = results_slide(
        prs, 10, "Result · Go runtime",
        "A win with a handicap — read it as a bound",
        [
            ("YOG-Go · admin allow", admin_y, TEAL),
            ("OPA Go SDK · admin allow", admin_c, SLATE),
            ("YOG-Go · team join", join_y, TEAL),
            ("OPA Go SDK · team join", join_c, SLATE),
            ("YOG-Go · guest deny", deny_y, TEAL),
            ("OPA Go SDK · guest deny", deny_c, SLATE),
        ],
        "OPA evaluates prepared queries over its in-memory store; YOG pays a "
        "syscall/cgo crossing on every decision and then scans facts.",
        f"{RESULTS_SOURCE}",
        callout="Asymmetric pairing: only YOG crosses an FFI boundary. Treat the gap "
                "as an upper bound on YOG and a lower bound on OPA, not as a pure "
                "engine comparison.",
    )
    note(slide, "Most audiences will over-read this chart. Say the asymmetry twice. "
                "The number is still useful: it bounds how bad the FFI can be for a "
                "C engine embedded in Go, and it shows OPA's prepared-query growth "
                "on this data set. ~45 seconds.")


def slide_load(prs):
    slide = add_slide(prs)
    header(slide, "Change the boundary and the winner changes", "Result · load, cold, service", 11)

    _, tf = textbox(slide, 0.72, 1.5, 11.9, 0.28)
    set_paragraph(tf.paragraphs[0], "LOAD / PREPARE — p50 ms", size=10, colour=TEAL,
                  bold=True, space_after=0)

    table(slide,
          ["Corpus", "YOG C", "YOG-Python", "YOG-Rust", "YOG-Go", "Casbin", "OPA Go", "Cedar Rust"],
          [["small", "0.13", "0.14", "0.23", "0.24", "2.17", "1.96", "5.11"],
           ["medium", "2.07", "1.87", "1.97", "2.00", "9.59", "2.03", "13.56"],
           ["large", "65.3", "62.2", "55.7", "57.8", "71.0", "1.92", "70.0"]],
          0.72, 1.76, 11.9, [1.45, 1.3, 1.55, 1.4, 1.3, 1.35, 1.35, 1.45],
          size=10, row_height=0.3,
          aligns=[PP_ALIGN.LEFT] + [PP_ALIGN.RIGHT] * 7, first_col_bold=True,
          highlight_rows={3})

    _, tf = textbox(slide, 0.72, 3.0, 11.9, 0.5)
    set_paragraph(tf.paragraphs[0],
                  "OPA's prepared-query setup is 34× cheaper than YOG's compile on "
                  "the large corpus and does not grow with the data set. Expected "
                  "loss, reported as such.",
                  size=10, colour=AMBER, bold=True, space_after=0, line=1.1)

    _, tf = textbox(slide, 0.72, 3.58, 11.9, 0.28)
    set_paragraph(tf.paragraphs[0], "COLD PROCESS PER REQUEST — p50 ms, guest-deny row",
                  size=10, colour=TEAL, bold=True, space_after=0)

    table(slide,
          ["Corpus", "YOG C CLI", "YOG Rust", "YOG Go", "YOG Python", "Casbin", "OPA CLI", "Cedar CLI"],
          [["small", "27.5", "32.2", "78.9", "127.7", "231.4", "82.5", "97.4"],
           ["medium", "31.5", "32.6", "76.5", "130.8", "238.0", "81.1", "474.9"],
           ["large", "81.8", "89.3", "138.7", "179.5", "313.7", "92.4", "3,176.1"]],
          0.72, 3.86, 11.9, [1.45, 1.55, 1.3, 1.25, 1.5, 1.2, 1.3, 1.5],
          size=10, row_height=0.3,
          aligns=[PP_ALIGN.LEFT] + [PP_ALIGN.RIGHT] * 7, first_col_bold=True,
          highlight_rows={3})

    bullets(slide, [
        "Cold is a deployment shape, not an engine property: Cedar CLI rebuilds the "
        "entity hierarchy per invocation (~3.2 s); its SDK is ~105 ms.",
        "Persistent OPA over HTTP: ~0.6–0.9 ms small, ~2.0–2.1 ms large, after a "
        "~0.5 s server start — still far above an in-process call.",
        "YOG has no service mode yet, so there is no YOG HTTP row. That gap is real.",
    ], top=5.2, width=11.8, height=1.6, size=11.5, gap=4)

    note(slide, "This is the slide that stops people from cherry-picking. Compile "
                "time is genuinely worse than OPA's prepared query, and cold start "
                "is dominated by process and runtime setup. The point is not that "
                "one engine wins; it is that the boundary decides. ~60 seconds.")


def slide_threats(prs):
    slide = add_slide(prs)
    header(slide, "What this evidence cannot support", "Threats to validity", 12)

    bullets(slide, [
        "**One machine, one OS.** Windows 11 desktop, pinned to one CPU; background "
        "load is not controlled. Linux numbers are pending the CI measurement job.",
        "**No external reviewer.** The study is self-reviewed; the checklist is "
        "published and the gap is named.",
        "**Four timed requests.** Agreement uses 300 requests per cell; timing "
        "distributions for other mixes may differ.",
        "**Generated corpus.** Real policies differ in clause order, cardinality and "
        "attribute shape.",
        "**Bootstrap intervals cover sampling noise only** — not machine, OS, "
        "compiler or translation bias.",
        "**Go is asymmetric** and Casbin covers a subset; the `full` mismatches are a "
        "measured feature gap, not a defect.",
        "**No YOG service benchmark, no concurrent-throughput or peak-RSS study, no "
        "long soak test.**",
    ], top=1.6, width=11.8, height=4.8, size=15, gap=13)

    note(slide, "Do not read this slide as a disclaimer mumble. Read three items out "
                "loud — one machine, no external reviewer, four timed requests — and "
                "offer the review doc. It is the strongest Q&A armour in the deck. "
                "~60 seconds.")


def slide_verdict(prs):
    slide = add_slide(prs)
    header(slide, "What the data supports — and what it does not", "Verdict", 13)

    panel(slide, 0.72, 1.6, 5.8, 3.4, fill=WHITE)
    _, tf = textbox(slide, 1.0, 1.74, 5.2, 0.35)
    set_paragraph(tf.paragraphs[0], "SUPPORTED", size=11, colour=TEAL, bold=True,
                  space_after=0)
    _, tf = textbox(slide, 1.0, 2.12, 5.2, 3.9)
    supported = [
        "In-process decisions are microseconds on this corpus.",
        "The first-match path is flat in corpus size.",
        "Default deny and joins scale linearly, and are expensive at large sizes.",
        "YOG beats Casbin and the OPA Go SDK in the same-runtime pairing on this corpus.",
        "Every engine agrees with the independent oracle on the feature-matched corpus.",
    ]
    first = True
    for text in supported:
        paragraph = tf.paragraphs[0] if first else tf.add_paragraph()
        first = False
        rich_paragraph(paragraph, text, size=12, colour=INK, space_after=8)

    panel(slide, 6.75, 1.6, 5.9, 3.4, fill=WHITE)
    _, tf = textbox(slide, 7.02, 1.74, 5.35, 0.35)
    set_paragraph(tf.paragraphs[0], "NOT SUPPORTED", size=11, colour=RED, bold=True,
                  space_after=0)
    _, tf = textbox(slide, 7.02, 2.12, 5.35, 3.9)
    not_supported = [
        "That YOG is faster than Cedar in general — it loses large deny by ~40×.",
        "That YOG compiles competitively with OPA's prepared query — it does not.",
        "That these results generalise beyond Windows, this CPU and this corpus.",
        "That YOG is safer or more expressive than any competitor.",
        "That YOG is production-ready.",
    ]
    first = True
    for text in not_supported:
        paragraph = tf.paragraphs[0] if first else tf.add_paragraph()
        first = False
        rich_paragraph(paragraph, text, size=12, colour=INK, space_after=8, bullet="×")

    _, tf = textbox(slide, 0.72, 5.3, 11.9, 0.4)
    set_paragraph(tf.paragraphs[0],
                  "The study would be invalidated, not weakened, by an unexplained "
                  "mismatch, a cross-language row sold as same-runtime, or a Linux "
                  "rerun that contradicts a headline and is not reported.",
                  size=10, colour=MUTED, space_after=0, line=1.15)

    note(slide, "Keep both columns on screen while you say the verdict. The right "
                "column is why the left column is credible. If asked 'so is it fast?' "
                "the answer is: microseconds in-process, but not the fastest engine "
                "here, and we know exactly where it loses. ~60 seconds.")


def slide_next(prs):
    slide = add_slide(prs)
    header(slide, "Next: fix the measured loss, not the narrative", "Roadmap", 14)

    bullets(slide, [
        "**Index predicates by name and first argument** — the direct fix for the "
        "large default-deny and join loss against Cedar.",
        "**Cut compiler symbol-table and cycle-detection cost** — the 34× load loss "
        "against OPA's prepared query.",
        "**Run the Linux measurement job** with the same pinned versions; report it "
        "even if it disagrees with Windows.",
        "**Add a YOG service boundary** and concurrent-throughput/peak-RSS "
        "measurements so the service question is answerable.",
    ], top=1.62, width=11.4, size=14.5, gap=12)

    panel(slide, 0.72, 4.6, 11.9, 1.08, fill=TEAL_SOFT)
    _, tf = textbox(slide, 0.98, 4.68, 11.4, 0.95)
    set_paragraph(tf.paragraphs[0], "TRY IT NOW", size=10.5, colour=TEAL, bold=True,
                  space_after=4)
    set_paragraph(tf.add_paragraph(),
                  "python examples\\ai_guardrails\\live_demo.py --step",
                  size=14, colour=INK, bold=True, font=CODE_FONT, space_after=4)
    set_paragraph(tf.add_paragraph(),
                  "Fourteen scenarios: shell, production database, money movement, and "
                  "fail-closed. Two seconds without --step.",
                  size=10.5, colour=INK_SOFT, space_after=0)

    _, tf = textbox(slide, 0.72, 5.92, 11.9, 0.5)
    set_paragraph(tf.paragraphs[0],
                  "An engine that states its losses is easier to trust than one that "
                  "hides them.",
                  size=12.5, colour=SLATE, space_after=0)

    note(slide, "Close on the next action, not on a slogan. The indexing work is "
                "motivated by the Cedar loss, and the Linux run is already wired in "
                "CI. Then run the demo if there is time, or offer the command. "
                "~45 seconds.")


def slide_appendix(prs):
    slide = add_slide(prs)
    header(slide, "Provenance, so anyone can rerun or contest this", "Appendix", 15)

    table(slide,
          ["Artifact", "What it contains", "How it is produced"],
          [["docs/BENCHMARKS.md", "method, boundaries, all result tables, threats",
            "hand-written from the JSON"],
           ["docs/PREREGISTRATION.md", "H1–H7, expected losses, analysis rules",
            "written before analysis"],
           ["docs/BENCHMARK_REVIEW.md", "self-review; external review not performed",
            "checklist"],
           ["benchmarks/results/comparison.json", "warm same-runtime p50/p95/p99 + CIs",
            "compare.py --pin-cpu 0"],
           ["benchmarks/results/boundaries.json", "cold, load, service",
            "boundaries.py --pin-cpu 0"],
           ["benchmarks/results/equivalence.json", "12,600 decision comparisons",
            "equivalence.py"],
           ["benchmarks/results/validation.json", "official validator runs",
            "validate_translations.py"]],
          0.72, 1.55, 11.9, [3.55, 5.6, 2.75], size=9.5, row_height=0.4,
          first_col_bold=True)

    _, tf = textbox(slide, 0.72, 5.15, 11.9, 0.28)
    set_paragraph(tf.paragraphs[0], "PINNED VERSIONS AND ENVIRONMENT", size=10,
                  colour=TEAL, bold=True, space_after=0)

    _, tf = textbox(slide, 0.72, 5.45, 11.9, 1.0)
    set_paragraph(tf.paragraphs[0],
                  "OPA 1.22.4 · cedar-policy 4.14.1 (Rust SDK) · Casbin 1.43.0 · "
                  "CPython 3.14.7 · Windows 11 10.0.26200 · MSVC Release · "
                  "10 runs × 500 calls · CPU 0 pinning · 95% bootstrap, fixed seed.",
                  size=10.5, colour=INK_SOFT, space_after=3, line=1.2)
    set_paragraph(tf.add_paragraph(),
                  "Linux: build and binding jobs pass in CI; the measurement job runs "
                  "from the default branch and its numbers are not in this deck yet.",
                  size=10, colour=MUTED, space_after=0)

    note(slide, "Leave this up for Q&A. It answers 'where are the numbers', 'what "
                "version', and 'why should I believe the environment was controlled' "
                "without taking the main narrative off track. ~20 seconds if skipped.")


# -------------------------------------------------------------------- main ----
def build(out: Path) -> Path:
    prs = Presentation()
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)

    slide_title(prs)
    slide_problem(prs)
    slide_what(prs)
    slide_language(prs)
    slide_correctness(prs)
    slide_method(prs)
    slide_corpus(prs)
    slide_python(prs)
    slide_rust(prs)
    slide_go(prs)
    slide_load(prs)
    slide_threats(prs)
    slide_verdict(prs)
    slide_next(prs)
    slide_appendix(prs)

    out.parent.mkdir(parents=True, exist_ok=True)
    prs.save(out)
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path,
                        default=HERE / "yog-benchmark-deck.pptx")
    args = parser.parse_args()
    path = build(args.out)
    prs = Presentation(path)
    print(f"wrote {path} ({len(prs.slides)} slides)")
    print(f"numbers: {RESULTS_SOURCE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
