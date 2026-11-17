#!/usr/bin/env python3
"""Render a rough PNG preview of a .pptx without PowerPoint or LibreOffice.

Development aid, not a faithful renderer: draws shape fills, outlines, text with
wrapping, and tables, so overflow and overlap are visible when no Office suite
is installed. Fonts are matched by name to files in C:/Windows/Fonts.

Usage:
    python presentation/preview_deck.py [deck.pptx] [--out DIR] [--scale 1.6]
"""
from __future__ import annotations

import argparse
import re
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont
from pptx import Presentation
from pptx.enum.shapes import MSO_SHAPE, MSO_SHAPE_TYPE
from pptx.enum.text import MSO_ANCHOR, PP_ALIGN

HERE = Path(__file__).resolve().parent
FONT_DIR = Path("C:/Windows/Fonts")
EMU_PER_INCH = 914400

FONT_FILES = {
    ("Segoe UI", False): ["segoeui.ttf", "arial.ttf", "DejaVuSans.ttf"],
    ("Segoe UI", True): ["segoeuib.ttf", "arialbd.ttf", "DejaVuSans-Bold.ttf"],
    ("Consolas", False): ["consola.ttf", "cour.ttf", "DejaVuSansMono.ttf"],
    ("Consolas", True): ["consolab.ttf", "courbd.ttf", "DejaVuSansMono-Bold.ttf"],
}


def font_for(name: str, bold: bool, size_pt: float, scale: float):
    candidates = FONT_FILES.get((name, bold)) or FONT_FILES[("Segoe UI", bold)]
    pixels = max(6, int(round(size_pt * scale * 96 / 72)))
    for candidate in candidates:
        path = FONT_DIR / candidate
        if path.exists():
            return ImageFont.truetype(str(path), pixels)
    return ImageFont.load_default(size=max(6, pixels // 2))


def rgb_of(colour_format):
    try:
        if colour_format.type == 1:
            rgb = colour_format.rgb
            return (rgb[0], rgb[1], rgb[2])
    except (AttributeError, ValueError, TypeError):
        pass
    return None


def fill_of(shape):
    try:
        if shape.fill.type == 1:
            return rgb_of(shape.fill.fore_color)
    except (AttributeError, ValueError, TypeError):
        pass
    return None


def outline_of(shape):
    try:
        if shape.line.fill.type == 1:
            return rgb_of(shape.line.color)
    except (AttributeError, ValueError, TypeError):
        pass
    return None


def runs_of(paragraph, scale):
    runs = []
    for run in paragraph.runs:
        if not run.text:
            continue
        size = run.font.size.pt if run.font.size else 15
        colour = rgb_of(run.font.color) if run.font.color and run.font.color.type == 1 else None
        runs.append((run.text,
                     font_for(run.font.name or "Segoe UI", bool(run.font.bold),
                              size, scale),
                     colour or (11, 27, 43),
                     size))
    return runs


def wrap(draw, runs, max_width):
    tokens = []
    for text, font, colour, size in runs:
        for part in re.split(r"(\s+)", text):
            if part:
                tokens.append((part, font, colour, size, part.isspace()))

    lines, current, width = [], [], 0.0
    for token in tokens:
        text, font, colour, size, is_space = token
        if text == "\n":
            lines.append((width, current))
            current, width = [], 0.0
            continue
        token_width = draw.textlength(text, font=font)
        if is_space:
            current.append(token)
            width += token_width
            continue
        if current and width + token_width > max_width:
            while current and current[-1][4]:
                width -= draw.textlength(current[-1][0], font=current[-1][1])
                current.pop()
            lines.append((width, current))
            current, width = [], 0.0
        current.append(token)
        width += token_width
    if current:
        lines.append((width, current))
    return lines


def draw_paragraphs(draw, shape, scale, px):
    tf = shape.text_frame
    left = shape.left * px + (tf.margin_left or 0) * px
    width = shape.width * px - ((tf.margin_left or 0) + (tf.margin_right or 0)) * px
    top = shape.top * px + (tf.margin_top or 0) * px

    prepared = []
    total_height = 0.0
    for paragraph in tf.paragraphs:
        runs = runs_of(paragraph, scale)
        if not runs:
            prepared.append((paragraph, [], 0.0))
            total_height += 6 * scale
            continue
        lines = wrap(draw, runs, max(1.0, width))
        line_height = max(run[3] for run in runs) * scale * 96 / 72 * 1.26
        prepared.append((paragraph, lines, line_height))
        total_height += line_height * len(lines)
        if paragraph.space_after:
            total_height += paragraph.space_after.pt * scale * 96 / 72

    anchor = tf.vertical_anchor
    if anchor == MSO_ANCHOR.MIDDLE or (anchor is None and shape.shape_type == MSO_SHAPE_TYPE.AUTO_SHAPE):
        top = shape.top * px + (shape.height * px - total_height) / 2

    y = top
    for paragraph, lines, line_height in prepared:
        if not lines:
            y += 6 * scale
            continue
        for line_width, pieces in lines:
            offset = 0.0
            if paragraph.alignment == PP_ALIGN.CENTER:
                offset = max(0.0, (width - line_width) / 2)
            elif paragraph.alignment == PP_ALIGN.RIGHT:
                offset = max(0.0, width - line_width)
            x = left + offset
            for text, font, colour, _, _ in pieces:
                draw.text((x, y), text, font=font, fill=colour)
                x += draw.textlength(text, font=font)
            y += line_height
        if paragraph.space_after:
            y += paragraph.space_after.pt * scale * 96 / 72


def draw_table(draw, shape, scale, px):
    table = shape.table
    left = shape.left * px
    y = shape.top * px
    for row in table.rows:
        height = row.height * px
        x = left
        for column_index, cell in enumerate(row.cells):
            width = table.columns[column_index].width * px
            fill = fill_of(cell) or (255, 255, 255)
            draw.rectangle([x, y, x + width, y + height], fill=fill,
                           outline=(226, 232, 240), width=1)
            text = cell.text.strip()
            if text:
                paragraph = cell.text_frame.paragraphs[0]
                runs = runs_of(paragraph, scale)
                if runs:
                    font = runs[0][1]
                    text_width = draw.textlength(text, font=font)
                    tx = x + 0.07 * 96 * scale
                    if paragraph.alignment == PP_ALIGN.RIGHT:
                        tx = x + width - text_width - 0.07 * 96 * scale
                    ty = y + (height - runs[0][3] * scale * 96 / 72) / 2 - 1
                    draw.text((tx, ty), text, font=font, fill=runs[0][2])
            x += width
        y += height


def render(deck: Path, out_dir: Path, scale: float) -> list[Path]:
    prs = Presentation(deck)
    px = scale * 96 / EMU_PER_INCH
    width = int(prs.slide_width * px)
    height = int(prs.slide_height * px)
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = []

    for index, slide in enumerate(prs.slides, start=1):
        image = Image.new("RGB", (width, height), (255, 255, 255))
        draw = ImageDraw.Draw(image)
        for shape in slide.shapes:
            if shape.has_table:
                draw_table(draw, shape, scale, px)
                continue
            box = [shape.left * px, shape.top * px,
                   (shape.left + shape.width) * px, (shape.top + shape.height) * px]
            fill, outline = fill_of(shape), outline_of(shape)
            if fill or outline:
                rounded = False
                try:
                    rounded = shape.auto_shape_type == MSO_SHAPE.ROUNDED_RECTANGLE
                except (AttributeError, ValueError):
                    pass
                if rounded:
                    draw.rounded_rectangle(box, radius=6 * scale, fill=fill, outline=outline)
                else:
                    draw.rectangle(box, fill=fill, outline=outline)
            if shape.has_text_frame and shape.text_frame.text.strip():
                draw_paragraphs(draw, shape, scale, px)

        path = out_dir / f"slide-{index:02d}.png"
        image.save(path)
        paths.append(path)
    return paths


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("deck", nargs="?", type=Path,
                        default=HERE / "yog-benchmark-deck.pptx")
    parser.add_argument("--out", type=Path, default=HERE / "preview")
    parser.add_argument("--scale", type=float, default=1.6)
    args = parser.parse_args()
    for path in render(args.deck, args.out, args.scale):
        print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
