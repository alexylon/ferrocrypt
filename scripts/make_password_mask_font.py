#!/usr/bin/env python3
"""Build the font the desktop app draws masked passwords with.

A masked password field shows one "●" (U+25CF) per character, and Inter draws
that glyph much larger than the macOS system font, which the layout was tuned
against. This font holds only a smaller "●". Its line metrics are Inter's, so
the text cursor in a masked field keeps the height it has elsewhere.

Writes ferrocrypt-desktop/fonts/PasswordMask.ttf. A given fontTools release
writes the same bytes on every run; the committed file was built with
fontTools 4.55.3 (`pip install fonttools==4.55.3`).
"""

from datetime import datetime
from pathlib import Path

from fontTools.fontBuilder import FontBuilder
from fontTools.pens.cu2quPen import Cu2QuPen
from fontTools.pens.ttGlyphPen import TTGlyphPen
from fontTools.ttLib import TTFont

FONTS = Path(__file__).resolve().parent.parent / "ferrocrypt-desktop" / "fonts"
INTER = FONTS / "Inter-Regular.ttf"
OUTPUT = FONTS / "PasswordMask.ttf"

# Must match `Theme.password-mask-font` in ferrocrypt-desktop/ui/app.slint; a
# desktop test checks it.
FAMILY = "FerroCrypt Password Mask"
STYLE = "Regular"

# At the app's 11.5 px body size, a dot 5.3 px wide every 7.7 px: what the
# macOS system font draws at the 12.5 px the layout was tuned with.
DOT_DIAMETER_EM = 0.46
DOT_ADVANCE_EM = 0.67

MASK_CHARACTER = 0x25CF
# Bezier handle length for a quarter circle of radius 1.
KAPPA = 0.5522847498
# The largest distance cu2qu may put between a cubic and its quadratic copy.
MAX_ERROR_UNITS = 1.0
# A fixed date for the `head` table, which counts seconds from 1904, so every
# run writes the same bytes.
TIMESTAMP = int((datetime(2026, 1, 1) - datetime(1904, 1, 1)).total_seconds())


def circle_glyph(cx, cy, r):
    """A filled circle as one clockwise TrueType contour."""
    pen = TTGlyphPen(None)
    cubic = Cu2QuPen(pen, MAX_ERROR_UNITS, reverse_direction=False)
    k = r * KAPPA
    cubic.moveTo((cx, cy + r))
    cubic.curveTo((cx + k, cy + r), (cx + r, cy + k), (cx + r, cy))
    cubic.curveTo((cx + r, cy - k), (cx + k, cy - r), (cx, cy - r))
    cubic.curveTo((cx - k, cy - r), (cx - r, cy - k), (cx - r, cy))
    cubic.curveTo((cx - r, cy + k), (cx - k, cy + r), (cx, cy + r))
    cubic.closePath()
    return pen.glyph()


def main():
    inter = TTFont(INTER)
    upm = inter["head"].unitsPerEm
    os2 = inter["OS/2"]
    hhea = inter["hhea"]
    inter_dot = inter["glyf"][inter.getBestCmap()[MASK_CHARACTER]]
    # The same height above the baseline as Inter's own dot.
    center_y = round((inter_dot.yMin + inter_dot.yMax) / 2)

    advance = round(DOT_ADVANCE_EM * upm)
    radius = round(DOT_DIAMETER_EM * upm / 2)
    dot = circle_glyph(advance // 2, center_y, radius)

    fb = FontBuilder(upm, isTTF=True)
    fb.font.recalcTimestamp = False
    fb.setupGlyphOrder([".notdef", "dot"])
    fb.setupCharacterMap({MASK_CHARACTER: "dot"})
    fb.setupGlyf({".notdef": TTGlyphPen(None).glyph(), "dot": dot})
    fb.setupHorizontalMetrics(
        {".notdef": (advance, 0), "dot": (advance, advance // 2 - radius)}
    )
    fb.setupHorizontalHeader(
        ascent=hhea.ascent, descent=hhea.descent, lineGap=hhea.lineGap
    )
    fb.setupOS2(
        version=os2.version,
        sTypoAscender=os2.sTypoAscender,
        sTypoDescender=os2.sTypoDescender,
        sTypoLineGap=os2.sTypoLineGap,
        usWinAscent=os2.usWinAscent,
        usWinDescent=os2.usWinDescent,
        sxHeight=os2.sxHeight,
        sCapHeight=os2.sCapHeight,
        fsSelection=os2.fsSelection,
        usWeightClass=os2.usWeightClass,
    )
    fb.setupNameTable(
        {
            "familyName": FAMILY,
            "styleName": STYLE,
            "uniqueFontIdentifier": f"{FAMILY} {STYLE}",
            "fullName": f"{FAMILY} {STYLE}",
            "psName": FAMILY.replace(" ", "") + "-" + STYLE,
            "version": "Version 1.000",
            "licenseDescription": "Part of FerroCrypt, licensed under GPL-3.0-only.",
        }
    )
    fb.setupPost()
    fb.font["head"].created = TIMESTAMP
    fb.font["head"].modified = TIMESTAMP
    fb.save(OUTPUT)
    print(OUTPUT)


if __name__ == "__main__":
    main()
