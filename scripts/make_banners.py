#!/usr/bin/env python3
"""Draw the banners from assets/banner.html.

Renders the page with headless Chrome at twice its size into the Snap Store's
featured banner, assets/snap_banner.png (3000 by 1000), and saves the same
picture with rounded corners as assets/readme_banner.png, for the top of the
README. The page gets the desktop app's icon and Inter fonts beside it.

Needs Google Chrome (or CHROME set to another Chrome), ImageMagick, and an
internet connection for JetBrains Mono, which the page loads from Google
Fonts. The image shown when ferrocrypt.app is shared is drawn from the same
page in the ferrocrypt-app repository.

    python3 scripts/make_banners.py
"""

import os
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ASSETS = ROOT / "assets"
PAGE = ASSETS / "banner.html"
SNAP_BANNER = ASSETS / "snap_banner.png"
README_BANNER = ASSETS / "readme_banner.png"
DESKTOP = ROOT / "ferrocrypt-desktop"
ICON = DESKTOP / "assets" / "app_icon.png"
INTER = [DESKTOP / "fonts" / f"Inter-{style}.ttf" for style in ("Regular", "SemiBold", "Bold")]
CHROME = os.environ.get("CHROME", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")

# The page's size, in CSS pixels, and the banners' pixels per CSS pixel.
WIDTH, HEIGHT = 1500, 500
SCALE = 2
# The README banner's corners' radius, in CSS pixels.
CORNER_RADIUS = 20
# Long enough for the fonts to load before Chrome takes the picture.
LOAD_MS = 5000


def render(page, png):
    subprocess.run(
        [CHROME, "--headless=new", "--disable-gpu", "--hide-scrollbars",
         "--allow-file-access-from-files", f"--user-data-dir={page.parent / 'profile'}",
         f"--window-size={WIDTH},{HEIGHT}", f"--force-device-scale-factor={SCALE}",
         f"--virtual-time-budget={LOAD_MS}", f"--screenshot={png}", page.as_uri()],
        check=True, capture_output=True,
    )


def round_corners(shot, radius, png):
    """Save the picture with its corners cut round and transparent, and without
    timestamps, so making it again gives the same file."""
    width, height = struct.unpack(">II", shot.read_bytes()[16:24])
    subprocess.run(
        ["magick", str(shot), "-alpha", "set",
         "(", "-size", f"{width}x{height}", "xc:none", "-fill", "white", "-draw",
         f"roundrectangle 0,0 {width - 1},{height - 1} {radius},{radius}", ")",
         "-compose", "DstIn", "-composite",
         "-define", "png:exclude-chunks=date,time", str(png)],
        check=True,
    )


def main():
    if not Path(CHROME).exists():
        raise SystemExit(f"Chrome wasn't found at {CHROME}; set CHROME to its path")
    if not shutil.which("magick"):
        raise SystemExit("ImageMagick's magick wasn't found")

    with tempfile.TemporaryDirectory(prefix="ferrocrypt-banner-") as tmp:
        work = Path(tmp)
        page = work / "banner.html"
        shutil.copy(PAGE, page)
        shutil.copy(ICON, work / "icon.png")

        for font in INTER:
            shutil.copy(font, work / font.name)

        render(page, SNAP_BANNER)
        print(f"Made {SNAP_BANNER.relative_to(ROOT)}")

    round_corners(SNAP_BANNER, CORNER_RADIUS * SCALE, README_BANNER)
    print(f"Made {README_BANNER.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
