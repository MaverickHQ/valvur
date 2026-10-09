"""Render the repository's social preview (R39.4, D78d).

    uv run python scripts/social_preview.py

Renders `docs/social-preview.svg` to `docs/social-preview.png` at 1280 by 640 with a
headless Chrome, the one SVG renderer a Mac and GitHub's Linux runners both have to hand.
GitHub's API cannot set a social preview, so the owner uploads the PNG in Settings →
General (tasks.md §8). Standard library only.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SVG = REPO / "docs" / "social-preview.svg"
PNG = REPO / "docs" / "social-preview.png"
#: Where a Chrome or Chromium is found: `CHROME` first, then the usual names.
CANDIDATES = ("google-chrome", "chromium", "chromium-browser",
              "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")


def chrome() -> str:
    for name in (os.environ.get("CHROME", ""), *CANDIDATES):
        found = name and (shutil.which(name) or (Path(name).is_file() and name))
        if found:
            return str(found)
    raise SystemExit("no Chrome or Chromium found; set CHROME to one")


def main() -> int:
    subprocess.run(  # noqa: S603 — a browser this machine has, fixed arguments
        [chrome(), "--headless=new", "--disable-gpu", "--hide-scrollbars",
         "--force-device-scale-factor=1", "--window-size=1280,640",
         f"--screenshot={PNG}", SVG.as_uri()],
        check=True, capture_output=True)
    print(f"{PNG.relative_to(REPO)}: {PNG.stat().st_size:,} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
