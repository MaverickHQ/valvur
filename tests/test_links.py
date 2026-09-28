"""R7.3: no Markdown file in the repository links to a file that is not there.

The closed reviews, the gates and the council's files moved to `docs/history/`,
and every document that pointed at them has to point at where they went. Every
tracked Markdown file is read, the fixtures' planted repositories apart; a link
with a scheme or only an anchor is not a file, and code, fenced or inline, is not
prose.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from urllib.parse import unquote

REPO = Path(__file__).resolve().parent.parent
LINK = re.compile(r"\[[^\]]*\]\(<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\)")
FENCE = re.compile(r"^(```|~~~).*?^\1", re.S | re.M)
INLINE = re.compile(r"`[^`\n]+`")


def _markdown() -> list[Path]:
    listed = subprocess.run(["git", "ls-files", "*.md"], cwd=REPO, capture_output=True,
                            text=True, check=True).stdout.split()
    return [REPO / name for name in listed if not name.startswith("tests/fixtures/")]


def _targets(path: Path) -> list[str]:
    text = INLINE.sub("", FENCE.sub("", path.read_text(encoding="utf-8")))
    found = []
    for match in LINK.finditer(text):
        target = match.group(1)
        if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", target) or target.startswith("#"):
            continue
        found.append(unquote(target.split("#", 1)[0]))
    return [t for t in found if t]


def test_every_relative_link_in_every_markdown_file_resolves():
    broken = []
    for path in _markdown():
        for target in _targets(path):
            resolved = REPO / target.lstrip("/") if target.startswith("/") \
                else path.parent / target
            if not resolved.exists():
                broken.append(f"{path.relative_to(REPO)} -> {target}")

    assert not broken, "\n".join(broken)
