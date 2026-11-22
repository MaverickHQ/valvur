"""R44.11 (D81ac): the image holds the Alpine packages a list names, and no other.

The self-healing spec's Requirement 23.3. `.github/image-packages.txt` names every Alpine
package of the image, one a line. The image is held to exactly that list, so a base update
that adds a package is seen, and one that valvur does not load is taken out on purpose. The
packages are read from `/lib/apk/db/installed`, which is what the image gate's Trivy reads.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
LIST = REPO / ".github" / "image-packages.txt"
_READ = ("import json; print(json.dumps(sorted(line[2:].strip() for line in "
         "open('/lib/apk/db/installed') if line.startswith('P:'))))")


def listed() -> list[str]:
    return LIST.read_text(encoding="utf-8").split()


def test_the_list_names_each_package_once_in_order():
    names = listed()

    assert names == sorted(set(names))
    assert LIST.read_text(encoding="utf-8") == "".join(f"{name}\n" for name in names)


@pytest.mark.e2e
def test_the_image_holds_exactly_the_packages_the_list_names():
    from valvur.engine_host import IMAGE

    said = subprocess.run(["docker", "run", "--rm", IMAGE, "python3", "-c", _READ],
                          capture_output=True, text=True, check=True).stdout
    held = json.loads(said)

    assert sorted(set(held) - set(listed())) == [], "in the image, and not on the list"
    assert sorted(set(listed()) - set(held)) == [], "on the list, and not in the image"


def test_security_md_says_where_a_removed_packages_bytes_remain():
    text = " ".join((REPO / "SECURITY.md").read_text(encoding="utf-8").split())

    assert ".github/image-packages.txt" in text
    assert "bytes remain in the base image's layer" in text
