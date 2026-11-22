"""R44.13: what the heal may write, held in one place (Requirements 8.1 and 19.7).

The lock's heal writes the Checkov lock and the CHANGELOG. The image's heal writes the
Dockerfile, inside its envelope, and the CHANGELOG. The weekly Checkov plan also writes the
requirement, and is never merged by the policy. Nothing else: each policy's list of files
is the list its `apply` writes, and neither script names another path to write.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))

import heal  # noqa: E402
import heal_policy  # noqa: E402
import image_heal  # noqa: E402


def test_each_policy_admits_exactly_the_files_its_heal_writes():
    assert heal_policy.ENVELOPE == ("requirements-checkov.txt", "CHANGELOG.md")
    assert (heal_policy.DOCKERFILE, heal.CHANGELOG) == ("Dockerfile", "CHANGELOG.md")
    assert heal.REQUIREMENT not in heal_policy.ENVELOPE, "a Checkov plan is the owner's to land"


def test_neither_script_writes_a_path_it_was_not_given():
    """Every write is to `--out`, or into the scratch copy the recipe runs in. Neither
    script opens a file to write, copies into the tree, or writes bytes anywhere else."""
    for script in ("heal.py", "image_heal.py"):
        source = (REPO / "scripts" / script).read_text(encoding="utf-8")
        writes = re.findall(r"^\s*(\S.*\.write_text\(.*)$", source, re.M)
        assert writes, script
        for line in writes:
            assert line.startswith(("(args.out", "args.out", "(copy /")), (script, line)
        assert not re.search(r"\.write_bytes\(|\bopen\([^)]*[\"']w|os\.rename|\.unlink\(", source)
        assert re.findall(r"shutil\.\w+\(([^)]*)\)", source) in (
            [], ["tree / name, copy / name"]), script


def test_the_one_mention_of_the_policy_file_is_in_words_for_the_owner():
    source = (REPO / "scripts" / "heal.py").read_text(encoding="utf-8")

    mentions = [line for line in source.splitlines() if ".security-scan.toml" in line]
    assert len(mentions) == 1 and "does not write it" in " ".join(
        source[source.index(mentions[0]):].split()[:40])
    assert ".security-scan.toml" not in (REPO / "scripts" / "image_heal.py").read_text()


def test_the_envelope_is_the_only_part_of_the_dockerfile_apply_can_change():
    real = (REPO / "Dockerfile").read_text(encoding="utf-8")
    plan = {"raises": [{"arg": "ALPINE_RAISE", "entry": "tzdata=2026z-r9", "package": "tzdata",
                        "answers": ["CVE-0"]}], "drops": [], "base": None, "go": None}

    assert image_heal.differs_outside(real, image_heal.apply(plan, real)) == ""
