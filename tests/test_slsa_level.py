"""R52.4: `SECURITY.md` states the SLSA Build level the release reaches, and no higher.

R52.1 read the Build track's requirements and `release.yml` against each: every row of
Build L2 has evidence, and neither row L3 adds has any. The policy says so, row by row, and
names what L3 would need. A level is a claim an adopter relies on, so a higher one's name
is refused wherever it is not being said to be out of reach, and the evidence the policy
cites is held to the workflow, which could lose it without a word here changing.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
POLICY = REPO / "SECURITY.md"
RELEASE = REPO / ".github" / "workflows" / "release.yml"
DOCUMENTS = sorted([REPO / "README.md", POLICY, REPO / "MAINTAINERS.md",
                    *(REPO / "docs").glob("*.md")])
#: The Build track's rows that L2 requires, as R52.1 recorded them.
L2 = ("Choose an appropriate build platform", "Follow a consistent build process",
      "Distribute provenance", "Provenance exists", "Provenance is authentic", "Hosted")
#: The two L3 adds.
L3 = ("Provenance is unforgeable", "Isolated")
OUT_OF_REACH = "### What Build L3 needs, and the release does not have"
_HIGHER = re.compile(r"\b(?:Build\s+)?(?:L|Level\s*)[34]\b|\bSLSA\s*(?:v?\d\.\d\s+)?[34]\b")


def _section() -> str:
    text = POLICY.read_text(encoding="utf-8")
    start = text.index("## How a release is built")
    return text[start:text.index("\n## ", start + 1)]


def higher_levels_named(text: str) -> list[str]:
    """Each line that names Build L3 or L4 outside the one place that says what L3 would
    need: the subsection under `OUT_OF_REACH`, to the next heading."""
    if OUT_OF_REACH in text:
        start = text.index(OUT_OF_REACH)
        end = text.find("\n#", start + len(OUT_OF_REACH))
        text = text[:start] + (text[end:] if end != -1 else "")
    return [line.strip() for line in text.splitlines() if _HIGHER.search(line)]


def test_the_policy_states_build_l2_and_no_higher():
    section = _section()

    assert "**valvur's releases reach SLSA Build L2, and no higher.**" in section
    assert "2026-11-23" in section, "the day the specification was read"


def test_each_requirement_of_the_level_has_its_evidence():
    rows = {cells[0]: cells[1] for cells in (
        [c.strip() for c in line.strip().strip("|").split("|")]
        for line in _section().splitlines() if line.startswith("| ")) if len(cells) == 2}

    assert [row for row in L2 if row not in rows] == []
    assert all(len(rows[row]) > 30 for row in L2), "a row with no evidence"
    assert "attest-build-provenance" in rows["Provenance exists"]
    assert "gh attestation verify" in _section()


def test_what_the_next_level_needs_is_named_as_out_of_reach():
    section = _section()
    beyond = section[section.index(OUT_OF_REACH):]

    for row in L3:
        assert f"**{row}" in beyond, row
    assert not any(f"| {row} |" in section for row in L3), "an L3 row among the evidence"


def test_a_higher_levels_name_is_refused_seen_against_a_planted_one():
    honest = POLICY.read_text(encoding="utf-8")

    assert higher_levels_named(honest) == []
    planted = honest.replace("reach SLSA Build L2, and no higher", "reach SLSA Build L3")
    [seen] = higher_levels_named(planted)
    assert seen.startswith("**valvur's releases reach SLSA Build L3.**")
    assert higher_levels_named("valvur is at SLSA 3.") == ["valvur is at SLSA 3."]
    assert higher_levels_named("Build Level 3, by a hosted builder.")
    assert higher_levels_named("SLSA 1.2 is current; the release reaches Build L2.") == []


def test_no_document_names_a_higher_level_as_reached():
    named = {str(path.relative_to(REPO)): found for path in DOCUMENTS
             if (found := higher_levels_named(path.read_text(encoding="utf-8")))}

    assert named == {}


def test_the_evidence_the_policy_cites_is_still_in_the_release_workflow():
    workflow = RELEASE.read_text(encoding="utf-8")
    code = "\n".join(line for line in workflow.splitlines()
                     if not line.lstrip().startswith("#"))

    assert code.count("uses: actions/attest-build-provenance@") == 2, "the image, the dists"
    assert "push-to-registry: true" in code
    assert "--predicate-type https://slsa.dev/provenance/v1" in code
    assert "gh attestation verify" in code
    runners = set(re.findall(r"runs-on:\s*(\S.*)", code)) | set(
        re.findall(r"runner:\s*(\S+)", code))
    assert runners == {"ubuntu-26.04", "ubuntu-26.04-arm", "${{ matrix.runner }}"}
    assert "self-hosted" not in code
    for name in ("image.intoto.jsonl", "dist.intoto.jsonl"):
        assert name in code and name in _section()
