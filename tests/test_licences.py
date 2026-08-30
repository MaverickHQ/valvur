"""Sub-phase 8.0 — the corrected licence claim (F10.4).

The original requirement said the image must contain no GPL component. No Linux
container can satisfy that: ours has 12, all from the base OS. What we control, and
what ADR-0005 actually cares about, is what valvur *deliberately installs*.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
from check_image_licences import licences, offending


def _component(name, *licence_ids):
    return {"name": name, "version": "1.0",
            "licenses": [{"license": {"id": i}} for i in licence_ids]}


def test_a_deliberately_added_gpl_component_is_caught():
    """A check that cannot fail is not a check.

    This is the case the whole script exists for: someone adds a GPL tool as a
    Scanner, and the release gate must refuse it.
    """
    problems = offending([
        _component("hadolint", "GPL-3.0"),
        _component("trivy", "Apache-2.0"),
    ])

    assert problems == [("hadolint", "GPL-3.0")]


def test_lgpl_is_permitted():
    """We ship Opengrep (LGPL-2.1) as an unmodified binary invoked as a subprocess —
    aggregation, not a derivative work (ADR-0004). Flagging it would force us back
    onto Semgrep, whose rule licence was the reason we left."""
    assert offending([_component("opengrep", "LGPL-2.1")]) == []


def test_agpl_and_sspl_are_caught():
    """The licences that would matter most, and are easiest to acquire by accident."""
    problems = offending([
        _component("something", "AGPL-3.0"),
        _component("otherthing", "SSPL-1.0"),
    ])

    assert {name for name, _ in problems} == {"something", "otherthing"}


def test_a_compound_expression_containing_gpl_is_caught():
    """Real SBOMs contain 'MIT AND BSD-2-Clause AND GPL-2.0-or-later' — our own base
    image does, on musl-utils. A naive equality check would miss it."""
    problems = offending([_component("musl-utils", "MIT AND BSD-2-Clause AND GPL-2.0-or-later")])

    assert problems


def test_licences_reads_id_name_and_expression_forms():
    """Syft emits all three shapes; missing one would silently under-report."""
    assert licences({"licenses": [{"license": {"id": "MIT"}}]}) == {"MIT"}
    assert licences({"licenses": [{"license": {"name": "Apache 2.0"}}]}) == {"Apache 2.0"}
    assert licences({"licenses": [{"expression": "MIT OR GPL-2.0"}]}) == {"MIT OR GPL-2.0"}


@pytest.mark.e2e
def test_our_real_image_adds_no_gpl_component():
    """F10.4 as corrected, against the actual image."""
    from check_image_licences import added_components

    added = added_components("valvur:dev", "python:3.12-alpine3.22")

    assert added, "the diff found nothing added — the comparison is broken"
    assert offending(added) == []
