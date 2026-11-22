"""R45.6: the released image and the new one give one output (Requirement 21.3, D81aa).

An image patch releases itself only when no Scanner reports anything else from the new
image than from the last release's. `scripts/same_output.py` runs each Scanner's golden
recipe in both, on one copy of the data, and compares the two outputs as a recapture is
judged (R47.3): after each run's identity is blanked. The container runtime is faked, as
every unit test fakes it.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))
_spec = importlib.util.spec_from_file_location("same_output", REPO / "scripts" / "same_output.py")
same_output = importlib.util.module_from_spec(_spec)  # type: ignore[arg-type]
_spec.loader.exec_module(same_output)  # type: ignore[union-attr]


class Runtime:
    """A Scan Container of one image, that answers each Scanner with its canned report."""

    def __init__(self, reports: dict[str, str], *, fails: bool = False):
        self.reports, self.fails, self.ran = reports, fails, []

    def run(self, plan, tar, scratch, **_):
        [invocation] = plan
        self.ran.append(invocation.tool)
        if self.fails:
            raise RuntimeError("pull access denied")
        (scratch / (invocation.report or f"{invocation.tool}.stdout")).write_text(
            self.reports[invocation.tool])
        return 0


def _trivy(report_id: str, vulnerability: str = "CVE-2026-0001") -> str:
    return json.dumps({"SchemaVersion": 2, "ReportID": report_id, "CreatedAt": report_id,
                       "Results": [{"Target": "requirements.txt",
                                    "Vulnerabilities": [{"VulnerabilityID": vulnerability}]}]})


ZIZMOR = json.dumps([{"ident": "unpinned-uses", "locations": []}])
TOOLS = ("trivy", "zizmor")


def _main(monkeypatch, capsys, released: Runtime, new: Runtime) -> tuple[int, str]:
    images = {"valvur:released": released, "valvur:new": new}
    monkeypatch.setattr(same_output, "runtime_for", lambda image: images[image])
    code = same_output.main(["--released", "valvur:released", "--new", "valvur:new",
                             *(word for tool in TOOLS for word in ("--tool", tool))])
    return code, capsys.readouterr().out


def test_two_images_that_differ_only_in_each_runs_identity_give_one_output(monkeypatch, capsys):
    released = Runtime({"trivy": _trivy("run-1"), "zizmor": ZIZMOR})
    new = Runtime({"trivy": _trivy("run-2"), "zizmor": ZIZMOR})

    code, said = _main(monkeypatch, capsys, released, new)

    assert code == 0, said
    assert released.ran == new.ran == ["trivy", "zizmor"]
    assert "2 Scanners give one output from both images" in said


def test_one_finding_that_differs_fails_it_naming_the_scanner_and_its_recipe(monkeypatch, capsys):
    released = Runtime({"trivy": _trivy("run-1"), "zizmor": ZIZMOR})
    new = Runtime({"trivy": _trivy("run-2", "CVE-2026-0002"), "zizmor": ZIZMOR})

    code, said = _main(monkeypatch, capsys, released, new)

    assert code == 1
    assert "trivy" in said and "broken-repo" in said and "zizmor" not in said.split("\n")[0]


@pytest.mark.parametrize("which", ["released", "new"])
def test_an_image_that_cannot_run_fails_it_and_nothing_is_assumed_equal(
        monkeypatch, capsys, which):
    reports = {"trivy": _trivy("run-1"), "zizmor": ZIZMOR}
    released = Runtime(reports, fails=which == "released")
    new = Runtime(reports, fails=which == "new")

    code, said = _main(monkeypatch, capsys, released, new)

    assert code == 1
    assert "could not be run" in said and f"valvur:{which}" in said


def test_a_scanner_that_gives_no_output_from_both_is_not_equal_either(monkeypatch, capsys):
    silent = {"trivy": "", "zizmor": ZIZMOR}

    code, said = _main(monkeypatch, capsys, Runtime(silent), Runtime(silent))

    assert code == 1 and "trivy gave no output" in said


def test_every_scanner_with_a_recipe_is_compared_unless_told_otherwise():
    sys.path.insert(0, str(REPO / "scripts"))
    import scanner_upgrade

    assert same_output.TOOLS == tuple(sorted(scanner_upgrade.RECIPES))
    assert "gitleaks" not in same_output.TOOLS, "Gitleaks has no recipe: R47.1 gave it none"


@pytest.mark.e2e
def test_the_built_image_gives_one_output_with_itself(capsys):
    """The real containers, and every Scanner with a recipe."""
    from valvur.engine_host import IMAGE

    code = same_output.main(["--released", IMAGE, "--new", IMAGE])

    assert code == 0, capsys.readouterr().out
