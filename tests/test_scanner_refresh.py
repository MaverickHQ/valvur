"""R16.3: the monthly Scanner refresh (D34, N3.5).

Dependabot moves a Scanner's pin on `main`; nothing then tells the owner a release
would ship it. `refresh.yml` compares `main`'s pins with the latest release's, by the
parser `test_scanner_pins.py` holds the image to, and when they differ runs the Score
and, if no track fell, dispatches a rehearsal and opens one issue for the owner to
tag. The tag stays the owner's.
"""

from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "scanner_pins.py"
WORKFLOW = REPO / ".github" / "workflows" / "refresh.yml"


def _pins():
    spec = importlib.util.spec_from_file_location("scanner_pins", SCRIPT)
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules["scanner_pins"] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def test_the_pin_test_and_the_refresh_read_pins_with_one_parser():
    from test_scanner_pins import _image_pins

    assert _pins().pins(_pins().in_tree(REPO)) == _image_pins()


def test_the_pins_at_a_git_ref_are_read_from_that_ref():
    """What a release shipped is read from its tag, not the working tree."""
    if subprocess.run(["git", "-C", str(REPO), "rev-parse", "HEAD"],
                      capture_output=True, check=False).returncode:
        pytest.skip("not a git checkout")
    scanner_pins = _pins()
    committed = subprocess.run(["git", "-C", str(REPO), "diff", "--quiet", "HEAD", "--",
                                "Dockerfile", "requirements-checkov.txt",
                                "requirements-zizmor.txt"], check=False).returncode == 0
    if not committed:
        pytest.skip("the pins have uncommitted changes here")

    assert scanner_pins.pins(scanner_pins.at_ref(REPO, "HEAD")) == \
        scanner_pins.pins(scanner_pins.in_tree(REPO))


def test_each_scanner_whose_pin_moved_is_named_with_both_versions():
    moved = _pins().changed({"trivy": "0.74.0", "syft": "1.52.0", "zizmor": "1.30.1"},
                            {"trivy": "0.75.0", "syft": "1.52.0", "gitleaks": "8.30.0"})

    assert moved == {"trivy": ["0.74.0", "0.75.0"], "zizmor": ["1.30.1", None],
                     "gitleaks": [None, "8.30.0"]}


def test_the_command_writes_what_moved_for_the_workflow(tmp_path, capsys):
    """`--since <ref>`: what moved, as JSON, and `changed=` for `$GITHUB_OUTPUT`."""
    if subprocess.run(["git", "-C", str(REPO), "rev-parse", "HEAD"],
                      capture_output=True, check=False).returncode:
        pytest.skip("not a git checkout")
    output = tmp_path / "github-output"

    assert _pins().main(["--since", "HEAD", "--github-output", str(output)]) == 0

    said = json.loads(capsys.readouterr().out)
    assert set(said) == {"since", "moved"} and said["since"] == "HEAD"
    assert re.search(r"^changed=(true|false)$", output.read_text(), re.M)
