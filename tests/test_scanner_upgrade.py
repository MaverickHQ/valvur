"""R47.2 (D81v): a Scanner's pin moves everywhere its stage's does (N3.9).

Dependabot moves a Scanner's stage in the Dockerfile, or its hash-locked requirements, and
nothing else, so its pull requests stayed red: #229 and #230 from 2026-10-17, #238 from
2026-10-24. `scripts/scanner_upgrade.py` moves the rest, R47.1's list: the adapter, the
golden's pin in conftest, the protocol table, and Opengrep's signature check. It is run here
on a copy of the tree with #238's one line applied, and the tests that kept #238 red are run
in that copy.
"""

from __future__ import annotations

import io
import json
import os
import re
import subprocess
import sys
import tarfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "scanner_upgrade.py"

#: #238's change, as a Trivy release now makes it: the stage's version and checksum, and
#: nothing else, since Trivy is built from its release's source (D81w). Applied to whatever
#: Trivy the tree pins, so the case outlives the pin it was measured on (0.75.0 to 0.76.0).
TRIVY_STAGE = re.compile(r"^ARG TRIVY_VERSION=([\d.]+)\nARG TRIVY_SUM=\S+$", re.M)
SUM = "h1:sngciHO0J0koTSzoBKyT0es/MEMqnd+/Nu08iTuTHBs="


def _tree(tmp_path: Path) -> Path:
    """The committed tree, copied: what a pull request's checkout holds."""
    archive = subprocess.run(["git", "-C", str(REPO), "archive", "HEAD"],
                             capture_output=True, check=True).stdout
    root = tmp_path / "tree"
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        tar.extractall(root, filter="data")
    return root


def _pins_now(root: Path) -> dict[str, str]:
    import importlib.util

    spec = importlib.util.spec_from_file_location("pins_copy", root / "scripts" / "scanner_pins.py")
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module.pins(module.in_tree(root))


def _upgrade(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, str(SCRIPT), *args, "--root", str(root)],
                          capture_output=True, text=True, check=False)


def _bump(version: str) -> str:
    major, minor, _ = version.split(".")
    return f"{major}.{int(minor) + 1}.0"


def _with_238(root: Path) -> tuple[Path, str, str]:
    """The tree with Trivy's stage alone moved one minor on; its old and new versions."""
    dockerfile = root / "Dockerfile"
    text = dockerfile.read_text()
    match = TRIVY_STAGE.search(text)
    assert match, "no Trivy stage pinned by version and checksum"
    old = match.group(1)
    new = _bump(old)
    dockerfile.write_text(TRIVY_STAGE.sub(f"ARG TRIVY_VERSION={new}\nARG TRIVY_SUM={SUM}", text))
    return root, old, new


def test_238s_change_is_completed_and_the_tests_that_kept_it_red_pass(tmp_path):
    root, old, new = _with_238(_tree(tmp_path))

    done = _upgrade(root, "trivy", old, new)

    assert done.returncode == 0, done.stderr
    report = json.loads(done.stdout)
    assert report["scanner"] == "trivy" and report["to"] == new
    assert sorted(report["changed"]) == ["docs/PROTOCOL.md", "src/valvur/adapters/trivy.py",
                                        "tests/conftest.py"]
    # The golden is the new binary's output, which R47.3's recapture writes: named, not faked.
    assert report["recapture"] == [f"tests/fixtures/golden/trivy-{new}.json"]
    golden = root / "tests" / "fixtures" / "golden" / f"trivy-{old}.json"
    golden.rename(golden.with_name(f"trivy-{new}.json"))  # the recapture, stood in for here

    env = {**os.environ, "PYTHONPATH": str(root / "src"), "PYTHONDONTWRITEBYTECODE": "1"}
    pinned = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
                             "tests/test_scanner_pins.py"],
                            cwd=root, env=env, capture_output=True, text=True, check=False)
    assert pinned.returncode == 0, pinned.stdout[-2000:]
    assert _pins_now(root)["trivy"] == new


def test_opengrep_s_signature_check_moves_with_its_release(tmp_path):
    root = _tree(tmp_path)
    dockerfile = root / "Dockerfile"
    text = dockerfile.read_text()
    old = _pins_now(root)["opengrep"]
    dockerfile.write_text(text.replace(f"/download/v{old}\n", "/download/v9.9.9\n"))

    done = _upgrade(root, "opengrep", old, "9.9.9")

    assert done.returncode == 0, done.stderr
    assert "scripts/verify-opengrep.sh" in json.loads(done.stdout)["changed"]
    assert 'VERSION="${OPENGREP_VERSION:-v9.9.9}"' in \
        (root / "scripts" / "verify-opengrep.sh").read_text()


def test_a_scanner_it_does_not_know_is_left_for_the_owner(tmp_path):
    root = _tree(tmp_path)

    done = _upgrade(root, "grype", "0.1.0", "0.2.0")

    assert done.returncode == 3
    assert "left for the owner" in done.stderr and "grype" in done.stderr
    assert done.stdout == ""


def test_a_change_to_more_than_one_scanner_is_left_for_the_owner_untouched(tmp_path):
    root, old, new = _with_238(_tree(tmp_path))
    pins = _pins_now(root)
    dockerfile = root / "Dockerfile"
    dockerfile.write_text(dockerfile.read_text().replace(
        f"/download/v{pins['opengrep']}\n", "/download/v9.9.9\n"))
    before = (root / "src" / "valvur" / "adapters" / "trivy.py").read_text()

    done = _upgrade(root, "trivy", old, new)

    assert done.returncode == 3
    assert "more than one Scanner" in done.stderr
    assert "opengrep" in done.stderr and "trivy" in done.stderr
    assert (root / "src" / "valvur" / "adapters" / "trivy.py").read_text() == before


def test_a_stage_that_does_not_pin_the_new_version_is_left_for_the_owner(tmp_path):
    root = _tree(tmp_path)                    # Trivy's stage still pins the old version
    old = _pins_now(root)["trivy"]

    done = _upgrade(root, "trivy", old, _bump(old))

    assert done.returncode == 3
    assert "stage pins" in done.stderr
