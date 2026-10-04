"""D61c: `valvur:dev` built in a Claude Code cloud session, by `scripts/cloud_image.py`.

The session's network re-terminates TLS with its own certificate authority, and a
build's `RUN` steps do not trust it: the cloud pre-flight's `apk add` failed there
(2026-10-03). The script builds from a Dockerfile derived in a temporary directory, in
which every `RUN` mounts the host's CA bundle as a BuildKit secret and names it in
`SSL_CERT_FILE` and `PIP_CERT`. These tests hold that the derived file changes nothing
else, and that the CA reaches no layer.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "cloud_image.py"


def _script():
    spec = importlib.util.spec_from_file_location("cloud_image", SCRIPT)
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules["cloud_image"] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def test_every_run_trusts_the_build_ca_and_no_other_line_changes():
    script = _script()
    committed = (REPO / "Dockerfile").read_text().splitlines()

    derived = script.derive("\n".join(committed)).splitlines()

    assert len(derived) == len(committed)
    runs = 0
    for before, after in zip(committed, derived, strict=True):
        if before.startswith("RUN "):
            runs += 1
            assert after == script.PREFIX + before.removeprefix("RUN ")
        else:
            assert after == before
    assert runs >= 5, "the committed Dockerfile's RUN steps were not found"


def test_the_ca_is_a_secret_mount_and_reaches_no_layer():
    script = _script()

    derived = script.derive((REPO / "Dockerfile").read_text())

    assert "--mount=type=secret,id=build-ca " in script.PREFIX
    for line in derived.splitlines():
        if script.CA_PATH in line:
            assert line.startswith(script.PREFIX), line
        assert not (line.startswith(("COPY", "ADD")) and "build-ca" in line), line


@pytest.mark.parametrize("run", [
    'RUN ["sh", "-c", "apk add x"]',
    "RUN --mount=type=cache,target=/root/.cache pip install x",
    "RUN <<EOF",
])
def test_a_run_it_cannot_prefix_safely_is_refused(run):
    with pytest.raises(ValueError, match="RUN"):
        _script().derive(f"FROM scratch\n{run}\n")


def test_the_ca_comes_from_the_override_then_the_environment_then_the_system(tmp_path):
    script = _script()
    override, environment, system = (tmp_path / n for n in ("o.pem", "e.pem", "s.pem"))
    for path in (override, environment, system):
        path.write_text("pem")

    assert script.ca_bundle({"VALVUR_BUILD_CA": str(override), "SSL_CERT_FILE": str(environment)},
                            system=system) == override
    assert script.ca_bundle({"SSL_CERT_FILE": str(environment)}, system=system) == environment
    assert script.ca_bundle({"VALVUR_BUILD_CA": str(tmp_path / "missing")},
                            system=system) == system
    assert script.ca_bundle({}, system=tmp_path / "none") is None


def test_the_build_is_bakes_dev_target_with_the_derived_file_and_the_secret(tmp_path):
    """Bake reads files outside the project only when allowed to (measured on buildx's
    current release, 2026-10-03: "additional privileges requested"), so the two it needs,
    the derived Dockerfile's directory and the CA bundle, are allowed and nothing else."""
    (tmp_path / "scratch").mkdir()
    dockerfile, ca = tmp_path / "scratch" / "Dockerfile", tmp_path / "ca.pem"
    ca.write_text("pem")

    assert _script().command(dockerfile, ca) == [
        "docker", "buildx", "bake", "dev",
        "--set", f"dev.dockerfile={dockerfile}",
        "--set", f"dev.secrets=id=build-ca,src={ca}",
        f"--allow=fs.read={dockerfile.parent.resolve()}",
        f"--allow=fs.read={ca.resolve()}",
    ]
