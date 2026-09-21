"""26.3.1 — the shim/image protocol, named and versioned (F1.9, 23.4.4).

What the shim assumes of the image — which binaries at which paths, the mount
points, the Checks entry point and its JSON, the labels, the digest file, the user
— was implicit in `runner.py`, the adapters and the Dockerfile, pinned only by the
e2e suite exercising it. Now it is written down in `docs/PROTOCOL.md`, carried by
the image as one label, `org.valvur.protocol`, and the compatibility check compares
protocol majors: the same major runs whatever the versions say (a different tree
is a diagnosis, 23.4.4); a different major is the one thing refused.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

from valvur import compat

PROTOCOL_MD = Path("docs/PROTOCOL.md")


# --------------------------------------------------------- the label decides


def test_the_same_protocol_major_runs_whatever_the_versions_say(monkeypatch):
    """A 0.4 shim against a 0.9 image that speaks the same protocol: the pair
    runs, and the tree difference is said in SUMMARY.md (23.4.4), never refused."""
    monkeypatch.setattr(compat, "shim_version", lambda: "0.4.0")
    monkeypatch.setattr(compat, "image_version", lambda r, i: "0.9.0")
    monkeypatch.setattr(compat, "image_protocol", lambda r, i: compat.PROTOCOL)

    assert compat.incompatibility("docker", "x") is None
    compat.check("docker", "x")


def test_a_different_protocol_major_is_the_one_thing_refused(monkeypatch):
    monkeypatch.setattr(compat, "shim_version", lambda: "0.4.0")
    monkeypatch.setattr(compat, "image_version", lambda r, i: "0.4.0")
    monkeypatch.setattr(compat, "image_protocol", lambda r, i: compat.PROTOCOL + 1)

    with pytest.raises(compat.IncompatibleImage) as caught:
        compat.check("docker", "ghcr.io/maverickhq/valvur:0.4.0")
    message = str(caught.value)
    assert f"protocol {compat.PROTOCOL + 1}" in message and f"protocol {compat.PROTOCOL}" in message
    assert "0.4.0" in message, "both versions are named"
    assert "pip install -U valvur" in message and "docker pull" in message


def test_an_image_without_the_protocol_label_falls_back_to_the_version_rule(monkeypatch):
    """Every image before this one — 0.3.0 included — has no protocol label; the
    version-series rule that served them keeps serving them."""
    monkeypatch.setattr(compat, "image_protocol", lambda r, i: None)
    monkeypatch.setattr(compat, "shim_version", lambda: "0.1.4")
    monkeypatch.setattr(compat, "image_version", lambda r, i: "0.1.9")
    assert compat.incompatibility("docker", "x") is None

    monkeypatch.setattr(compat, "image_version", lambda r, i: "0.2.0")
    reason = compat.incompatibility("docker", "x")
    assert reason and "0.1.4" in reason and "0.2.0" in reason


def test_doctor_says_what_compat_says(monkeypatch, tmp_path):
    """One verdict, two surfaces: `doctor` no longer re-derives compatibility."""
    from valvur import doctor

    monkeypatch.setattr(doctor, "_image_present", lambda r, i: True)
    monkeypatch.setattr(doctor, "_image_label", lambda r, i: "0.4.0")
    monkeypatch.setattr(doctor, "_image_protocol", lambda r, i: 9)
    monkeypatch.setattr(compat, "verdict",
                        lambda ours, declared, theirs: "protocol 9 is not the shim's protocol 1")

    check, _ = doctor._check_image("/usr/local/bin/docker")

    assert check.level == "fail"
    assert "protocol 9 is not the shim's protocol 1" in check.detail


def test_the_dockerfile_declares_the_protocol_the_shim_speaks():
    dockerfile = Path("Dockerfile").read_text()
    label = re.search(rf'^LABEL {re.escape(compat.PROTOCOL_LABEL)}="(\d+)"', dockerfile, re.M)

    assert label, f"the Dockerfile carries no {compat.PROTOCOL_LABEL} label"
    assert int(label.group(1)) == compat.PROTOCOL


# ------------------------------------------------- the document is the contract


def _protocol_table(kind: str) -> list[list[str]]:
    """The rows of the PROTOCOL.md table whose header's first cell is `kind` —
    `path`, `label` or `binary` — each row as its cells, backticks stripped."""
    text = PROTOCOL_MD.read_text()
    rows: list[list[str]] = []
    active = False
    for line in text.splitlines():
        if line.startswith("|"):
            cells = [c.strip().strip("`") for c in line.strip("|").split("|")]
            if cells and cells[0].lower() == kind:
                active = True
                continue
            if active and cells and set(cells[0]) <= {"-"}:
                continue
            if active:
                rows.append(cells)
        else:
            active = False
    assert rows, f"PROTOCOL.md has no `{kind}` table"
    return rows


def _protocol_rows(kind: str) -> list[str]:
    return [row[0] for row in _protocol_table(kind)]


def _image_paths() -> list[str]:
    """The path rows the image provides — not the mounts the shim does."""
    return [row[0] for row in _protocol_table("path") if row[1].startswith("the image")]


def test_protocol_md_lists_every_path_the_adapters_and_the_runner_assume(tmp_path, monkeypatch):
    """The document cannot be narrower than the code: every absolute path any
    Invocation names, and every mount the runner makes, is a row."""
    from valvur import adapters, cache

    monkeypatch.setattr(cache, "db_present", lambda: True)
    documented = set(_protocol_rows("path"))
    assumed: set[str] = set()
    for adapter in adapters.DEFAULT_ADAPTERS:
        for arg in adapter.command(tmp_path).argv:
            for token in re.split(r"[=,]", arg):
                if token.startswith("/"):
                    assumed.add(token)
    assumed |= {"/workspace", "/results", "/cache/trivy", "/cache/names", "/tmp"}  # noqa: S108
    assumed.add(compat.IMAGE_INPUTS_FILE)

    def covered(path: str) -> bool:
        return any(path == d or path.startswith(d.rstrip("/") + "/") for d in documented)

    missing = sorted(p for p in assumed if not covered(p))
    assert missing == [], f"PROTOCOL.md does not list: {missing}"


def test_protocol_md_lists_every_binary_and_both_labels():
    from valvur import adapters

    binaries = set(_protocol_rows("binary"))
    invoked = {a.command(Path("/nonexistent")).argv[0] for a in adapters.DEFAULT_ADAPTERS
               if getattr(a, "kind", "") == "scanner" and a.name != "trivy"}
    invoked.add("trivy")
    assert invoked <= binaries, f"binaries invoked but undocumented: {sorted(invoked - binaries)}"

    labels = set(_protocol_rows("label"))
    assert {compat.LABEL, compat.PROTOCOL_LABEL} <= labels


def test_protocol_md_names_the_checks_entry_point_and_its_shapes():
    text = PROTOCOL_MD.read_text()
    for needed in ("python -m valvur.checks", "batch", '"ok"', '"findings"', '"error"',
                   "usage:", "VALVUR_NETWORK", "10001", "--network=none", "--read-only"):
        assert needed in text, f"PROTOCOL.md does not mention {needed!r}"


# ------------------------------------------------------ the built image agrees


@pytest.mark.e2e
def test_the_built_image_honours_protocol_md():
    """Every path and label the document lists exists in the image the shim would
    use; the user is the one it names. The e2e suite runs this against the image
    just built, so the document cannot drift from the Dockerfile."""
    from valvur.runner import IMAGE, detect_runtime

    runtime = detect_runtime()

    def run(*argv: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [runtime, "run", "--rm", "--network=none", "--entrypoint", "sh", IMAGE, "-c",
             " ".join(argv)],
            capture_output=True, text=True, timeout=120, check=False,
        )

    paths = _image_paths()
    assert len(paths) >= 5, paths
    probe = '; do [ -e "$p" ] && echo "ok $p" || echo "MISSING $p"; done'
    listing = run("for p in " + " ".join(paths) + probe)
    missing = [line for line in listing.stdout.splitlines() if line.startswith("MISSING")]
    assert not missing, f"the image lacks paths PROTOCOL.md lists: {missing}"

    binaries = _protocol_rows("binary")
    probe = '; do command -v "$b" >/dev/null && echo "ok $b" || echo "MISSING $b"; done'
    which = run("for b in " + " ".join(binaries) + probe)
    assert "MISSING" not in which.stdout, which.stdout

    inspect = subprocess.run(
        [runtime, "image", "inspect", "--format", "{{json .Config.Labels}}", IMAGE],
        capture_output=True, text=True, timeout=60, check=False,
    )
    import json

    labels = json.loads(inspect.stdout or "{}") or {}
    for label in _protocol_rows("label"):
        assert label in labels, f"the image carries no {label} label"
    assert labels[compat.PROTOCOL_LABEL] == str(compat.PROTOCOL)

    assert run("id -u").stdout.strip() == "10001"
