"""R44.12: the image's plan, made by rule from the image gate's verdict (D81x).

`scripts/image_heal.py plan` reads the gate's verdict on the image built from `main`, for
both architectures, and the Dockerfile. It asks Alpine's index, Docker Hub and Go's module
proxy what exists, and writes what the Dockerfile's envelope should become. Every network
answer here is `tests/fake_registry.py`'s, so nothing opens a socket.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from fake_registry import FakePackageRegistry, alpine_answers

REPO = Path(__file__).resolve().parent.parent
IMAGE_HEAL = REPO / "scripts" / "image_heal.py"
NOW = "2026-11-21T06:41:00Z"
PYTHON = "python:3.12-alpine3.24@sha256:" + "e" * 64
GOLANG = "golang:1.27.4-alpine3.24@sha256:" + "a" * 64
DOCKERFILE = f"""\
FROM {PYTHON} AS opengrep
FROM {GOLANG} AS gitleaks
ARG GITLEAKS_RAISE="golang.org/x/crypto@v0.58.0"
FROM {GOLANG} AS trivy
ARG TRIVY_RAISE=""
FROM {GOLANG} AS osv
ARG OSV_SCANNER_RAISE=""
FROM {GOLANG} AS syft
ARG SYFT_RAISE=""
FROM {PYTHON}
ARG ALPINE_RAISE="zlib=1.4-r0"
RUN true
"""
BOTH = ("x86_64", "aarch64")


def _entry(vid: str, package: str, installed: str, fixed: str, *, kind: str = "alpine",
           target: str = "img (alpine 3.24.3)") -> dict:
    return {"id": vid, "package": package, "installed": installed, "fixed": fixed,
            "severity": "HIGH", "target": target, "kind": kind}


def _plan(tmp_path: Path, monkeypatch, blocking: list[dict], answers: dict[str, object],
          *, arm64: list[dict] | None = None, dockerfile: str = DOCKERFILE
          ) -> tuple[subprocess.CompletedProcess[str], dict]:
    FakePackageRegistry(tmp_path / "registry", answers).install(monkeypatch)
    (tmp_path / "Dockerfile").write_text(dockerfile)
    for arch, found in (("amd64", blocking), ("arm64", blocking if arm64 is None else arm64)):
        (tmp_path / f"verdict-{arch}.json").write_text(json.dumps(
            {"blocking": found, "accepted": [], "unfixed": [], "refused": []}))
    out = tmp_path / "plan.json"
    run = subprocess.run(
        [sys.executable, str(IMAGE_HEAL), "plan", "--verdict", str(tmp_path / "verdict-amd64.json"),
         "--verdict", str(tmp_path / "verdict-arm64.json"), "--dockerfile",
         str(tmp_path / "Dockerfile"), "--now", NOW, "--out", str(out)],
        capture_output=True, text=True, check=False)
    return run, json.loads(out.read_text()) if out.is_file() else {}


def _index(**packages: str) -> dict[str, object]:
    return alpine_answers("3.24", {arch: packages for arch in BOTH})


def test_an_alpine_entry_whose_fix_the_index_holds_is_one_raise_at_that_version(
        tmp_path, monkeypatch):
    blocking = [_entry("CVE-2026-0001", "busybox", "1.37.0-r31", "1.37.0-r32"),
                _entry("CVE-2026-0002", "busybox", "1.37.0-r31", "1.37.0-r32")]

    run, plan = _plan(tmp_path, monkeypatch, blocking, _index(busybox="1.37.0-r32"))

    assert run.returncode == 0, run.stderr
    assert plan["raises"] == [{"arg": "ALPINE_RAISE", "entry": "busybox=1.37.0-r32",
                               "package": "busybox", "from": "1.37.0-r31",
                               "answers": ["CVE-2026-0001", "CVE-2026-0002"],
                               "rule": "alpine-index"}]
    assert plan["escalations"] == []


def test_when_the_index_holds_a_later_version_the_raise_is_at_the_indexs(tmp_path, monkeypatch):
    blocking = [_entry("CVE-2026-0001", "busybox", "1.37.0-r31", "1.37.0-r32")]

    _run, plan = _plan(tmp_path, monkeypatch, blocking, _index(busybox="1.37.1-r0"))

    assert [r["entry"] for r in plan["raises"]] == ["busybox=1.37.1-r0"]


def test_an_index_behind_the_fix_or_split_by_architecture_is_no_alpine_fix(tmp_path, monkeypatch):
    blocking = [_entry("CVE-2026-0001", "busybox", "1.37.0-r31", "1.37.0-r32"),
                _entry("CVE-2026-0003", "tzdata", "2026a-r0", "2026b-r0")]
    answers = alpine_answers("3.24", {
        "x86_64": {"busybox": "1.37.0-r31", "tzdata": "2026b-r0"},
        "aarch64": {"busybox": "1.37.0-r31", "tzdata": "2026a-r0"}})

    run, plan = _plan(tmp_path, monkeypatch, blocking, answers)

    assert run.returncode == 0, run.stderr
    assert plan["raises"] == []
    assert plan["escalations"] == [
        {"subject": "busybox", "reason": "no-alpine-fix", "answers": ["CVE-2026-0001"]},
        {"subject": "tzdata", "reason": "no-alpine-fix", "answers": ["CVE-2026-0003"]}]


@pytest.mark.parametrize("lower, higher", [
    ("1.37.0-r31", "1.37.0-r32"), ("1.37.0-r32", "1.37.1-r0"), ("1.3.2-r1", "1.4-r0"),
    ("3.5.9-r0", "3.5.9-r1"), ("1.22.2-r1", "1.22.3-r0"), ("2026a-r0", "2026b-r0"),
    ("6.6_p20260516-r0", "6.6_p20260601-r0"), ("1.2.5_rc1-r0", "1.2.5-r0"),
    ("1.2.5-r0", "1.2.5_p1-r0"), ("1.9-r0", "1.10-r0"), ("20261020-r0", "20261101-r0"),
])
def test_alpine_versions_order_as_apk_orders_them(lower, higher):
    """The pairs are ones `apk version -t` calls `<`: releases, revisions, a letter, and
    the `_rc` and `_p` suffixes. A version this does not read orders against nothing."""
    sys.path.insert(0, str(IMAGE_HEAL.parent))
    import image_heal

    assert image_heal.apk_key(lower) < image_heal.apk_key(higher)
    assert image_heal.apk_key("1.0~weird") is None
