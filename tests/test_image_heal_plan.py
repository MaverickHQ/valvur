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
from fake_registry import GOPROXY, HUB, FakePackageRegistry, alpine_answers, raw

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
         str(tmp_path / "Dockerfile"), "--now", NOW, "--out", str(out),
         "--docker", str(_docker(tmp_path))],
        capture_output=True, text=True, check=False)
    return run, json.loads(out.read_text()) if out.is_file() else {}


def _docker(tmp_path: Path, installed: dict[str, str] | None = None) -> Path:
    """A stand-in for the container runtime: it records what it was asked, and answers
    `cat /lib/apk/db/installed` with a database that holds `installed`."""
    fake = tmp_path / "docker"
    if installed is not None or not fake.exists():
        database = "".join(f"P:{name}\nV:{version}\n\n" for name, version in
                           (installed or {}).items())
        (tmp_path / "installed.db").write_text(database)
        fake.write_text(f'#!/bin/sh\necho "$@" >> "{tmp_path}/docker.log"\n'
                        f'cat "{tmp_path}/installed.db"\n')
        fake.chmod(0o755)
    return fake


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


def _go(vid: str, module: str, installed: str, fixed: str, scanner: str = "trivy") -> dict:
    return _entry(vid, module, installed, fixed, kind="gobinary",
                  target=f"usr/local/bin/{scanner}")


def _tags(module: str, *versions: str) -> dict[str, object]:
    return {f"{GOPROXY}/{module}/@v/list": raw("".join(f"{v}\n" for v in versions))}


def test_a_go_module_is_raised_in_the_scanner_whose_binary_holds_it(tmp_path, monkeypatch):
    blocking = [_go("CVE-2026-0010", "golang.org/x/net", "v0.60.0", "0.62.0"),
                _go("CVE-2026-0010", "golang.org/x/net", "v0.61.0", "0.62.0", "osv-scanner")]

    run, plan = _plan(tmp_path, monkeypatch, blocking,
                      _tags("golang.org/x/net", "v0.60.0", "v0.61.0", "v0.62.0"))

    assert run.returncode == 0, run.stderr
    assert plan["raises"] == [
        {"arg": "OSV_SCANNER_RAISE", "entry": "golang.org/x/net@v0.62.0",
         "package": "golang.org/x/net", "from": "v0.61.0", "answers": ["CVE-2026-0010"],
         "rule": "go-fixed-version"},
        {"arg": "TRIVY_RAISE", "entry": "golang.org/x/net@v0.62.0",
         "package": "golang.org/x/net", "from": "v0.60.0", "answers": ["CVE-2026-0010"],
         "rule": "go-fixed-version"}]


def test_of_several_fixed_versions_the_lowest_in_the_installed_major_is_taken(
        tmp_path, monkeypatch):
    blocking = [_go("CVE-2026-0011", "github.com/example/mod", "v1.4.0", "2.0.1, 1.4.2"),
                _go("CVE-2026-0012", "github.com/example/mod", "v1.4.0", "1.4.1")]

    _run, plan = _plan(tmp_path, monkeypatch, blocking,
                       _tags("github.com/example/mod", "v1.4.0", "v1.4.1", "v1.4.2"))

    assert [(r["entry"], r["answers"]) for r in plan["raises"]] == [
        ("github.com/example/mod@v1.4.2", ["CVE-2026-0011", "CVE-2026-0012"])]


def test_a_fix_only_in_a_new_major_is_go_major(tmp_path, monkeypatch):
    blocking = [_go("CVE-2026-0013", "github.com/example/mod", "v1.4.0", "2.0.1")]

    _run, plan = _plan(tmp_path, monkeypatch, blocking, {})

    assert plan["raises"] == []
    assert plan["escalations"] == [{"subject": "github.com/example/mod in trivy",
                                    "reason": "go-major", "answers": ["CVE-2026-0013"]}]


def test_a_fix_with_no_tagged_version_is_go_untagged_and_no_pseudo_version_is_written(
        tmp_path, monkeypatch):
    """As `golang.org/x/crypto` in 1.6.2: the fix was a commit, and a person chose it."""
    blocking = [_go("GO-2026-5932", "golang.org/x/crypto", "v0.58.0",
                    "0.58.1-0.20261009181718-2f1f834330b2")]

    run, plan = _plan(tmp_path, monkeypatch, blocking,
                      _tags("golang.org/x/crypto", "v0.57.0", "v0.58.0"))

    assert plan["raises"] == []
    assert plan["escalations"] == [{"subject": "golang.org/x/crypto in trivy",
                                    "reason": "go-untagged", "answers": ["GO-2026-5932"]}]
    assert "2f1f834330b2" not in json.dumps(plan["raises"]) and run.returncode == 0


def test_a_scanners_own_module_is_scanner_version_and_plans_nothing(tmp_path, monkeypatch):
    blocking = [_go("CVE-2026-0014", "github.com/aquasecurity/trivy", "v0.76.2", "0.76.3")]

    _run, plan = _plan(tmp_path, monkeypatch, blocking, {})

    assert plan["raises"] == []
    assert plan["escalations"] == [{"subject": "trivy", "reason": "scanner-version",
                                    "answers": ["CVE-2026-0014"]}]


def test_an_entry_of_a_kind_the_plan_does_not_know_is_named_and_never_dropped(
        tmp_path, monkeypatch):
    blocking = [_entry("CVE-2026-0015", "left-pad", "1.0", "1.1", kind="node-pkg",
                       target="opt/x/package.json"),
                _go("CVE-2026-0016", "golang.org/x/net", "v0.60.0", "0.62.0", "opengrep"),
                _entry("CVE-2026-0017", "soupsieve", "2.8", "2.9", kind="python-pkg",
                       target="Python")]

    _run, plan = _plan(tmp_path, monkeypatch, blocking, {})

    assert plan["raises"] == []
    assert plan["unplanned"] == [
        {"id": "CVE-2026-0015", "package": "left-pad", "kind": "node-pkg",
         "target": "opt/x/package.json", "why": "a kind the image's heal does not plan"},
        {"id": "CVE-2026-0016", "package": "golang.org/x/net", "kind": "gobinary",
         "target": "usr/local/bin/opengrep", "why": "a binary no `_RAISE` builds"},
        {"id": "CVE-2026-0017", "package": "soupsieve", "kind": "python-pkg",
         "target": "Python", "why": "a Python package: the Checkov lock's heal, or Dependabot"}]


def _hub_tags(repository: str, prefix: str, tags: dict[str, str]) -> dict[str, object]:
    """Docker Hub's list of an official image's tags that start with `prefix`."""
    return {f"{HUB}/{repository}/tags?page_size=100&name={prefix}": {
        "next": None, "results": [{"name": name, "digest": digest}
                                  for name, digest in tags.items()]}}


def _std(vid: str, installed: str, fixed: str, scanner: str = "trivy") -> dict:
    return _go(vid, "stdlib", installed, fixed, scanner)


def test_gos_standard_library_moves_the_one_pin_to_the_newest_patch_of_its_minor(
        tmp_path, monkeypatch):
    blocking = [_std("CVE-2026-97054", "v1.27.4", "1.26.11, 1.27.5"),
                _std("CVE-2026-97054", "v1.27.4", "1.26.11, 1.27.5", "syft")]
    hub = _hub_tags("golang", "1.27.", {
        "1.27.4-alpine3.24": "sha256:" + "a" * 64, "1.27.5-alpine3.24": "sha256:" + "b" * 64,
        "1.27.6-alpine3.24": "sha256:" + "c" * 64, "1.27.6-alpine3.25": "sha256:" + "d" * 64,
        "1.27.7-bookworm": "sha256:" + "f" * 64, "1.27.6rc1-alpine3.24": "sha256:" + "9" * 64})

    run, plan = _plan(tmp_path, monkeypatch, blocking, hub)

    assert run.returncode == 0, run.stderr
    assert plan["go"] == {"from": "golang:1.27.4-alpine3.24@sha256:" + "a" * 64,
                          "to": "golang:1.27.6-alpine3.24@sha256:" + "c" * 64,
                          "answers": ["CVE-2026-97054"], "rule": "newest-patch-of-the-minor"}
    assert plan["raises"] == [] and plan["escalations"] == []


def test_a_standard_library_fix_only_in_another_minor_is_go_major(tmp_path, monkeypatch):
    blocking = [_std("CVE-2026-0020", "v1.27.4", "1.28.1")]
    hub = _hub_tags("golang", "1.27.", {"1.27.4-alpine3.24": "sha256:" + "a" * 64})

    _run, plan = _plan(tmp_path, monkeypatch, blocking, hub)

    assert plan["go"] is None
    assert plan["escalations"] == [{"subject": "go", "reason": "go-major",
                                    "answers": ["CVE-2026-0020"]}]


def test_with_no_standard_library_entry_docker_hub_is_not_asked(tmp_path, monkeypatch):
    _run, plan = _plan(tmp_path, monkeypatch, [], {})

    assert plan["go"] is None
    assert (tmp_path / "registry" / "asked.log").read_text() == ""


NEWER = "sha256:" + "7" * 64


def _base(digest: str) -> dict[str, object]:
    return _hub_tags("python", "3.12-alpine3.24", {"3.12-alpine3.24": digest,
                                                   "3.12-alpine3.24-extra": "sha256:" + "0" * 64})


def test_a_base_tag_with_a_newer_digest_is_planned_and_what_it_carries_is_dropped(
        tmp_path, monkeypatch):
    """The Dockerfile raises zlib to 1.4-r0. The new base carries it, and busybox's fix,
    so neither is raised. tzdata's fix is in neither, and the index holds it."""
    _docker(tmp_path, {"zlib": "1.4-r0", "busybox": "1.37.0-r32", "tzdata": "2026a-r0"})
    blocking = [_entry("CVE-2026-0001", "busybox", "1.37.0-r31", "1.37.0-r32"),
                _entry("CVE-2026-0003", "tzdata", "2026a-r0", "2026b-r0")]

    run, plan = _plan(tmp_path, monkeypatch, blocking,
                      {**_base(NEWER), **_index(busybox="1.37.0-r32", tzdata="2026b-r0")})

    assert run.returncode == 0, run.stderr
    assert plan["base"] == {"from": PYTHON, "to": f"python:3.12-alpine3.24@{NEWER}",
                            "answers": ["CVE-2026-0001"], "rule": "the-tags-digest-moved"}
    assert plan["drops"] == [{"arg": "ALPINE_RAISE", "entry": "zlib=1.4-r0",
                              "why": "the new base carries zlib 1.4-r0"}]
    assert [r["entry"] for r in plan["raises"]] == ["tzdata=2026b-r0"]
    asked = (tmp_path / "docker.log").read_text()
    assert f"python@{NEWER}" in asked and "--network none" in asked


def test_a_base_tag_that_has_not_moved_plans_no_move_and_runs_no_container(
        tmp_path, monkeypatch):
    blocking = [_entry("CVE-2026-0001", "busybox", "1.37.0-r31", "1.37.0-r32")]

    _run, plan = _plan(tmp_path, monkeypatch, blocking,
                       {**_base("sha256:" + "e" * 64), **_index(busybox="1.37.0-r32")})

    assert plan["base"] is None and plan["drops"] == []
    assert [r["entry"] for r in plan["raises"]] == ["busybox=1.37.0-r32"]
    assert not (tmp_path / "docker.log").exists()


def test_the_same_inputs_give_the_same_bytes_and_only_three_hosts_are_asked(tmp_path, monkeypatch):
    """One run with every kind in it. Each item names what it answers and the rule that
    chose it, and the second run's plan is the first's, byte for byte."""
    _docker(tmp_path, {"zlib": "1.4-r0", "tzdata": "2026a-r0"})
    blocking = [_entry("CVE-2026-0003", "tzdata", "2026a-r0", "2026b-r0"),
                _go("CVE-2026-0010", "golang.org/x/net", "v0.60.0", "0.62.0"),
                _std("CVE-2026-97054", "v1.27.4", "1.27.5"),
                _entry("CVE-2026-0017", "soupsieve", "2.8", "2.9", kind="python-pkg")]
    answers = {**_base(NEWER), **_index(tzdata="2026b-r0"),
               **_tags("golang.org/x/net", "v0.62.0"),
               **_hub_tags("golang", "1.27.", {"1.27.5-alpine3.24": "sha256:" + "b" * 64})}

    run, plan = _plan(tmp_path, monkeypatch, blocking, answers)
    first = (tmp_path / "plan.json").read_bytes()
    again, _ = _plan(tmp_path, monkeypatch, list(reversed(blocking)), answers)

    assert run.returncode == 0 and again.returncode == 0, run.stderr + again.stderr
    assert (tmp_path / "plan.json").read_bytes() == first
    for item in [*plan["raises"], plan["base"], plan["go"]]:
        assert item["rule"] and isinstance(item["answers"], list)
    hosts = {url.split("/")[2] for url in (tmp_path / "registry" / "asked.log").read_text().split()}
    assert hosts == {"dl-cdn.alpinelinux.org", "hub.docker.com", "proxy.golang.org"}


def test_no_other_host_can_be_asked():
    sys.path.insert(0, str(IMAGE_HEAL.parent))
    import image_heal

    with pytest.raises(image_heal.Unreadable, match="not a host"):
        image_heal._get("https://example.invalid/alpine/v3.24/main/x86_64/APKINDEX.tar.gz")
    with pytest.raises(image_heal.Unreadable, match="not a host"):
        image_heal._get("https://hub.docker.com.example.invalid/v2/repositories/library/x")
