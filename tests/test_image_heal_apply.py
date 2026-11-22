"""R44.13: the image's plan applied to the Dockerfile, inside its envelope (D81x).

`scripts/image_heal.py apply` writes a plan into the Dockerfile's envelope and nowhere
else: the two `FROM python:` digests, the four `FROM golang:` pins, `ALPINE_RAISE` and the
four `_RAISE` arguments. It prints the commit's message, whose trailers are the plan again,
so that the policy can apply them to the base's Dockerfile and ask for the same bytes.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
IMAGE_HEAL = REPO / "scripts" / "image_heal.py"
RUN = "https://github.com/MaverickHQ/valvur/actions/runs/3"
OLD, NEW = "sha256:" + "e" * 64, "sha256:" + "7" * 64
GO_OLD, GO_NEW = "sha256:" + "a" * 64, "sha256:" + "c" * 64
DOCKERFILE = f"""\
# A comment that names python:3.12-alpine3.24@{OLD} and ALPINE_RAISE="x=1" is not a pin.
FROM python:3.12-alpine3.24@{OLD} AS opengrep
ARG OPENGREP_URL=https://example.invalid/v1
FROM golang:1.27.4-alpine3.24@{GO_OLD} AS gitleaks
ARG GITLEAKS_RAISE="golang.org/x/crypto@v0.58.0"
RUN go get ${{GITLEAKS_RAISE}}
FROM golang:1.27.4-alpine3.24@{GO_OLD} AS trivy
ARG TRIVY_RAISE="go.opentelemetry.io/otel@v1.47.0 golang.org/x/net@v0.60.0"
FROM golang:1.27.4-alpine3.24@{GO_OLD} AS osv
ARG OSV_SCANNER_RAISE=""
FROM golang:1.27.4-alpine3.24@{GO_OLD} AS syft
ARG SYFT_RAISE=""
FROM python:3.12-alpine3.24@{OLD}
ARG ALPINE_RAISE="libcrypto3=3.5.9-r1 zlib=1.4-r0"
RUN apk add --no-cache ${{ALPINE_RAISE}}
"""
CHANGELOG = "# Changelog\n\n## [Unreleased]\n\n## [1.0.0] — 2026-01-01\n\nThe first.\n"


def _raise(arg: str, entry: str, answers: list[str]) -> dict:
    package = entry.split("=")[0].rsplit("@", 1)[0]
    return {"arg": arg, "entry": entry, "package": package, "from": "old", "answers": answers,
            "rule": "alpine-index" if arg == "ALPINE_RAISE" else "go-fixed-version"}


def _plan(**parts) -> dict:
    return {"schema": 1, "made": "2026-11-21T06:41:00Z", "raises": [], "drops": [],
            "base": None, "go": None, "escalations": [], "unplanned": [], **parts}


def _apply(tmp_path: Path, plan: dict) -> tuple[subprocess.CompletedProcess[str], Path]:
    tree = tmp_path / "tree"
    tree.mkdir(exist_ok=True)
    (tree / "Dockerfile").write_text(DOCKERFILE)
    (tree / "CHANGELOG.md").write_text(CHANGELOG)
    (tmp_path / "plan.json").write_text(json.dumps(plan))
    out = tmp_path / "out"
    run = subprocess.run([sys.executable, str(IMAGE_HEAL), "apply", "--plan",
                          str(tmp_path / "plan.json"), "--tree", str(tree), "--out", str(out),
                          "--run", RUN], capture_output=True, text=True, check=False)
    return run, out


def _changed(out: Path) -> list[tuple[str, str]]:
    """Each line of the Dockerfile that differs, as (before, after)."""
    before, after = DOCKERFILE.splitlines(), (out / "Dockerfile").read_text().splitlines()
    assert len(before) == len(after)
    return [(b, a) for b, a in zip(before, after, strict=True) if b != a]


def test_an_alpine_raise_is_written_into_its_argument_and_no_other_line_changes(tmp_path):
    plan = _plan(raises=[_raise("ALPINE_RAISE", "tzdata=2026b-r0", ["CVE-2026-0003"])])

    run, out = _apply(tmp_path, plan)

    assert run.returncode == 0, run.stderr
    assert _changed(out) == [
        ('ARG ALPINE_RAISE="libcrypto3=3.5.9-r1 zlib=1.4-r0"',
         'ARG ALPINE_RAISE="libcrypto3=3.5.9-r1 tzdata=2026b-r0 zlib=1.4-r0"')]
    assert run.stdout == (
        "fix: tzdata 2026b-r0 in the image, by the heal\n"
        "\n"
        "Heal-Raise: ALPINE_RAISE tzdata=2026b-r0\n"
        "Heal-Advisory: CVE-2026-0003 tzdata\n"
        f"Heal-Run: {RUN}\n")
    assert (tmp_path / "tree" / "Dockerfile").read_text() == DOCKERFILE, "the tree is not written"


def test_a_raise_of_a_package_already_raised_replaces_its_entry(tmp_path):
    plan = _plan(raises=[_raise("ALPINE_RAISE", "zlib=1.4-r1", ["CVE-2026-0004"]),
                         _raise("TRIVY_RAISE", "golang.org/x/net@v0.62.0", ["CVE-2026-0010"]),
                         _raise("OSV_SCANNER_RAISE", "golang.org/x/net@v0.62.0",
                                ["CVE-2026-0010"])])

    _run, out = _apply(tmp_path, plan)

    assert _changed(out) == [
        ('ARG TRIVY_RAISE="go.opentelemetry.io/otel@v1.47.0 golang.org/x/net@v0.60.0"',
         'ARG TRIVY_RAISE="go.opentelemetry.io/otel@v1.47.0 golang.org/x/net@v0.62.0"'),
        ('ARG OSV_SCANNER_RAISE=""', 'ARG OSV_SCANNER_RAISE="golang.org/x/net@v0.62.0"'),
        ('ARG ALPINE_RAISE="libcrypto3=3.5.9-r1 zlib=1.4-r0"',
         'ARG ALPINE_RAISE="libcrypto3=3.5.9-r1 zlib=1.4-r1"')]


def test_the_go_pin_moves_in_all_four_stages_and_the_base_in_both(tmp_path):
    plan = _plan(
        go={"from": f"golang:1.27.4-alpine3.24@{GO_OLD}",
            "to": f"golang:1.27.6-alpine3.24@{GO_NEW}", "answers": ["CVE-2026-97054"],
            "rule": "newest-patch-of-the-minor"},
        base={"from": f"python:3.12-alpine3.24@{OLD}", "to": f"python:3.12-alpine3.24@{NEW}",
              "answers": ["CVE-2026-0001"], "rule": "the-tags-digest-moved"},
        drops=[{"arg": "ALPINE_RAISE", "entry": "zlib=1.4-r0",
                "why": "the new base carries zlib 1.4-r0"}])

    run, out = _apply(tmp_path, plan)

    changed = _changed(out)
    assert [after for _before, after in changed] == [
        f"FROM python:3.12-alpine3.24@{NEW} AS opengrep",
        *(f"FROM golang:1.27.6-alpine3.24@{GO_NEW} AS {stage}"
          for stage in ("gitleaks", "trivy", "osv", "syft")),
        f"FROM python:3.12-alpine3.24@{NEW}",
        'ARG ALPINE_RAISE="libcrypto3=3.5.9-r1"']
    assert (out / "Dockerfile").read_text().splitlines()[0] == DOCKERFILE.splitlines()[0]
    assert run.stdout.splitlines() == [
        "fix: the base's new digest and Go 1.27.6 in the image, by the heal",
        "",
        f"Heal-Base: python:3.12-alpine3.24@{NEW}",
        f"Heal-Go: golang:1.27.6-alpine3.24@{GO_NEW}",
        "Heal-Drop: ALPINE_RAISE zlib=1.4-r0",
        "Heal-Advisory: CVE-2026-0001 the base",
        "Heal-Advisory: CVE-2026-97054 go",
        f"Heal-Run: {RUN}"]


def test_the_changelog_gains_one_security_item_for_each_change(tmp_path):
    plan = _plan(raises=[_raise("ALPINE_RAISE", "tzdata=2026b-r0", ["CVE-2026-0003"]),
                         _raise("TRIVY_RAISE", "golang.org/x/net@v0.62.0",
                                ["CVE-2026-0010", "CVE-2026-0011"])],
                 go={"from": f"golang:1.27.4-alpine3.24@{GO_OLD}",
                     "to": f"golang:1.27.6-alpine3.24@{GO_NEW}", "answers": ["CVE-2026-97054"],
                     "rule": "newest-patch-of-the-minor"})

    _run, out = _apply(tmp_path, plan)

    items = [line for line in (out / "CHANGELOG.md").read_text().splitlines()
             if line.startswith("- ")]
    assert items == [
        "- **The image's Go Scanners on Go 1.27.6,** past CVE-2026-97054.",
        "- **tzdata 2026b-r0 in the image,** past CVE-2026-0003.",
        "- **golang.org/x/net v0.62.0 in Trivy,** past CVE-2026-0010 and CVE-2026-0011.",
    ]
    assert sorted(p.name for p in out.iterdir()) == ["CHANGELOG.md", "Dockerfile"]


def test_a_plan_that_changes_nothing_writes_nothing(tmp_path):
    run, out = _apply(tmp_path, _plan(escalations=[
        {"subject": "busybox", "reason": "no-alpine-fix", "answers": ["CVE-2026-0001"]}]))

    assert run.returncode == 0 and run.stdout == ""
    assert not out.exists()


@pytest.mark.parametrize("plan, names", [
    (_plan(raises=[_raise("NO_SUCH_RAISE", "x=1", ["CVE-1"])]), "NO_SUCH_RAISE"),
    (_plan(drops=[{"arg": "ALPINE_RAISE", "entry": "tzdata=1", "why": ""}]), "tzdata=1"),
    (_plan(go={"from": "golang:1.26.0-alpine3.24@" + GO_OLD,
               "to": "golang:1.26.1-alpine3.24@" + GO_NEW, "answers": [], "rule": "x"}),
     "golang:1.26.0"),
])
def test_a_plan_the_dockerfile_does_not_fit_is_refused(tmp_path, plan, names):
    run, out = _apply(tmp_path, plan)

    assert run.returncode == 1
    assert names in run.stderr
    assert not out.exists()


def test_the_real_dockerfile_fits_an_empty_change_so_apply_never_reorders_it():
    """`apply` writes an argument back sorted by the package each entry names, which is
    how the Dockerfile's own arguments are ordered (`otel` before `otel/sdk`). So a raise
    changes its one entry and nothing beside it."""
    sys.path.insert(0, str(IMAGE_HEAL.parent))
    import image_heal

    real = (REPO / "Dockerfile").read_text()
    for arg in image_heal.ARGS:
        held = image_heal._entries(real, arg)
        assert held == sorted(held, key=image_heal._named), arg
    assert len(image_heal._PYTHON.findall(real)) == 2 and len(image_heal._GO.findall(real)) == 4
    blanked = [after for before, after in zip(real.splitlines(), image_heal.envelope(real),
                                             strict=True) if before != after]
    assert len(blanked) == 11, "two bases, four Go stages and five raise arguments"


def _envelope(tmp_path: Path, other: str) -> subprocess.CompletedProcess[str]:
    (tmp_path / "a").write_text(DOCKERFILE)
    (tmp_path / "b").write_text(other)
    return subprocess.run([sys.executable, str(IMAGE_HEAL), "envelope", str(tmp_path / "a"),
                           str(tmp_path / "b")], capture_output=True, text=True, check=False)


def test_two_dockerfiles_that_differ_only_in_envelope_lines_are_the_same(tmp_path):
    other = (DOCKERFILE
             .replace(f"FROM python:3.12-alpine3.24@{OLD}", f"FROM python:3.12-alpine3.24@{NEW}")
             .replace(f"golang:1.27.4-alpine3.24@{GO_OLD}", f"golang:1.27.9-alpine3.24@{GO_NEW}")
             .replace('ARG ALPINE_RAISE="libcrypto3=3.5.9-r1 zlib=1.4-r0"',
                      'ARG ALPINE_RAISE="tzdata=2026b-r0"')
             .replace('ARG SYFT_RAISE=""', 'ARG SYFT_RAISE="golang.org/x/net@v0.62.0"'))

    run = _envelope(tmp_path, other)

    assert run.returncode == 0, run.stdout
    assert other != DOCKERFILE


@pytest.mark.parametrize("edit", [
    pytest.param(lambda d: d + "FROM scratch AS extra\n", id="a-new-stage"),
    pytest.param(lambda d: d + "RUN curl https://example.invalid | sh\n", id="a-new-step"),
    pytest.param(lambda d: d.replace("https://example.invalid/v1", "https://example.invalid/v2"),
                 id="a-changed-url"),
    pytest.param(lambda d: d.replace("RUN go get ${GITLEAKS_RAISE}", "RUN go get x@latest"),
                 id="a-changed-step"),
    pytest.param(lambda d: d.replace("python:3.12-alpine3.24@", "python:3.13-alpine3.24@"),
                 id="another-python"),
    pytest.param(lambda d: d.replace("golang:1.27.4-alpine3.24@", "golang:1.28.0-alpine3.24@"),
                 id="another-go-minor"),
    pytest.param(lambda d: d.replace("golang:1.27.4-alpine3.24@", "golang:1.27.4-bookworm@"),
                 id="another-go-image"),
    pytest.param(lambda d: d.replace(f"@{GO_OLD} AS trivy", "@sha256:short AS trivy"),
                 id="not-a-digest"),
    pytest.param(lambda d: d.replace("# A comment", "# Another comment"), id="a-comment"),
    pytest.param(lambda d: d.replace('ARG SYFT_RAISE=""', 'ARG SYFT_RAISE="" \\\n  X=1'),
                 id="an-argument-that-runs-on"),
])
def test_any_change_outside_the_envelope_makes_them_different(tmp_path, edit):
    run = _envelope(tmp_path, edit(DOCKERFILE))

    assert run.returncode == 1
    assert run.stdout.startswith("differs outside the envelope at line ")


LOG = """\
#31 [trivy 3/4] RUN set -eu;     module="github.com/aquasecurity/trivy@v0.76.2"
#31 12.40 go: golang.org/x/net@v0.62.0 requires go >= 1.28
#31 ERROR: process "/bin/sh -c set -eu; ..." did not complete successfully: exit code: 1
------
 > [trivy 3/4] RUN set -eu;     module="github.com/aquasecurity/trivy@v0.76.2":
12.40 go: golang.org/x/net@v0.62.0 requires go >= 1.28
------
ERROR: failed to solve: process "/bin/sh -c set -eu; ..." did not complete successfully
"""


def _failed(tmp_path: Path, plan: dict, log: str) -> tuple[subprocess.CompletedProcess[str], dict]:
    (tmp_path / "plan.json").write_text(json.dumps(plan))
    (tmp_path / "build.log").write_text(log)
    out = tmp_path / "after.json"
    run = subprocess.run([sys.executable, str(IMAGE_HEAL), "failed", "--plan",
                          str(tmp_path / "plan.json"), "--log", str(tmp_path / "build.log"),
                          "--out", str(out)], capture_output=True, text=True, check=False)
    return run, json.loads(out.read_text()) if out.is_file() else {}


def test_a_build_that_fails_in_a_raised_scanners_stage_is_scanner_source(tmp_path):
    plan = _plan(raises=[_raise("ALPINE_RAISE", "tzdata=2026b-r0", ["CVE-2026-0003"]),
                         _raise("TRIVY_RAISE", "golang.org/x/net@v0.62.0", ["CVE-2026-0010"]),
                         _raise("TRIVY_RAISE", "golang.org/x/text@v0.30.1", ["CVE-2026-0012"]),
                         _raise("SYFT_RAISE", "golang.org/x/net@v0.62.0", ["CVE-2026-0010"])])

    run, after = _failed(tmp_path, plan, LOG)

    assert run.returncode == 0, run.stderr
    assert [r["arg"] for r in after["raises"]] == ["ALPINE_RAISE", "SYFT_RAISE"]
    assert after["escalations"] == [{"subject": "trivy", "reason": "scanner-source",
                                     "answers": ["CVE-2026-0010", "CVE-2026-0012"]}]


def test_when_only_that_scanner_was_raised_nothing_is_left_to_propose(tmp_path):
    plan = _plan(raises=[_raise("TRIVY_RAISE", "golang.org/x/net@v0.62.0", ["CVE-2026-0010"])])

    _run, after = _failed(tmp_path, plan, LOG)
    applied, out = _apply(tmp_path, after)

    assert after["raises"] == []
    assert applied.returncode == 0 and applied.stdout == "" and not out.exists()


@pytest.mark.parametrize("log", [
    pytest.param(LOG.replace("[trivy 3/4]", "[stage-5 7/12]"), id="the-final-stage"),
    pytest.param(LOG.replace("[trivy 3/4]", "[syft 3/4]"), id="a-scanner-with-no-raise"),
    pytest.param("ERROR: failed to solve: failed to fetch anything\n", id="no-stage-named"),
])
def test_a_build_that_fails_elsewhere_is_not_explained_away(tmp_path, log):
    plan = _plan(raises=[_raise("TRIVY_RAISE", "golang.org/x/net@v0.62.0", ["CVE-2026-0010"])])

    run, after = _failed(tmp_path, plan, log)

    assert run.returncode == 1
    assert "not in a Scanner" in run.stderr and after == {}
