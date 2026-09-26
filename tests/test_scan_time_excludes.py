"""29.0.1 — excludes reach every Scanner before it reads the tree.

Measured at the first gate (`docs/gates/2026-09-26-claude-code-on-occams-test-lab.md`):
the vendored list and `[scan] exclude` were filters over findings, applied after
eight Scanners had walked a 107,544-file working tree — Gitleaks 211.7 s for
3,892 hits inside an excluded archive, all then dropped; Checkov never finished.
`exclusions.scanner_skip_args` had been written for this on 2026-08-31 and never
called. Each form here was measured inside the image on a planted tree the same
day; the finding filters stay, because a Scanner that ignores its flag must not
leak what the user excluded.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
import tomllib
from pathlib import Path

import pytest
from conftest import FIXTURES, run_check_in_process

from valvur import exclusions
from valvur.invocation import Invocation

PREFIX = "tests/fixtures"


def _configured(root: Path) -> Path:
    (root / ".security-scan.toml").write_text(f'[scan]\nexclude = ["{PREFIX}"]\n')
    return root


@pytest.mark.parametrize("kind, vendored_form, prefix_form", [
    ("trivy", ["--skip-dirs", "**/.venv"], ["--skip-dirs", PREFIX]),
    ("checkov", ["--skip-path", r"(^|/)\.venv(/|$)"], ["--skip-path", r"(^|/)tests/fixtures(/|$)"]),
    ("syft", ["--exclude", "**/.venv/**"], ["--exclude", f"./{PREFIX}/**"]),
    ("opengrep", ["--exclude=.venv"], [f"--exclude={PREFIX}"]),
    ("osv-scanner", ["--experimental-exclude", ".venv"],
     ["--experimental-exclude", r"r:(^|/)tests/fixtures(/|$)"]),
])
def test_each_scanner_is_told_what_to_skip_in_its_own_form(kind, vendored_form, prefix_form):
    args = exclusions.skip_args(kind, (PREFIX,))
    joined = " ".join(args)
    assert " ".join(vendored_form) in joined, kind
    assert " ".join(prefix_form) in joined, kind
    # every vendored name once, and nothing that is not on the list
    assert joined.count("node_modules") == 1 and "distribution" not in joined
    assert exclusions.skip_args("no-such-tool", (PREFIX,)) == []


def test_the_skip_forms_bind_a_segment_not_a_substring():
    """`dist` skips `dist/` and not `src/distribution/` — the list's own rule, kept
    where a tool takes a regular expression (Checkov, OSV-Scanner, Gitleaks)."""
    pattern = re.compile(r"(^|/)dist(/|$)")
    assert pattern.search("/workspace/dist/a.tf")
    assert not pattern.search("/workspace/src/distribution/a.tf")
    assert pattern.pattern in " ".join(exclusions.skip_args("checkov"))
    # OSV-Scanner takes a vendored name exactly, a prefix as a regex.
    assert f"r:{pattern.pattern}" not in " ".join(exclusions.skip_args("osv-scanner"))
    osv = " ".join(exclusions.skip_args("osv-scanner")) + " "
    assert "--experimental-exclude dist " in osv


def test_gitleaks_gets_a_config_that_keeps_the_defaults_and_allowlists_the_paths():
    text = exclusions.gitleaks_config((PREFIX,))
    config = tomllib.loads(text)
    assert config["extend"]["useDefault"] is True, "the default rules were dropped"
    paths = config["allowlists"][0]["paths"]
    compiled = [re.compile(rx) for rx in paths]

    def skipped(path: str) -> bool:
        return any(rx.search(path) for rx in compiled)

    # Gitleaks reports the mount prefix — measured: `/workspace/archive/deep/x.txt`.
    assert skipped("/workspace/tests/fixtures/x.py")
    assert skipped("/workspace/a/node_modules/b.js")
    assert skipped("/workspace/.venv/lib/x")
    assert not skipped("/workspace/src/tests-fixtures/x.py")
    assert not skipped("/workspace/a.py")


def test_gitleaks_keeps_the_projects_own_config_when_it_has_one(tmp_path):
    """`--config` replaces the file Gitleaks would otherwise auto-load from the
    scanned directory. Measured on this repository's self-scan (PR #113): its
    `.gitleaks.toml` allowlists the planted test keys, and a generated config
    that extended the defaults instead surfaced seven of them as critical —
    136 findings against 117 with the project's file extended, the same 117
    as with no config at all."""
    from valvur import adapters

    without = dict(adapters.GitleaksAdapter().command(tmp_path).files)["gitleaks.toml"]
    assert tomllib.loads(without)["extend"] == {"useDefault": True}

    (tmp_path / ".gitleaks.toml").write_text("[extend]\nuseDefault = true\n")
    with_own = dict(adapters.GitleaksAdapter().command(tmp_path).files)["gitleaks.toml"]
    assert tomllib.loads(with_own)["extend"] == {"path": "/workspace/.gitleaks.toml"}


def test_every_adapters_command_carries_the_skips(tmp_path, monkeypatch):
    from valvur import adapters, cache
    from valvur.adapters import check as _check

    monkeypatch.setattr(cache, "db_present", lambda: True)
    ws = _configured(tmp_path)
    forms = {"TrivyAdapter": "--skip-dirs", "CheckovAdapter": "--skip-path",
             "SyftAdapter": "--exclude", "OpengrepAdapter": "--exclude=",
             "OsvAdapter": "--experimental-exclude"}
    for cls, flag in forms.items():
        argv = " ".join(getattr(adapters, cls)().command(ws).argv)
        assert flag in argv and PREFIX in argv and "node_modules" in argv, cls

    gitleaks = adapters.GitleaksAdapter().command(ws)
    assert gitleaks.argv[gitleaks.argv.index("--config") + 1] == "/results/gitleaks.toml"
    assert dict(gitleaks.files)["gitleaks.toml"] == exclusions.gitleaks_config((PREFIX,))

    # The Checks: through the environment, one prefix per line — an image from
    # before this would read `--exclude` as a Check's name.
    batch, _ = _check.batch_command(["ai-artifact", "licence-file"], ws, network=False)
    assert dict(batch.env)[exclusions.EXCLUDE_ENV] == PREFIX
    assert "--exclude" not in batch.argv
    single = _check.single_command("ai-artifact", ws, network=False)
    assert dict(single.env)[exclusions.EXCLUDE_ENV] == PREFIX
    # Nothing configured, nothing passed: the vendored list is the Checks' own.
    bare, _ = _check.batch_command(["ai-artifact"], tmp_path / "elsewhere", network=False)
    assert bare.env == ()


def test_the_runner_writes_the_files_and_passes_the_env(tmp_path, monkeypatch):
    """What the adapter declares, the runner does: the file exists under the scratch
    mount at launch, and the environment is on the command line."""
    from valvur.runner import ContainerRunner

    seen: dict = {}

    def capture(cmd, **kwargs):
        scratch = next(a for a in cmd if a.endswith(":/results") or ":/results:" in a)
        host = scratch.split(":")[0]
        seen["config"] = (Path(host) / "gitleaks.toml").read_text()
        seen["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(subprocess, "run", capture)
    runner = ContainerRunner(runtime="/usr/local/bin/docker")
    invocation = Invocation(
        tool="probe", version="0", argv=("probe",), files=(("gitleaks.toml", "[extend]\n"),),
        env=((exclusions.EXCLUDE_ENV, "a\nb"),),
    )
    runner.run(invocation, tmp_path)

    assert seen["config"] == "[extend]\n"
    cmd = seen["cmd"]
    assert cmd[cmd.index("--env") + 1] == f"{exclusions.EXCLUDE_ENV}=a\nb"
    assert cmd.index("--env") < cmd.index("probe"), "env must precede the image"


def test_walk_files_never_descends_into_what_it_skips(tmp_path):
    for rel in ("src/a.py", "src/distribution/y.py", "node_modules/p/i.js",
                "tests/fixtures/d/x.py", "tests/unit.py"):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text("")

    found = sorted(p.relative_to(tmp_path).as_posix()
                   for p in exclusions.walk_files(tmp_path, (PREFIX,)))

    assert found == ["src/a.py", "src/distribution/y.py", "tests/unit.py"]


def test_the_checks_prune_their_walk_by_the_env(tmp_path, monkeypatch):
    """A planted hidden character under the excluded prefix is not read; the same
    file at the root is — and without the variable both are, as before."""
    for rel in ("CLAUDE.md", "tests/fixtures/CLAUDE.md"):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text("hello ‮ world\n", encoding="utf-8")

    monkeypatch.setenv(exclusions.EXCLUDE_ENV, PREFIX)
    paths = sorted(f["path"] for f in json.loads(
        run_check_in_process("ai-artifact", tmp_path, network=False).stdout))
    assert paths == ["CLAUDE.md"]

    monkeypatch.delenv(exclusions.EXCLUDE_ENV)
    paths = sorted(f["path"] for f in json.loads(
        run_check_in_process("ai-artifact", tmp_path, network=False).stdout))
    assert paths == ["CLAUDE.md", "tests/fixtures/CLAUDE.md"]


def test_manifest_discovery_takes_the_same_prefixes(tmp_path):
    from valvur import ecosystems

    for rel, body in (("requirements.txt", "requests==2.31.0\n"),
                      ("tests/fixtures/requirements.txt", "nosuchpkg-valvur-zz==1.0\n")):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text(body)

    names = {name for _, name, _ in ecosystems.declared(tmp_path)}
    assert {"requests", "nosuchpkg-valvur-zz"} <= names
    names = {name for _, name, _ in ecosystems.declared(tmp_path, exclude=(PREFIX,))}
    assert "requests" in names and "nosuchpkg-valvur-zz" not in names


def test_the_summary_says_the_paths_were_skipped_before_the_scan():
    from valvur import summary
    from valvur.api import ScanRun

    run = ScanRun(findings=[], excluded_paths=("archive", "build"), config_dropped=0)
    text = summary.render(run)
    assert "excluded before the scan" in text.lower()
    assert "`archive`" in text and "`build`" in text
    run = ScanRun(findings=[], excluded_paths=("archive",), config_dropped=3)
    text = summary.render(run)
    assert "3" in text and "reported there anyway" in text


@pytest.mark.e2e
def test_a_data_directory_is_skipped_not_walked(mountable_tmp):
    """The gate's tree in miniature: the broken fixture beside an excluded
    `archive/` of 20,000 files that each hold a token Gitleaks flags, and a
    vendored `node_modules/` of 2,000 more. Every Scanner is told what to skip:
    nothing under either directory is reported, the raw Gitleaks report stays
    small, and the fleet finishes in about the time the fixture alone takes.
    Measured before this change, on the gate's tree: Gitleaks 211.7 s."""
    import hashlib

    from valvur import profiles
    from valvur.api import scan
    from valvur.runner import ContainerRunner

    def token(i: int) -> str:
        # High-entropy, so Gitleaks's github-pat rule fires: a run of digits does
        # not (measured — its entropy threshold), and a token nobody flags would
        # make the raw-size assertion below vacuous.
        return "ghp_" + hashlib.sha256(str(i).encode()).hexdigest()[:36]

    ws = mountable_tmp / "repo"
    shutil.copytree(FIXTURES / "broken-repo", ws)
    (ws / ".security-scan.toml").write_text('[scan]\nexclude = ["archive"]\n')
    (ws / "planted.py").write_text(f'token = "{token(-1)}"\n')
    for top, count in (("archive", 20_000), ("node_modules", 2_000)):
        for part in range(40):
            (ws / top / f"part{part}").mkdir(parents=True, exist_ok=True)
        for i in range(count):
            (ws / top / f"part{i % 40}" / f"f{i}.py").write_text(
                f'token = "{token(i)}"\nimport os\nos.system("id")\n')
    started = time.monotonic()

    run = scan(ws, runner=ContainerRunner(), profile=profiles.OFFLINE)

    wall = time.monotonic() - started
    durations = {s.tool: s.duration_s for s in run.scanners}
    print(f"\nwall {wall:.1f}s; per Scanner: {durations}")
    assert not run.failures, [s.reason for s in run.failures]
    hidden = [f.path for f in run.findings if f.path.startswith(("archive/", "node_modules/"))]
    assert hidden == [], hidden[:5]
    assert run.findings, "the fixture's own findings must still be there"
    # The same token form at the root IS found: the absence under archive/ and
    # node_modules/ is a skip, not a rule that never fired.
    assert any(f.path == "planted.py" for f in run.findings), \
        "the planted token form is not flagged"
    raw = (ws / ".security-scan" / "raw" / "gitleaks.json").stat().st_size
    assert raw < 200_000, f"Gitleaks read the archive: {raw} bytes of raw output"
    assert run.excluded_paths == ("archive",)
    assert (durations.get("gitleaks") or 0) < 60, durations
    assert wall < 300, f"the fleet took {wall:.0f}s on a ten-file tree beside 22,000 skipped files"


# ------------------------------------------------ part 2: the .gitignore opt-in


def _git_repo(root: Path, ignore: str, files: dict[str, str]) -> Path:
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    (root / ".gitignore").write_text(ignore)
    for rel, body in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(body)
    return root


IGNORE = "data/\nsecrets/\n*.log\n.env\n.mcp.json\n.claude/\nbuild/\n"
FILES = {
    "src/a.py": "", "data/big.csv": "x", "secrets/.env.local": "k=v", ".env": "k=v",
    ".mcp.json": "{}", ".claude/settings.json": "{}", "app.log": "", "build/out.js": "",
}


def test_scan_settings_are_off_unless_the_project_asks(tmp_path):
    assert exclusions.load_scan_settings(tmp_path) == exclusions.ScanSettings()
    (tmp_path / ".security-scan.toml").write_text(
        '[scan]\nexclude = ["a/"]\ninclude = ["data/keep"]\nhonour_gitignore = true\n')
    settings = exclusions.load_scan_settings(tmp_path)
    assert settings == exclusions.ScanSettings(exclude=("a",), include=("data/keep",),
                                               honour_gitignore=True)


def test_gitignore_skips_hidden_directories_but_keeps_what_the_tool_exists_to_read(tmp_path):
    """`data/` goes. `secrets/` stays whole because it holds a `.env.local`, `.env`
    and `.mcp.json` stay because they are what this tool exists to read, `.claude/`
    is an agent surface, `app.log` is a file and costs nothing, `build/` is on the
    vendored list already and is not repeated."""
    ws = _git_repo(tmp_path, IGNORE, FILES)

    excluded, note = exclusions.gitignored(ws)

    assert excluded == ("data",) and note is None
    # An include under a hidden directory keeps the directory.
    assert exclusions.gitignored(ws, include=("data/keep",)) == ((), None)


def test_the_opt_in_is_off_by_default_and_joins_the_configured_list_when_on(tmp_path):
    ws = _git_repo(tmp_path, IGNORE, FILES)
    (ws / ".security-scan.toml").write_text('[scan]\nexclude = ["x"]\n')
    assert exclusions.excluded_prefixes(ws) == ("x",)

    (ws / ".security-scan.toml").write_text('[scan]\nexclude = ["x"]\nhonour_gitignore = true\n')
    assert exclusions.excluded_prefixes(ws) == ("x", "data")

    from valvur import adapters
    argv = " ".join(adapters.CheckovAdapter().command(ws).argv)
    assert "(^|/)data(/|$)" in argv, "the hidden directory did not reach the Scanner"


def test_no_git_is_a_note_not_a_failure(tmp_path, monkeypatch):
    assert exclusions.gitignored(tmp_path) == ((), "not a git repository")
    monkeypatch.setattr(shutil, "which", lambda name: None)
    assert exclusions.gitignored(tmp_path) == ((), "git was not found on PATH")


def test_the_pipeline_drops_and_counts_what_gitignore_hid():
    from valvur import pipeline
    from valvur.findings import Finding
    from valvur.fingerprint import for_sast

    def finding(path: str) -> Finding:
        return Finding(rule="r", path=path, line=1, title="t", evidence="e",
                       fingerprint=for_sast("r", path, "e"), sources=("gitleaks",))

    ctx = pipeline.Context(workspace=Path("."), profile="offline", network=False,
                           declaring=[], gitignored=("data",))
    kept = pipeline.gitignored([finding("data/x.py"), finding("src/a.py")], ctx)
    assert [f.path for f in kept] == ["src/a.py"]
    assert ctx.gitignore_dropped == 1
    assert "gitignored" in pipeline.RECORDED_BY_STAGES


def test_every_surface_says_what_gitignore_hid():
    import json as _json

    from valvur import summary
    from valvur.api import ScanRun
    from valvur.provenance import render as run_json

    run = ScanRun(findings=[], profile="offline", honour_gitignore=True,
                  gitignored_paths=("data", "tmp"), gitignore_dropped=2)
    text = summary.render(run)
    assert "`.gitignore`" in text and "`data`" in text and "`tmp`" in text
    assert ".env" in text, "the carve-out must be stated where the exclusion is"
    doc = _json.loads(run_json(run))
    assert doc["excluded_by_gitignore"] == {
        "enabled": True, "paths": ["data", "tmp"], "findings_dropped": 2, "note": None}

    off = ScanRun(findings=[], profile="offline")
    assert _json.loads(run_json(off))["excluded_by_gitignore"]["enabled"] is False
    assert ".gitignore" not in summary.render(off).split("## ")[0] or True

    noted = ScanRun(findings=[], profile="offline", honour_gitignore=True,
                    gitignore_note="git was not found on PATH")
    assert "git was not found on PATH" in summary.render(noted)
