#!/usr/bin/env python3
"""The acceptance set (task R2.1): eight repositories, each built from nothing.

    python3 scripts/acceptance/generate.py DEST            # all eight
    python3 scripts/acceptance/generate.py DEST --only 4   # one, by number or name

Every later phase is judged on these (tasks.md §4). Each repository carries an
`expected.toml` naming what a scan must find, what it must not, and `until` on an
expectation a later task delivers. Building is deterministic: fixed contents, and in
the git repositories a fixed author and date, so two builds are the same trees with
the same commit ids. Planted credentials are assembled at runtime; push protection is
on for this repository, and no literal credential is written in it.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
BROKEN = REPO / "tests" / "fixtures" / "broken-repo"
CORPUS_CHECKOUTS = REPO / "tests" / "corpus" / ".checkouts"
TERRAFORM_URL = "https://github.com/terraform-aws-modules/terraform-aws-vpc"
TERRAFORM_PIN = "cf0e3ca46fd51f47bf095957f2a6ac6127c89045"   # tests/corpus/corpus.toml
#: This repository at the commit R0 landed on `main` (2026-09-27).
SELF_PIN = "0d85768"
#: A known-malicious npm package (OSV `MAL-2023-1`), named in a manifest, never installed.
MALICIOUS = ("@hyperion-util/cookies", "77.77.79", "MAL-2023-1")
#: The gate's shape: its archive held 103,251 files.
DATA_FILES = 100_000

_GIT_ENV = {
    "GIT_AUTHOR_NAME": "acceptance", "GIT_AUTHOR_EMAIL": "acceptance@example.invalid",
    "GIT_COMMITTER_NAME": "acceptance", "GIT_COMMITTER_EMAIL": "acceptance@example.invalid",
}


def _flow(tag: str) -> str:
    """A shell-injection flow Opengrep's `subprocess-shell-true` rule reports."""
    return f"import subprocess\n\n\ndef run_{tag}(value):\n" \
           f"    subprocess.call(value, shell=True)\n"


def _write(root: Path, files: dict[str, str]) -> None:
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


def _git(root: Path, *args: str, when: int = 1_790_000_000) -> None:
    env = {**os.environ, **_GIT_ENV, "GIT_AUTHOR_DATE": f"{when} +0000",
           "GIT_COMMITTER_DATE": f"{when} +0000"}
    subprocess.run(["git", "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null",  # noqa: S603
                    *args], cwd=root, env=env, check=True, capture_output=True)


def _commit_all(root: Path, message: str, when: int = 1_790_000_000) -> None:
    if not (root / ".git").exists():
        _git(root, "init", "-q", "-b", "main")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", message, when=when)


def _expected(root: Path, text: str) -> None:
    (root / "expected.toml").write_text(text.strip() + "\n", encoding="utf-8")


# ------------------------------------------------------------------ the eight


def gate_shaped(root: Path, data_files: int = DATA_FILES) -> None:
    """1. A few hundred source files, a large gitignored data directory, a `.venv`."""
    files = {f"src/pkg/mod_{i:03}.py": f"VALUE_{i} = {i}\n" for i in range(300)}
    files["src/pkg/runner.py"] = _flow("gate")
    files[".gitignore"] = "data/\n.venv/\n"
    files["README.md"] = "# gate-shaped\n"
    _write(root, files)
    _commit_all(root, "the source")
    for i in range(data_files):
        path = root / "data" / f"batch_{i // 1000:03}" / f"{i:06}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('{"k": "' + f"{i:032x}" + '"}\n', encoding="utf-8")
    _write(root, {f".venv/lib/site-packages/dep_{i}/__init__.py": "" for i in range(50)})
    _expected(root, """
[run]
complete = true
[timing]
mac_warm_seconds = 30
until = "R3.2"

[[must]]
rule = "subprocess-shell-true"
path = "src/pkg/runner.py"

[[must_not]]
path_prefix = "data/"
[[must_not]]
path_prefix = ".venv/"
""")


def lockfiles(root: Path) -> None:
    """2. `broken-repo`: lockfiles with known CVEs, a secret, agent files, Terraform."""
    shutil.copytree(BROKEN, root, dirs_exist_ok=True)
    _expected(root, """
[run]
complete = true

[[must]]
rule = "aws-access-token"
path = "config.py"
[[must]]
rule = "CVE-2020-14343"
path = "requirements.txt"
[[must]]
rule = "CVE-2021-44906"
path = "package-lock.json"
[[must]]
rule = "valvur.dependency.nonexistent"
path = "requirements-ai.txt"
[[must]]
rule = "valvur.ai-artifact.prompt-injection"
path = "AGENTS.md"
[[must]]
rule = "valvur.ai-artifact.hidden-unicode"
path = "CLAUDE.md"
[[must]]
rule = "valvur.ai-artifact.permission-bypass"
path = ".claude/settings.json"
[[must]]
rule = "valvur.llm.output-to-shell"
path = "llm_app.py"
[[must]]
rule = "subprocess-shell-true"
path = "handler.py"
[[must]]
rule = "CKV_AWS_18"
path = "main.tf"
[[must]]
rule = "mutable-action-ref"
path = ".github/workflows/ci.yml"
""")


def history_secret(root: Path) -> None:
    """3. A credential committed, then removed in the next commit."""
    key = "AKIA" + "QX3ZR5TW7YB2MN4P"            # assembled: push protection is on
    _write(root, {"config.py": f'AWS_ACCESS_KEY_ID = "{key}"\n', "README.md": "# history\n"})
    _commit_all(root, "add the config", when=1_790_000_000)
    _write(root, {"config.py": 'import os\n\nAWS_ACCESS_KEY_ID = os.environ["AWS_KEY"]\n'})
    _commit_all(root, "read the key from the environment", when=1_790_000_100)
    _expected(root, """
[run]
complete = true

[[must]]
rule = "aws-access-token"
path = "config.py"
until = "R3.7"
""")


def nested_names(root: Path) -> None:
    """4. Flows in `archive/`, `src/archive/`, `mypkg/build/` and `src/app/`, with
    `archive` excluded: only the top-level one may go unread."""
    _write(root, {"archive/app.py": _flow("archive"), "src/archive/app.py": _flow("nested"),
                  "mypkg/build/steps.py": _flow("build"), "src/app/app.py": _flow("app"),
                  ".security-scan.toml": '[scan]\nexclude = ["archive"]\n'})
    _commit_all(root, "nested names")
    _expected(root, """
[run]
complete = true

[[must]]
rule = "subprocess-shell-true"
path = "src/archive/app.py"
[[must]]
rule = "subprocess-shell-true"
path = "src/app/app.py"
[[must]]
rule = "subprocess-shell-true"
path = "mypkg/build/steps.py"
until = "R3.2"

[[must_not]]
path_prefix = "archive/"
""")


def infrastructure(root: Path) -> None:
    """5. `terraform-aws-vpc` at the corpus's pin."""
    source = CORPUS_CHECKOUTS / "terraform-aws-vpc"
    if not (source / ".git").exists():
        source = root.parent / ".terraform-aws-vpc-clone"
        if not source.exists():
            subprocess.run(["git", "clone", "-q", TERRAFORM_URL, str(source)], check=True)  # noqa: S603
    archive = subprocess.run(["git", "-C", str(source), "archive", TERRAFORM_PIN],  # noqa: S603
                             check=True, capture_output=True).stdout
    root.mkdir(parents=True, exist_ok=True)
    subprocess.run(["tar", "-x", "-C", str(root)], input=archive, check=True)  # noqa: S603
    _expected(root, """
[run]
complete = true

[[must]]
rule = "CKV2_AWS_12"
[[must]]
rule = "CKV_AWS_338"
""")


def self_at_pin(root: Path) -> None:
    """6. This repository at a pinned commit: it passes its own gate (N2.5)."""
    archive = subprocess.run(["git", "-C", str(REPO), "archive", SELF_PIN],  # noqa: S603
                             check=True, capture_output=True).stdout
    root.mkdir(parents=True, exist_ok=True)
    subprocess.run(["tar", "-x", "-C", str(root)], input=archive, check=True)  # noqa: S603
    _expected(root, """
[run]
complete = true
""")


def local_exposure(root: Path) -> None:
    """7. An unignored `.mcp.json` holding an absolute home path, and a workflow whose
    default permissions are write-all: what the owner's 2026-09-27 audit found."""
    mcp = {"mcpServers": {"tool": {"command": "/Users/example/tools/run-tool",
                                   "args": ["--stdio"]}}}
    workflow = ("name: deploy\non: push\npermissions: write-all\njobs:\n  deploy:\n"
                "    runs-on: ubuntu-24.04\n    steps:\n"
                "      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n"
                "      - run: echo deploy\n")
    _write(root, {".mcp.json": json.dumps(mcp, indent=2) + "\n",
                  ".github/workflows/deploy.yml": workflow, "README.md": "# exposure\n"})
    _commit_all(root, "local exposure")
    _expected(root, """
[run]
complete = true

[[must]]
rule = "local-config-exposed"
path = ".mcp.json"
until = "R5.3"
[[must]]
rule = "excessive-permissions"
path = ".github/workflows/deploy.yml"
until = "R4.2"
""")


def malicious_dependency(root: Path) -> None:
    """8. A manifest and lockfile naming a known-malicious package. Never installed."""
    name, version, _mal = MALICIOUS
    manifest = {"name": "acceptance-8", "version": "1.0.0",
                "dependencies": {name: version}}
    lock = {"name": "acceptance-8", "version": "1.0.0", "lockfileVersion": 3,
            "requires": True, "packages": {
                "": {"name": "acceptance-8", "version": "1.0.0",
                     "dependencies": {name: version}},
                f"node_modules/{name}": {"version": version}}}
    _write(root, {"package.json": json.dumps(manifest, indent=2) + "\n",
                  "package-lock.json": json.dumps(lock, indent=2) + "\n"})
    _commit_all(root, "a malicious dependency")
    _expected(root, f"""
[run]
complete = true

[[must]]
rule = "{_mal}"
path = "package-lock.json"
until = "R4.6"
""")


BUILDERS: dict[str, Callable[[Path], None]] = {
    "1-gate-shaped": gate_shaped, "2-lockfiles": lockfiles,
    "3-history-secret": history_secret, "4-nested-names": nested_names,
    "5-infrastructure": infrastructure, "6-self": self_at_pin,
    "7-local-exposure": local_exposure, "8-malicious-dependency": malicious_dependency,
}


def build(dest: Path, only: str | None = None, *,
          data_files: int = DATA_FILES) -> dict[str, Path]:
    """Build the set, or one repository, under `dest`; returns name -> path.
    `data_files` sizes repository 1's ignored data directory (tests use a few)."""
    built: dict[str, Path] = {}
    for name, builder in BUILDERS.items():
        if only is not None and only not in (name, name.split("-", 1)[0]):
            continue
        root = dest / name
        if root.exists():
            shutil.rmtree(root)
        root.mkdir(parents=True)
        if builder is gate_shaped:
            gate_shaped(root, data_files=data_files)
        else:
            builder(root)
        built[name] = root
    return built


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("dest", type=Path)
    parser.add_argument("--only", help="one repository, by number or name")
    args = parser.parse_args(argv)
    for name, root in build(args.dest, args.only).items():
        print(f"{name}: {root}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
