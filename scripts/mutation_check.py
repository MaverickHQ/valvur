#!/usr/bin/env python3
"""Every hunk of a change under `src/valvur`, reverted in turn (task 28.4.4, X1).

Five tests on 2026-09-22 passed against the defect each was written for — a lazy
import invisible to a module-level probe, an orphaned container that merely
finished inside the window, a scan argument named `path`, goldens blind to their
own line cap, an order assertion comparing a dict with the constant it is built
from — and all five were caught by hand mutation, one person's habit. This is the
habit as a script, scoped to the diff: put each hunk's old lines back, run the
unit suite, and report the hunks no test noticed. Those are the changes the
change's own tests do not cover.

    scripts/mutation_check.py --base origin/main

A hunk that changes only comments or docstrings is skipped: reverting it changes
nothing a test could see. Exit status is 0 whatever the verdicts — the job that
runs this in CI reports and does not gate (non-required at first) — unless
`--strict` is given.
"""

from __future__ import annotations

import argparse
import ast
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

SCOPE = "src/valvur"
UNIT = [sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", "-m", "not e2e"]


@dataclass
class Hunk:
    path: str
    header: str
    body: list[str] = field(default_factory=list)

    @property
    def added(self) -> list[str]:
        return [line[1:] for line in self.body if line.startswith("+")]

    @property
    def removed(self) -> list[str]:
        return [line[1:] for line in self.body if line.startswith("-")]


def hunks(diff: str) -> list[Hunk]:
    """One Hunk per `@@` block, each knowing its file."""
    found: list[Hunk] = []
    path = ""
    for line in diff.splitlines():
        if line.startswith("+++ b/"):
            path = line[len("+++ b/"):]
        elif line.startswith("@@"):
            found.append(Hunk(path, line))
        elif found and path and (line[:1] in "+-" and not line.startswith(("+++", "---"))):
            found[-1].body.append(line)
        elif found and line.startswith("\\ No newline"):
            found[-1].body.append(line)
    return found


def revert_patch(hunk: Hunk) -> str:
    """A patch of this hunk alone, with its file headers, for `git apply -R`."""
    return "\n".join([f"--- a/{hunk.path}", f"+++ b/{hunk.path}", hunk.header, *hunk.body]) + "\n"


def _stripped(source: str) -> str:
    """The AST with docstrings removed and comments already gone: what a test can see."""
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
            body = getattr(node, "body", None)
            if (body and isinstance(body[0], ast.Expr)
                    and isinstance(body[0].value, ast.Constant)
                    and isinstance(body[0].value.value, str)):
                del body[0]
    return ast.dump(tree)


def code_changed(before: str, after: str) -> bool:
    """Whether two versions of a module differ in anything but comments and docstrings."""
    try:
        return _stripped(before) != _stripped(after)
    except SyntaxError:
        return True


def _git(repo: Path, *args: str, check: bool = True, input: str | None = None) -> str:
    proc = subprocess.run(  # noqa: S603 — git, with arguments this script wrote
        ["git", "-C", str(repo), *args], capture_output=True, text=True, check=False, input=input)
    if check and proc.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)}: {proc.stderr.strip()}")
    return proc.stdout


def run(repo: Path, *, base: str, pytest_args: list[str] | None = None,
        limit: int = 40) -> list[tuple[Hunk, str]]:
    """Each hunk of `base...HEAD` under SCOPE with its verdict: `caught` (a test
    failed with the hunk reverted), `survived` (none did), `no code change`
    (comments or docstrings only) or `not applied` (the revert did not apply)."""
    repo = Path(repo)
    diff = _git(repo, "diff", "-U0", "--no-color", f"{base}...HEAD", "--", SCOPE)
    report: list[tuple[Hunk, str]] = []
    for hunk in hunks(diff)[:limit]:
        target = repo / hunk.path
        if not target.is_file():
            report.append((hunk, "not applied"))
            continue
        after = target.read_text(encoding="utf-8")
        patch = revert_patch(hunk)
        applied = subprocess.run(  # noqa: S603 — git, with a patch this script wrote
            ["git", "-C", str(repo), "apply", "-R", "--unidiff-zero", "-"],
            input=patch, capture_output=True, text=True, check=False)
        if applied.returncode != 0:
            report.append((hunk, "not applied"))
            continue
        try:
            before = target.read_text(encoding="utf-8")
            if not code_changed(before, after):
                verdict = "no code change"
            else:
                tests = subprocess.run(  # noqa: S603 — the unit suite, this interpreter
                    pytest_args or UNIT, cwd=repo, capture_output=True, text=True, check=False,
                    env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
                verdict = "caught" if tests.returncode != 0 else "survived"
        finally:
            _git(repo, "checkout", "--", hunk.path)
        report.append((hunk, verdict))
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--base", default="origin/main", help="the ref the change is against")
    parser.add_argument("--limit", type=int, default=40, help="at most this many hunks")
    parser.add_argument("--strict", action="store_true", help="exit 1 when a hunk survives")
    args = parser.parse_args(argv)

    repo = Path(__file__).resolve().parent.parent
    if _git(repo, "status", "--porcelain", "--", SCOPE).strip():
        print(f"mutation check: {SCOPE} has uncommitted changes; commit or stash them first")
        return 2
    report = run(repo, base=args.base, limit=args.limit)
    if not report:
        print(f"mutation check: no hunks under {SCOPE} between {args.base} and HEAD")
        return 0
    survivors = [h for h, verdict in report if verdict == "survived"]
    for hunk, verdict in report:
        mark = {"caught": "ok  ", "survived": "MISS", "no code change": "doc ",
                "not applied": "skip"}[verdict]
        print(f"  {mark}  {hunk.path} {hunk.header.split(' @@')[0]}  {verdict}")
        if verdict == "survived":
            print(f"::warning file={hunk.path}::reverting this hunk ({hunk.header.split(' @@')[0]}) "
                  "fails no unit test — the change's own tests do not cover it")
    caught = sum(1 for _, v in report if v == "caught")
    print(f"mutation check: {caught} hunk(s) caught, {len(survivors)} survived, "
          f"{sum(1 for _, v in report if v == 'no code change')} documentation only, "
          f"{sum(1 for _, v in report if v == 'not applied')} not applied")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as out:
            out.write(f"## Mutation check\n\n{caught} caught, {len(survivors)} survived\n\n")
            for hunk, verdict in report:
                out.write(f"- `{hunk.path}` `{hunk.header.split(' @@')[0]}` — {verdict}\n")
    return 1 if survivors and args.strict else 0


if __name__ == "__main__":
    sys.exit(main())
