"""Prepare a release in one commit, or mark one published (D33, N3.4; R16.2).

    uv run python scripts/prepare_release.py 1.2.0 [--dry-run]
    uv run python scripts/prepare_release.py --published 1.2.0 [--dry-run]

The first sets every version surface in one commit, `chore: release <version>`:
`pyproject.toml` and the lock; the README's status line, worded *release in
progress* until the run has promoted; `SECURITY.md`'s supported series; the
CHANGELOG's heading, under an empty *Unreleased*; the skill's version in the
package, copied byte for byte to the Claude Code plugin and the Kiro power; the
plugin's and the power's manifests and pinned servers; the plugin's hook; and the
image the pipeline examples name. `--published` makes the
commit that flips the README once `promote` has completed. `--dry-run` prints what
either would change and changes nothing.

What it never does: tag, push, or approve the brake. Those are the owner's
(`docs/RELEASING.md`). After it, `uv sync` brings the installed metadata along.
"""

from __future__ import annotations

import argparse
import datetime
import difflib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SKILL = Path("src/valvur/data/skills/valvur")
#: The skill's copies, which Claude Code and Kiro load from the repository (R15).
COPIES = (Path("plugins/valvur/skills/valvur"), Path("powers/valvur/skills/valvur"))
MANIFESTS = (Path("plugins/valvur/.claude-plugin/plugin.json"), Path("powers/valvur/plugin.json"))
SERVERS = (Path("plugins/valvur/.mcp.json"), Path("powers/valvur/mcp.json"))
#: The plugin's hook, which runs the release's own valvur-hook (R18.4).
HOOK = Path("plugins/valvur/hooks/pre-tool-use.sh")
#: The pipeline examples, which name the image this release publishes (R8.2).
EXAMPLES = (Path("docs/examples/github-actions.yml"), Path("docs/examples/gitlab-ci.yml"))
_VERSION = re.compile(r"^\d+\.\d+\.\d+$")


def declared(root: Path) -> str:
    return re.search(r'^version = "([^"]+)"', (root / "pyproject.toml").read_text(), re.M)[1]


def _sub(pattern: str, replacement: str, text: str, where: str, flags: int = 0) -> str:
    changed, count = re.subn(pattern, replacement, text, count=1, flags=flags)
    if count != 1:
        raise SystemExit(f"prepare_release: {where} no longer has what it edits ({pattern!r})")
    return changed


def _status_line(text: str, line: str) -> str:
    return _sub(r"^> \*\*Status: `[^`]+`\*\*.*$", line.replace("\\", "\\\\"), text, "README.md",
                re.M)


def _server(path: Path, version: str) -> str:
    """The pinned server, as `valvur.mcp.clients` renders it: `uvx --from
    valvur==<version> valvur-mcp`, whatever else the file holds kept."""
    from valvur.mcp.clients import server_args

    config = json.loads(path.read_text())
    config["mcpServers"]["valvur"]["args"] = server_args(version)
    return json.dumps(config, indent=2) + "\n"


def planned(root: Path, version: str, date: str) -> dict[Path, str]:
    """Each file the release commit changes, by its path under `root`, to its text."""
    previous = declared(root)
    plan = {
        Path("pyproject.toml"): _sub(r'^version = "[^"]+"', f'version = "{version}"',
                                     (root / "pyproject.toml").read_text(), "pyproject.toml",
                                     re.M),
        Path("uv.lock"): _sub(r'(name = "valvur"\nversion = ")[^"]+"', rf'\g<1>{version}"',
                              (root / "uv.lock").read_text(), "uv.lock"),
        Path("README.md"): _status_line(
            (root / "README.md").read_text(),
            f"> **Status: `{version}`** — release in progress: this tree is rehearsed and "
            "waits at the release brake; `pip install valvur` serves "
            f"`{previous}` until the run's `promote` completes."),
        Path("SECURITY.md"): _sub(r"^\| `[^`]+` \|", "| `" + ".".join(version.split(".")[:2])
                                  + ".x` |", (root / "SECURITY.md").read_text(),
                                  "SECURITY.md", re.M),
        Path("CHANGELOG.md"): _sub(r"^## \[Unreleased\]\n\n",
                                   f"## [Unreleased]\n\n## [{version}] — {date}\n\n",
                                   (root / "CHANGELOG.md").read_text(), "CHANGELOG.md", re.M),
    }
    skill = _sub(r'^  version: "[^"]+"$', f'  version: "{version}"',
                 (root / SKILL / "SKILL.md").read_text(), "SKILL.md", re.M)
    for directory in (SKILL, *COPIES):
        plan[directory / "SKILL.md"] = skill
    for manifest in MANIFESTS:
        plan[manifest] = _sub(r'("version":\s*")[^"]+"', rf'\g<1>{version}"',
                              (root / manifest).read_text(), str(manifest))
    for server in SERVERS:
        plan[server] = _server(root / server, version)
    if (root / HOOK).is_file():
        plan[HOOK] = _sub(rf"valvur=={re.escape(previous)} valvur-hook",
                          f"valvur=={version} valvur-hook", (root / HOOK).read_text(), str(HOOK))
    for example in EXAMPLES:
        plan[example] = _sub(rf"ghcr\.io/maverickhq/valvur:{re.escape(previous)}\b",
                             f"ghcr.io/maverickhq/valvur:{version}",
                             (root / example).read_text(), str(example))
    return plan


def published(root: Path, version: str, date: str) -> dict[Path, str]:
    return {Path("README.md"): _status_line(
        (root / "README.md").read_text(),
        f"> **Status: `{version}`** — published and installable, released on {date}; "
        "rehearsed on its commit before its signed tag.")}


def _show(root: Path, plan: dict[Path, str]) -> None:
    for path, text in plan.items():
        before = (root / path).read_text()
        if before != text:
            sys.stdout.writelines(difflib.unified_diff(
                before.splitlines(keepends=True), text.splitlines(keepends=True),
                f"a/{path}", f"b/{path}", n=0))


def _apply(root: Path, plan: dict[Path, str], message: str) -> None:
    for path, text in plan.items():
        (root / path).write_text(text)
    # Every other file of the skill is the package's too: the copies stay whole.
    for copy in COPIES:
        if (root / copy).parent.is_dir():
            shutil.rmtree(root / copy, ignore_errors=True)
            shutil.copytree(root / SKILL, root / copy)
    paths = [str(p) for p in plan] + [str(c) for c in COPIES if (root / c).exists()]
    subprocess.run(["git", "-C", str(root), "add", "-A", "--", *paths], check=True)  # noqa: S603
    subprocess.run(["git", "-C", str(root), "commit", "-q", "-m", message], check=True)  # noqa: S603


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("version", nargs="?", help="the version to prepare, X.Y.Z")
    parser.add_argument("--published", metavar="VERSION",
                        help="the version the run has promoted: flip the README")
    parser.add_argument("--dry-run", action="store_true", help="print, change nothing")
    parser.add_argument("--date", default=datetime.date.today().isoformat())
    parser.add_argument("--root", type=Path, default=REPO)
    args = parser.parse_args(argv)
    root = args.root.resolve()
    version = args.published or args.version
    if not version or not _VERSION.match(version) or (args.published and args.version):
        print("prepare_release: give one version, X.Y.Z, or --published X.Y.Z",
              file=sys.stderr)
        return 2
    current = declared(root)
    if args.published:
        if version != current:
            print(f"prepare_release: this tree is {current}, not {version}; prepare "
                  f"{version} first", file=sys.stderr)
            return 2
        plan, message = published(root, version, args.date), f"docs: {version} published"
    else:
        if tuple(map(int, version.split("."))) <= tuple(map(int, current.split("."))):
            print(f"prepare_release: {version} is not after this tree's {current}",
                  file=sys.stderr)
            return 2
        plan, message = planned(root, version, args.date), f"chore: release {version}"
    if args.dry_run:
        _show(root, plan)
        print(f"\n(dry run: {message}, {len(plan)} files; nothing changed)")
        return 0
    dirty = subprocess.run(["git", "-C", str(root), "status", "--porcelain"],  # noqa: S603
                           capture_output=True, text=True, check=True).stdout
    if dirty.strip():
        print("prepare_release: the tree has uncommitted changes; the release commit "
              "holds the release alone", file=sys.stderr)
        return 2
    _apply(root, plan, message)
    print(f"{message}: {len(plan)} files. Next: `uv sync`, then docs/RELEASING.md; "
          "the tag and the brake are the owner's.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
