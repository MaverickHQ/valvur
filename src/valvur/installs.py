"""Install commands, read before they run (R18.2, D44).

The `check_package` hook sees the text of a shell command an agent is about to run.
When the command installs named packages, they are checked as `valvur check` checks
them, before the install can run a squatted name's code. This module only reads: which
packages a command would install, in which ecosystem, and at which version when one
is named. It runs nothing and opens nothing but a requirements file the command names.

A name read wrongly costs a question the human answers; a name missed costs the
protection. So a spec that is not a registry name (a path, a URL, a git reference) is
never taken for one, and a command that names no packages (`npm ci`, a bare
`npm install`) yields nothing: the lockfile's packages are the scan's to check.
"""

from __future__ import annotations

import re
import shlex
from pathlib import Path

from .packages import Package

#: Where a chain splits: each command between these is read on its own.
_SEPARATORS = frozenset({"&&", "||", ";", "|", "&", "(", ")"})

#: npm's install verbs, as each JavaScript package manager spells them.
_NPM_VERBS = {"npm": {"install", "i", "add", "in"}, "pnpm": {"add", "install", "i"},
              "yarn": {"add"}, "bun": {"add", "install", "i"}}
#: npm flags whose next word is their value, not a package.
_NPM_VALUED = frozenset({"--registry", "--cache", "--prefix", "--tag", "--workspace", "-w",
                         "--omit", "--include", "--save-prefix", "--filter", "-C", "--dir",
                         "--cwd", "--userconfig"})


#: pip flags whose next word is their value, not a package (`-r` is read, R18.2).
_PIP_VALUED = frozenset({"-c", "--constraint", "-e", "--editable", "-i", "--index-url",
                         "--extra-index-url", "-f", "--find-links", "-t", "--target",
                         "--prefix", "--root", "--platform", "--python-version",
                         "--implementation", "--abi", "--only-binary", "--no-binary",
                         "--upgrade-strategy", "--progress-bar", "--log", "--cache-dir",
                         "--src", "--trusted-host", "--proxy", "--retries", "--timeout",
                         "--exists-action", "--cert", "--client-cert", "-C",
                         "--config-settings", "--report", "--python", "-p",
                         # uv's and poetry's own
                         "--optional", "--group", "-G", "--source", "-E", "--extras",
                         "--index", "--default-index", "--package", "--script",
                         "--directory", "--project", "--extra", "--tag", "--branch",
                         "--rev", "--lock", "--constraints", "--overrides"})
#: A PEP 508 requirement's name, extras and an exact pin; any other specifier is a range,
#: which names no version.
_PIP_SPEC = re.compile(r"(?P<name>[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)"
                       r"(?:\[[^\]]*\])?\s*(?:===?\s*(?P<version>[^\s;,]+)|[<>!~=@;,].*)?")


def packages(command: str, cwd: Path) -> list[Package]:
    """Every registry package `command` would install, in order, from each command of a
    chain. `cwd` is where the command runs, for a requirements file it names."""
    found: list[Package] = []
    for words in _commands(command):
        found += _read(words, cwd)
    return found


def _commands(command: str) -> list[list[str]]:
    """The words of each command in a chain; a command that does not parse is skipped,
    since a shell would not run it either."""
    lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|()")
    lexer.whitespace_split = True
    try:
        tokens = list(lexer)
    except ValueError:
        return []
    commands: list[list[str]] = []
    current: list[str] = []
    for token in tokens:
        if token in _SEPARATORS or set(token) <= set(";&|()"):
            if current:
                commands.append(current)
            current = []
        else:
            current.append(token)
    if current:
        commands.append(current)
    return [_bare(words) for words in commands]


def _bare(words: list[str]) -> list[str]:
    """`words` without what only runs the command: variable assignments, `sudo`, `env`."""
    while words and (("=" in words[0] and not words[0].startswith("-"))
                     or words[0] in {"sudo", "env", "command", "exec", "time"}):
        words = words[1:]
    return words


def _read(words: list[str], cwd: Path) -> list[Package]:
    if not words:
        return []
    tool = Path(words[0]).name
    if tool.startswith("python") and words[1:3] == ["-m", "pip"]:
        tool, words = "pip", ["pip", *words[3:]]
    if tool in {"pip", "pip3"} and words[1:2] == ["install"]:
        return _pip(words[2:], cwd)
    if tool == "uv" and words[1:3] == ["pip", "install"]:
        return _pip(words[3:], cwd)
    if tool == "uv" and words[1:2] == ["add"]:
        return _pip(words[2:], cwd)
    if tool == "poetry" and words[1:2] == ["add"]:
        return _pip(words[2:], cwd, at_version=True)
    if tool == "cargo" and words[1:2] == ["add"]:
        return _cargo(words[2:])
    if tool == "gem" and words[1:2] == ["install"]:
        return _gem(words[2:])
    if tool == "composer" and words[1:2] in (["require"], ["req"]):
        return _composer(words[2:])
    if tool in _NPM_VERBS:
        rest = words[1:]
        if tool == "yarn" and rest[:1] == ["global"]:
            rest = rest[1:]
        if rest and rest[0] in _NPM_VERBS[tool]:
            return _npm(rest[1:])
    return []


def _npm(args: list[str]) -> list[Package]:
    found: list[Package] = []
    skip = False
    for arg in args:
        if skip:
            skip = False
            continue
        if arg.startswith("-"):
            skip = arg in _NPM_VALUED
            continue
        spec = _npm_spec(arg)
        if spec:
            found.append(spec)
    return found


def _npm_spec(arg: str) -> Package | None:
    """`name`, `name@version` or `@scope/name@version`; None for a path, a URL, a git
    reference, a tarball or GitHub's `owner/repo` shorthand."""
    if (arg.startswith((".", "/", "~", "file:", "git", "http:", "https:", "github:",
                        "npm:", "link:", "workspace:"))
            or arg.endswith((".tgz", ".tar.gz")) or "://" in arg):
        return None
    scoped = arg.startswith("@")
    at = arg.find("@", 1 if scoped else 0)
    name, version = (arg[:at], arg[at + 1:] or None) if at > 0 else (arg, None)
    if "/" in name and not scoped:
        return None                       # `owner/repo` is a GitHub reference
    if scoped and name.count("/") != 1:
        return None
    return ("npm", name, version) if name else None


#: How deep `-r` inside a requirements file is followed, so a file that names itself ends.
_REQUIREMENTS_DEPTH = 3


def _pip(args: list[str], cwd: Path, *, at_version: bool = False,
         depth: int = 0) -> list[Package]:
    """pip's arguments: requirement specifiers, and `-r FILE` read as the file it names.
    poetry also writes a version as `name@^1.0`."""
    found: list[Package] = []
    skip, requirements = False, False
    for arg in args:
        if requirements:
            requirements = False
            found += _requirements(cwd / arg, depth)
            continue
        if skip:
            skip = False
            continue
        if arg in {"-r", "--requirement"}:
            requirements = True
            continue
        if arg.startswith(("--requirement=", "-r")) and len(arg) > 2:
            found += _requirements(cwd / arg.split("=", 1)[-1].removeprefix("-r"), depth)
            continue
        if arg.startswith("-"):
            skip = arg in _PIP_VALUED
            continue
        spec = _pip_spec(arg, at_version=at_version)
        if spec:
            found.append(spec)
    return found


def _requirements(path: Path, depth: int) -> list[Package]:
    """A requirements file's packages: each line as pip reads it, comments and options
    aside, `-r` followed into the file it names. A file that cannot be read names none."""
    if depth >= _REQUIREMENTS_DEPTH:
        return []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    found: list[Package] = []
    for line in lines:
        line = line.split(" #", 1)[0].strip()
        if not line or line.startswith("#"):
            continue
        try:
            words = shlex.split(line)
        except ValueError:
            continue
        if words[0].startswith("-"):
            if words[0] in {"-r", "--requirement"} and len(words) > 1:
                found += _requirements(path.parent / words[1], depth + 1)
            continue
        spec = _pip_spec(line)
        if spec:
            found.append(spec)
    return found


def _pip_spec(arg: str, *, at_version: bool = False) -> Package | None:
    """A requirement's name and exact pin; None for a path, a URL, a wheel or archive,
    or a direct reference (`name @ url`)."""
    if (arg.startswith((".", "/", "~", "git+", "http:", "https:", "file:"))
            or arg.endswith((".whl", ".tar.gz", ".zip")) or "://" in arg):
        return None
    if at_version and "@" in arg:
        name, _, version = arg.partition("@")
        return ("pip", name, version or None) if _PIP_SPEC.fullmatch(name) else None
    match = _PIP_SPEC.fullmatch(arg.strip())
    if not match or "@" in arg:
        return None
    return "pip", match.group("name"), match.group("version")


#: cargo's flags whose next word is their value; `--git` and `--path` make every name
#: in the command a source other than crates.io, so the command names none to check.
_CARGO_VALUED = frozenset({"--features", "-F", "--rename", "--package", "-p", "--registry",
                           "--target", "--branch", "--tag", "--rev", "--manifest-path"})
_CRATE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]*")


def _cargo(args: list[str]) -> list[Package]:
    if any(arg in {"--git", "--path"} or arg.startswith(("--git=", "--path=")) for arg in args):
        return []
    found: list[Package] = []
    skip = False
    for arg in args:
        if skip:
            skip = False
            continue
        if arg.startswith("-"):
            skip = arg in _CARGO_VALUED
            continue
        name, _, version = arg.partition("@")
        if _CRATE.fullmatch(name):
            found.append(("cargo", name, version or None))
    return found


_GEM = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*")


def _gem(args: list[str]) -> list[Package]:
    """`gem install NAME [-v VERSION] …`: a version flag belongs to the name before it."""
    found: list[Package] = []
    take_version, skip = False, False
    for arg in args:
        if take_version:
            take_version = False
            if found:
                found[-1] = (found[-1][0], found[-1][1], arg)
            continue
        if skip:
            skip = False
            continue
        if arg in {"-v", "--version"}:
            take_version = True
            continue
        if arg.startswith("-"):
            skip = arg in {"-s", "--source", "-i", "--install-dir", "-n", "--bindir",
                           "--platform"}
            continue
        if _GEM.fullmatch(arg) and not arg.endswith(".gem"):
            found.append(("gem", arg, None))
    return found


_COMPOSER = re.compile(r"[a-z0-9][a-z0-9_.-]*/[a-z0-9][a-z0-9_.-]*")


def _composer(args: list[str]) -> list[Package]:
    """`composer require vendor/name[:constraint] …`."""
    found: list[Package] = []
    for arg in args:
        if arg.startswith("-"):
            continue
        name, _, version = arg.replace("=", ":", 1).partition(":")
        if _COMPOSER.fullmatch(name.lower()):
            found.append(("composer", name, version or None))
    return found
