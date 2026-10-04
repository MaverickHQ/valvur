"""R26.2: rehearse when the machinery changed (D62a).

`1.4.0`'s rehearsal took 31 minutes to prove a pipeline no commit since `1.3.1` had
touched. So `prepare_release.py` names each file the release run builds from that
changed since the last tag, or says none did, and `RELEASING.md` asks for a
rehearsal then and only then. The list is held to what `release.yml` reads, so a
new input to the run cannot be left off it.
"""

from __future__ import annotations

import importlib.util
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "prepare_release.py"
COPIED = ("pyproject.toml", "uv.lock", "README.md", "SECURITY.md", "CHANGELOG.md",
          "src/valvur/data/skills", "plugins", "powers", "docs/examples", "Dockerfile")


def _script():
    spec = importlib.util.spec_from_file_location("prepare_release", SCRIPT)
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules["prepare_release"] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def _git(root: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True,
                          check=True).stdout


def _declared(root: Path) -> str:
    return re.search(r'^version = "([^"]+)"', (root / "pyproject.toml").read_text(), re.M)[1]


MAJOR, MINOR, _ = (int(n) for n in _declared(REPO).split("."))
NEXT = f"{MAJOR}.{MINOR + 1}.0"


@pytest.fixture
def tagged(tmp_path) -> Path:
    """A copy of the files the script reads, committed and tagged as this tree's
    version, the way `main` stands after a release."""
    root = tmp_path / "repo"
    for name in COPIED:
        source, target = REPO / name, root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        (shutil.copytree if source.is_dir() else shutil.copy2)(source, target)
    _git(root, "init", "-q")
    for key, value in (("user.email", "test@example.invalid"), ("user.name", "test"),
                       ("commit.gpgsign", "false"), ("tag.gpgsign", "false")):
        _git(root, "config", key, value)
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "chore: the release before")
    _git(root, "tag", "-a", f"v{_declared(root)}", "-m", "the release before")
    return root


def _commit(root: Path, path: str, text: str) -> None:
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text)
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", f"change {path}")


def test_it_names_each_machinery_file_changed_since_the_last_tag(tagged, capsys):
    tag = f"v{_declared(tagged)}"
    _commit(tagged, "Dockerfile", (tagged / "Dockerfile").read_text() + "# moved\n")
    _commit(tagged, "docker-bake.hcl", "# new\n")
    _commit(tagged, "src/valvur/cli.py", "# product code, not machinery\n")

    assert _script().main([NEXT, "--dry-run", "--root", str(tagged)]) == 0

    out = capsys.readouterr().out
    line = next(line for line in out.splitlines() if line.startswith("machinery"))
    assert line == (f"machinery changed since {tag}: Dockerfile, docker-bake.hcl; "
                    "rehearse before the tag (docs/RELEASING.md)")


def test_it_says_none_did_when_none_did(tagged, capsys):
    tag = f"v{_declared(tagged)}"
    _commit(tagged, "src/valvur/cli.py", "# product code, not machinery\n")

    assert _script().main([NEXT, "--dry-run", "--root", str(tagged)]) == 0

    assert (f"machinery unchanged since {tag}: no rehearsal needed"
            in capsys.readouterr().out.splitlines())


def test_without_a_tag_it_cannot_tell_and_asks_for_the_rehearsal(tagged, capsys):
    _git(tagged, "tag", "-d", f"v{_declared(tagged)}")

    assert _script().main([NEXT, "--dry-run", "--root", str(tagged)]) == 0

    assert ("machinery: no earlier tag here to compare with; rehearse before the tag "
            "(docs/RELEASING.md)" in capsys.readouterr().out.splitlines())


def _read_by_the_release() -> set[str]:
    """What `release.yml` builds from besides the product, found by reading it: the
    workflow, each action it uses from this repository, the bake file and the
    Dockerfile it names, each lock the Dockerfile copies, and the wheel's hook."""
    release = (REPO / ".github" / "workflows" / "release.yml").read_text()
    found = {".github/workflows/release.yml"}
    found |= {f"{path}/action.yml" for path in re.findall(r"uses: \./(\S+)", release)}
    if "docker buildx bake" in release:
        bake = (REPO / "docker-bake.hcl").read_text()
        dockerfile = re.search(r'dockerfile\s*=\s*"([^"]+)"', bake)[1]
        found |= {"docker-bake.hcl", dockerfile}
        found |= set(re.findall(r"^COPY (requirements-[\w-]+\.txt) ",
                                (REPO / dockerfile).read_text(), re.M))
    if "uv build" in release:
        hook = re.search(r'\[tool\.hatch\.build\.hooks\.custom\][^\[]*?^path = "([^"]+)"',
                         (REPO / "pyproject.toml").read_text(), re.M | re.S)
        found.add(hook[1])
    return found


def test_the_machinery_list_is_what_the_release_builds_from():
    listed = set(_script().MACHINERY)

    assert listed == _read_by_the_release(), (
        f"listed and not read: {sorted(listed - _read_by_the_release())}; "
        f"read and not listed: {sorted(_read_by_the_release() - listed)}")
    assert all((REPO / path).is_file() for path in listed), "a listed file does not exist"
