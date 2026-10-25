"""A Scanner's upgrade, completed: every pin moved with its stage's (R47.2, D81v, N3.9).

    uv run python scripts/scanner_upgrade.py trivy 0.75.0 0.76.0 [--root DIR]

Dependabot moves a Scanner's stage (its `FROM`, Opengrep's release `ARG`s, or its
hash-locked requirements) and nothing else, so its pull requests stay red until the rest
move too (#229, #230, #238). This moves the rest, as R47.1 lists them: the adapter's
`VERSION`, the golden's pin in `tests/conftest.py`, `docs/PROTOCOL.md`'s table, and
Opengrep's signature check. Each pin must read the old version exactly once, or nothing
is written. Prints `{"scanner", "from", "to", "changed", "recapture"}`.

With `--recapture` (R47.3), the new binary's golden is captured twice from the image and
written only when the two agree (`recapture`), as `docs/MAINTENANCE.md` describes. With
`--score DIR`, the Score runs against `tests/eval/baseline.json`, and `--body FILE` writes
each track's delta into the pull request's body; `--go` adds the new binary's Go
toolchain, read from its build information in the image. Exit 3
means the upgrade is left for the owner, with why on stderr.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import scanner_pins

REPO = Path(__file__).resolve().parent.parent


#: Each Scanner's adapter module, under `src/valvur/adapters/`.
ADAPTERS = {"gitleaks": "gitleaks", "trivy": "trivy", "osv-scanner": "osv", "syft": "syft",
            "opengrep": "opengrep", "checkov": "checkov", "zizmor": "zizmor"}
#: Scanners whose output conftest builds, so they have no golden to recapture.
NO_GOLDEN = {"gitleaks"}


def _pins(tool: str, old: str, new: str) -> list[tuple[str, str, str]]:
    """Each pin as (file, what it reads today, what it reads after)."""
    q = re.escape
    pins = [
        (f"src/valvur/adapters/{ADAPTERS[tool]}.py",
         rf'^VERSION = "{q(old)}"$', f'VERSION = "{new}"'),
        ("tests/conftest.py", rf'(?<="{q(tool)}": )"{q(old)}"', f'"{new}"'),
        ("docs/PROTOCOL.md", rf"^(\| `{q(tool)}` \|[^\n]*\| ){q(old)}( \|)$", rf"\g<1>{new}\g<2>"),
    ]
    if tool == "opengrep":
        pins.append(("scripts/verify-opengrep.sh",
                     rf'^VERSION="\$\{{OPENGREP_VERSION:-v{q(old)}\}}"$',
                     f'VERSION="${{OPENGREP_VERSION:-v{new}}}"'))
    return pins


class LeftForOwner(Exception):
    """The upgrade is not one this script completes, with why."""


def declared(root: Path) -> dict[str, str]:
    """Each Scanner's version, as its adapter declares it."""
    found = {}
    for tool, module in ADAPTERS.items():
        text = (root / "src" / "valvur" / "adapters" / f"{module}.py").read_text(encoding="utf-8")
        match = re.search(r'^VERSION = "([^"]+)"$', text, re.M)
        if match:
            found[tool] = match.group(1)
    return found


def check(root: Path, tool: str, new: str) -> None:
    """Refuse anything but one known Scanner whose stage, alone, moved to `new`."""
    if tool not in ADAPTERS:
        raise LeftForOwner(f"{tool!r} is not a Scanner this script knows: "
                           f"one of {', '.join(sorted(ADAPTERS))}")
    stages = scanner_pins.pins(scanner_pins.in_tree(root))
    moved = sorted(t for t, v in stages.items() if declared(root).get(t) != v)
    if len(moved) > 1:
        raise LeftForOwner(f"the change moves more than one Scanner: {', '.join(moved)}")
    if stages.get(tool) != new:
        raise LeftForOwner(f"{tool}'s stage pins {stages.get(tool)}, not {new}")


def update(root: Path, tool: str, old: str, new: str) -> list[str]:
    """Move every pin from `old` to `new`; the files changed. All or none."""
    check(root, tool, new)
    written: dict[str, str] = {}
    for name, pattern, replacement in _pins(tool, old, new):
        text = written.get(name) or (root / name).read_text(encoding="utf-8")
        after, count = re.subn(pattern, replacement, text, flags=re.M)
        if count != 1:
            raise LeftForOwner(f"{name} pins {tool} {old} {count} times, not once")
        written[name] = after
    for name, text in written.items():
        (root / name).write_text(text, encoding="utf-8")
    return sorted(written)


#: How each golden is captured (R47.1): the fixture, and the files of it kept, or all.
RECIPES: dict[str, tuple[str, tuple[str, ...] | None]] = {
    "trivy": ("broken-repo", ("package-lock.json", "requirements.txt")),
    "osv-scanner": ("broken-repo", None),
    "syft": ("broken-repo", ("requirements.txt",)),
    "opengrep": ("broken-repo", None),
    "checkov": ("broken-repo", None),
    "zizmor": ("workflows-repo", None),
}
#: What differs between two runs of one binary on one tree and one day's data, measured by
#: R47.1, and nothing more: each run's identity, and the order Checkov reports in, of its
#: failed checks and of each check's evaluated keys.
VOLATILE = {"trivy": (("ReportID",), ("CreatedAt",)),
            "syft": (("serialNumber",), ("metadata", "timestamp"))}


def _blank(data: object, path: tuple[str, ...]) -> None:
    *parents, last = path
    for key in parents:
        data = data.get(key) if isinstance(data, dict) else None
    if isinstance(data, dict) and last in data:
        data[last] = None


def comparable(tool: str, report: bytes) -> object:
    """The report as two runs must agree on it."""
    data = json.loads(report or b"null")
    for path in VOLATILE.get(tool, ()):
        _blank(data, path)
    if tool == "checkov":
        for block in data if isinstance(data, list) else [data]:
            checks = (block.get("results") or {}).get("failed_checks")
            if isinstance(checks, list):
                for check in checks:
                    # A set in Checkov, so in the hash seed's order (3.3.29, measured).
                    keys = (check.get("check_result") or {}).get("evaluated_keys")
                    if isinstance(keys, list):
                        keys.sort(key=str)
                checks.sort(key=lambda c: json.dumps(c, sort_keys=True))
    return data


def capture(tool: str, runtime: object) -> bytes:
    """The Scanner's report on its recipe's fixture, from one Scan Container."""
    import shutil
    import tempfile

    # deferred: the image's machinery, needed only by a recapture, not by the pin moves.
    import fixtures

    from valvur import datasets, fileset, osv_offline
    from valvur.adapters import DEFAULT_ADAPTERS
    from valvur.engine_host import snapshot

    fixture, kept = RECIPES[tool]
    adapter = next(a for a in DEFAULT_ADAPTERS if a.name == tool)
    if hasattr(adapter, "for_profile"):
        adapter = adapter.for_profile(network=False)     # the `offline` Profile's command
    with tempfile.TemporaryDirectory() as tmp:
        workspace = fixtures.copy(fixture, Path(tmp) / "workspace")
        for path in sorted(workspace.rglob("*"), reverse=True):
            if kept is not None and path.is_file() and \
                    path.relative_to(workspace).as_posix() not in kept:
                path.unlink()
        files = fileset.build(workspace).files
        if tool == "osv-scanner":
            osv_offline.ensure(files, lambda event: None, due=datasets.OSV.due)
        scratch = Path(tmp) / "scratch"
        scratch.mkdir()
        invocation = adapter.command(workspace)
        runtime.run([invocation], snapshot(workspace, files), scratch)  # type: ignore[attr-defined]
        report = scratch / (invocation.report or f"{invocation.tool}.stdout")
        out = report.read_bytes() if report.is_file() else b""
        shutil.rmtree(scratch, ignore_errors=True)
        return out


def recapture(root: Path, tool: str, version: str, *, runtime: object) -> str:
    """Capture twice; write the first as the new golden when both agree, and remove the
    old. A pair that differs is refused, and nothing is written."""
    if tool not in RECIPES:
        raise LeftForOwner(f"{tool} has no golden to recapture")
    first, second = capture(tool, runtime), capture(tool, runtime)
    if comparable(tool, first) != comparable(tool, second):
        raise LeftForOwner(f"{tool}'s recapture is not deterministic: two captures on "
                           f"{RECIPES[tool][0]} differ beyond its run's identity")
    folder = root / "tests" / "fixtures" / "golden"
    for old in folder.glob(f"{tool}-*.json"):
        old.unlink()
    [name] = golden(tool, version)
    (root / name).write_bytes(first)
    return name


#: Each Scanner by the name its project gives it.
NAMES = {"gitleaks": "Gitleaks", "trivy": "Trivy", "osv-scanner": "OSV-Scanner",
         "syft": "Syft", "opengrep": "Opengrep", "checkov": "Checkov", "zizmor": "zizmor"}
#: Points a track may fall under its baseline (ADR-0026), as `scripts/eval.py` judges it.
TOLERANCE = 2.0
Deltas = dict[str, tuple[float, float, float]]


def score(root: Path, out: Path, *, run=subprocess.run) -> Deltas:
    """The Score against the baseline, each track as (baseline, now, delta)."""
    baseline_path = root / "tests" / "eval" / "baseline.json"
    run([sys.executable, str(root / "scripts" / "eval.py"),
         "--compare", str(baseline_path), "--out", str(out)], check=False)
    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))["tracks"]
    tracks = json.loads((out / "score.json").read_text(encoding="utf-8"))["tracks"]
    return {name: (was, tracks[name]["score"], round(tracks[name]["score"] - was, 1))
            for name, was in baseline.items() if name in tracks}


#: Where the image installs each Scanner that is one binary.
BINARIES = {"gitleaks": "/usr/local/bin/gitleaks", "trivy": "/usr/local/bin/trivy",
            "osv-scanner": "/usr/local/bin/osv-scanner", "syft": "/usr/local/bin/syft",
            "opengrep": "/usr/local/bin/opengrep"}
_BUILDINFO = b"\xff Go buildinf:"


def _uvarint(data: bytes, at: int) -> tuple[int, int]:
    value = shift = 0
    while True:
        byte = data[at]
        value |= (byte & 0x7F) << shift
        at, shift = at + 1, shift + 7
        if not byte & 0x80:
            return value, at


def go_toolchain(binary: Path) -> str | None:
    """The Go that built `binary`, from its build information (`go version`'s answer), or
    None when it is no Go binary. A `go.mod` line would be a minimum, not the toolchain.
    Reads the layout of Go 1.18 and later: the version inline after a 32-byte header."""
    data = binary.read_bytes()
    at = data.find(_BUILDINFO)
    while at != -1 and at % 16:
        at = data.find(_BUILDINFO, at + 1)
    if at == -1 or not data[at + 15] & 2:
        return None
    length, start = _uvarint(data, at + 32)
    version = data[start:start + length].decode("ascii", "replace")
    return version if version.startswith("go") else None


def image_toolchain(tool: str, image: str) -> str | None:
    """The Go toolchain of the binary `image` installs for `tool`."""
    import tempfile

    if tool not in BINARIES:
        return None
    runtime = os.environ.get("VALVUR_RUNTIME", "docker")
    made = subprocess.run([runtime, "create", image], capture_output=True, text=True,  # noqa: S603
                          check=True).stdout.strip()
    try:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / tool
            subprocess.run([runtime, "cp", f"{made}:{BINARIES[tool]}", str(out)],  # noqa: S603
                           capture_output=True, check=True)
            return go_toolchain(out)
    finally:
        subprocess.run([runtime, "rm", made], capture_output=True, check=False)  # noqa: S603


def body(report: dict, *, deltas: Deltas | None = None) -> str:
    """The pull request's body: what moved, and what it measured."""
    tool = report["scanner"]
    lines = [f"**{NAMES.get(tool, tool)} {report['from']} → {report['to']}**, its other pins "
             "moved by `scripts/scanner_upgrade.py` (R47.2)."]
    if "go" in report:
        lines += ["", f"The new binary was built with {report['go']}, read from its build "
                      "information." if report["go"] else "The new binary is not a Go binary."]
    if deltas is not None:
        lines += ["", "| track | baseline | now | delta |", "|---|---|---|---|"]
        lines += [f"| {name} | {was} | {now} | {delta:+.1f} |"
                  for name, (was, now, delta) in deltas.items()]
        under = [name for name, (was, now, _) in deltas.items() if now < was - TOLERANCE]
        lines += ["", f"**Stopped:** more than {TOLERANCE:g} points under its baseline: "
                      f"{', '.join(under)}." if under else
                  ("Every track unchanged." if all(d == 0 for *_, d in deltas.values())
                   else "Tracks moved, none more than 2 points under its baseline.")]
    return "\n".join(lines) + "\n"


def golden(tool: str, version: str) -> list[str]:
    return [] if tool in NO_GOLDEN else [f"tests/fixtures/golden/{tool}-{version}.json"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("scanner", nargs="?")
    parser.add_argument("old", nargs="?", help="the version every other pin reads today")
    parser.add_argument("new", nargs="?", help="the version the stage now pins")
    parser.add_argument("--toolchains-of", metavar="IMAGE",
                        help="print each binary Scanner's Go in IMAGE, as JSON, and stop "
                             "(the watchdog's input)")
    parser.add_argument("--root", type=Path, default=REPO, help="the tree (default: this one)")
    parser.add_argument("--recapture", action="store_true",
                        help="recapture the golden twice from the image (VALVUR_IMAGE)")
    parser.add_argument("--score", type=Path, metavar="DIR",
                        help="run the Score against the baseline, its report under DIR")
    parser.add_argument("--go", action="store_true",
                        help="read the new binary's Go toolchain from the image")
    parser.add_argument("--body", type=Path, metavar="FILE",
                        help="write the pull request's body here")
    args = parser.parse_args(argv)
    if args.toolchains_of:
        print(json.dumps({tool: image_toolchain(tool, args.toolchains_of) for tool in BINARIES},
                         indent=2))
        return 0
    if not (args.scanner and args.old and args.new):
        parser.error("a Scanner and its old and new versions are needed")
    try:
        changed = update(args.root, args.scanner, args.old, args.new)
        if args.recapture and args.scanner in RECIPES:
            # deferred: a recapture needs the image; moving the pins does not.
            from valvur.engine_host import ContainerRuntime

            changed.append(recapture(args.root, args.scanner, args.new,
                                     runtime=ContainerRuntime()))
    except LeftForOwner as why:
        print(f"left for the owner: {why}", file=sys.stderr)
        return 3
    report = {"scanner": args.scanner, "from": args.old, "to": args.new,
              "changed": changed, "recapture": golden(args.scanner, args.new)}
    deltas = score(args.root, args.score) if args.score else None
    if deltas is not None:
        report["deltas"] = deltas
    if args.go:
        report["go"] = image_toolchain(args.scanner, os.environ.get("VALVUR_IMAGE", "valvur:dev"))
    if args.body:
        args.body.write_text(body(report, deltas=deltas), encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
