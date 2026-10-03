#!/usr/bin/env python3
"""Write each generated block of the docs from the code (D55a, R24.2).

A block is the text between `<!-- generated: <name> -->` and `<!-- /generated -->`,
and `BLOCKS` says what writes each one. A fact the code holds is written here
rather than compared with prose by a test of its own; `tests/test_generated_docs.py`
regenerates every block and names the one that differs.

    uv run python scripts/generate_docs.py           # rewrite every stale block
    uv run python scripts/generate_docs.py --check   # name them, and exit 1
"""

from __future__ import annotations

import itertools
import re
import sys
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

BLOCK = re.compile(r"(<!-- generated: (?P<name>[\w-]+) -->\n)(?P<body>.*?)(<!-- /generated -->)",
                   re.S)
SKILL = REPO / "src" / "valvur" / "data" / "skills" / "valvur"


def mcp_tools() -> str:
    """Every MCP tool, its description and each field it takes, as the server lists them."""
    from valvur.mcp.tools import reference

    return reference()


def agent_rules() -> str:
    """The rules the server hands an agent at `initialize`, word for word."""
    from valvur.mcp.tools import instructions

    return instructions().strip("\n") + "\n"


def mcp_clients() -> str:
    """Each MCP client: the file valvur's server goes in, what to do after, and the
    snippet, from the clients' table."""
    from valvur.mcp.clients import readme_section

    return readme_section()


NUMBERS = ("no", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine",
           "ten", "eleven", "twelve")


def cli_commands() -> str:
    """The CLI's commands, as `valvur --help` names them: the retired ones that still
    parse for a release are not among them."""
    import argparse

    from valvur.cli import build_parser

    [sub] = [a for a in build_parser()._actions if isinstance(a, argparse._SubParsersAction)]
    commands = [f"`{name}`" for name in sub.metavar.strip("{}").split(",")]
    listed = ", ".join(commands[:-1]) + f" and {commands[-1]}"
    return (f"{NUMBERS[len(commands)].capitalize()} commands in all: {listed}. `--help` on "
            "each says what it takes.\n")


#: Each path in the Scan Container: who provides it, and who relies on it. The
#: paths the code assumes are read from it, and each must fall under a row here.
PATHS: dict[str, tuple[str, str]] = {
    '/workspace': (
        'the shim: the unpacked Snapshot, in a tmpfs up to 512 MB or a volume named for the '
        'scan beyond, removed after it; never a mount of the source',
        'every Scanner and Check — the argument they scan'),
    '/results': (
        'the shim: a scratch directory mounted read-write, one per Scan Container, holding the '
        'plan, the reports and the manifest',
        "the engine; every Scanner's report (`Invocation.report`)"),
    '/cache/trivy': (
        'the shim: the vulnerability database, mounted from the host cache (ADR-0012)',
        "Trivy (`--cache-dir`, and `TRIVY_CACHE_DIR`), and `valvur update`'s fetch into it"),
    '/cache/names': (
        'the shim: the package-name index, mounted read-only from the host cache (ADR-0018), '
        'with the known-malicious list in `malicious/` beside it (R11.5, ADR-0027)',
        'the dependency-reality Check'),
    '/cache/osv': (
        "the shim: OSV's offline database, one zip per ecosystem, mounted read-only from the "
        'host cache (R4.6)',
        'OSV-Scanner on `offline` (`OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY`)'),
    '/tmp': (  # noqa: S108 — a path in the container, documented
        'the shim: a tmpfs (`rw,noexec,nosuid,size=512m`); `HOME` points here',
        "any tool that needs scratch space; nothing runs from here, since Opengrep's core is "
        'unpacked in the image at `/opt/opengrep`'),
    '/opt/valvur-rules': (
        "the image: valvur's own Opengrep rules, licensed with the project (ADR-0004), and in "
        "`vendor/` the rules vendored on measured precision, each with its origin's licence "
        '(R13, ADR-0029)',
        'Opengrep (`--config`)'),
    '/opt/checkov': (
        "the image: Checkov's own virtual environment, hash-locked (23.4.1); `checkov` on PATH "
        'links into it',
        'Checkov'),
    '/usr/local/lib/python3.12/site-packages/valvur': (
        'the image: the `valvur` package itself, so the engine and the Checks run in the '
        'container (ADR-0013)',
        '`python -m valvur.engine`, `python -m valvur.checks`'),
    '/etc/valvur/inputs.sha256': (
        'the image: the digest of the tree it was built from (22.C.1, 23.4.4); `chmod 0444`',
        "the shim's build-provenance comparison, `doctor`, the e2e guard"),
    '/etc/valvur/Dockerfile': (
        "the image: the Dockerfile it was built from — one of the digest's inputs",
        'the digest'),
}
#: Each binary on PATH and where it comes from; the version is its adapter's, or the
#: text here for the two no adapter pins.
BINARIES: dict[str, tuple[str, str | None]] = {
    'gitleaks': ('`zricethezav/gitleaks`', None),
    'trivy': ('`aquasec/trivy`', None),
    'osv-scanner': ('`ghcr.io/google/osv-scanner`', None),
    'syft': ('`anchore/syft`', None),
    'opengrep': ('`opengrep/opengrep`', None),
    'checkov': ('`/opt/checkov`, from `requirements-checkov.txt`', None),
    'zizmor': ('`/opt/zizmor`, from `requirements-zizmor.txt`, the musl wheel by hash '
               '(R4.2)', None),
    'python': ("the base image's Python 3.12", 'with the Checks'),
    'valvur': ('`/usr/local/bin/valvur`, which runs `python3 -m valvur.cli`: the image as a '
               'pipeline step (R8.1)', "the image's own version"),
}


def _table(header: tuple[str, ...], rows: Iterable[tuple[str, ...]]) -> str:
    lines = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    lines += ["| " + " | ".join(row) + " |" for row in rows]
    return "\n".join(lines) + "\n"


def _assumed_paths() -> set[str]:
    """Every absolute path the code assumes in a Scan Container: each in an adapter's
    command, each mount and tmpfs the shim's command makes, and the image's digest."""
    import tempfile
    from unittest import mock

    from valvur import cache, compat, tree_hash
    from valvur.adapters.registry import DEFAULT_ADAPTERS
    from valvur.engine_host import ContainerRuntime

    assumed = {compat.IMAGE_INPUTS_FILE, tree_hash.IMAGE_DOCKERFILE}
    with tempfile.TemporaryDirectory() as scratch, \
            mock.patch.object(cache, "db_present", return_value=True):
        for adapter in DEFAULT_ADAPTERS:
            for arg in adapter.command(Path(scratch)).argv:
                assumed |= {t for t in re.split(r"[=,]", arg) if t.startswith("/")}
        command = ContainerRuntime(image="valvur:docs", runtime="docker").command(
            Path(scratch), name="valvur-docs")
    for flag, value in itertools.pairwise(command):
        if flag == "-v":
            assumed.add(value.split(":")[1])
        elif flag == "--tmpfs":
            assumed.add(value.split(":")[0])
    return assumed


def protocol_paths() -> str:
    """Each path in a Scan Container, and who provides and relies on it; every path the
    code assumes falls under one, or this refuses."""
    def covered(path: str) -> bool:
        return any(path == d or path.startswith(d.rstrip("/") + "/") for d in PATHS)

    missing = sorted(p for p in _assumed_paths() if not covered(p))
    if missing:
        raise SystemExit(f"PATHS in scripts/generate_docs.py does not describe: {missing}")
    return _table(("path", "provided by", "who relies on it"),
                  ((f"`{path}`", provided, relied) for path, (provided, relied) in PATHS.items()))


def protocol_binaries() -> str:
    """Each binary on PATH, where it comes from, and the version its adapter declares."""
    from valvur.adapters.registry import DEFAULT_ADAPTERS

    pinned = {a.command(Path("/nonexistent")).argv[0]: a.version for a in DEFAULT_ADAPTERS
              if a.kind == "scanner" and a.name != "trivy"}
    pinned["trivy"] = next(a.version for a in DEFAULT_ADAPTERS if a.name == "trivy")
    missing = sorted(set(pinned) - set(BINARIES))
    if missing:
        raise SystemExit(f"BINARIES in scripts/generate_docs.py does not name: {missing}")
    return _table(("binary", "from", "pinned at"),
                  ((f"`{name}`", source, pin if pin is not None else pinned[name])
                   for name, (source, pin) in BINARIES.items()))


def protocol_labels() -> str:
    """The image's labels, their values from the Dockerfile, and who reads each."""
    from valvur import compat

    declared = dict(re.findall(r'^LABEL ([\w.]+)="([^"]*)"', (REPO / "Dockerfile").read_text(),
                               re.M))
    if declared.get(compat.PROTOCOL_LABEL) != str(compat.PROTOCOL):
        raise SystemExit(f"the Dockerfile's {compat.PROTOCOL_LABEL} is not {compat.PROTOCOL}")
    source, licences = "org.opencontainers.image.source", "org.opencontainers.image.licenses"
    return _table(("label", "value", "read by"), (
        (f"`{compat.LABEL}`", "the valvur version the image was built as",
         "`compat.image_version` — F1.9's version rule, and `doctor`"),
        (f"`{compat.PROTOCOL_LABEL}`", f"the protocol major, `{compat.PROTOCOL}`",
         "`compat.image_protocol` — the rule above"),
        (f"`{source}`", f"`{declared[source]}`", "GHCR, to link the package to the repository"),
        (f"`{licences}`", f"`{declared[licences]}`", "readers"),
    ))


#: The settings a mirror needs, in the order AIR-GAPPED.md gives them, and what each
#: does; each variable is `settings.ENVIRONMENT`'s, `=1` after a switch.
MIRROR_SETTINGS: dict[str, str] = {
    'db_repository': (
        'The OCI repository Trivy fetches its database from.'),
    'db_insecure': (
        'Allows plain HTTP, or a certificate the container does not trust. Trivy assumes TLS '
        'for any registry that is not `localhost` or a private-range IP literal; without this '
        'an internal mirror on HTTP fails with *"server gave HTTP response to HTTPS client"*. '
        'Found by the first real test, not by reading the docs.'),
    'index_repository': (
        'The OCI repository the package-name index is pulled from, `host/name[:tag]`. Default '
        '`ghcr.io/maverickhq/valvur-index:latest`. Set explicitly, it is the only source '
        'tried: a mirror that fails is reported, not worked around by walking the registries. '
        "The known-malicious list is pulled from the same repository's `malicious` tag."),
    'index_insecure': (
        'Plain HTTP, or an untrusted certificate, for that repository. The shim pulls the '
        "index itself, no container involved, so this is the shim's own switch, not Trivy's."),
    'name_index_url': (
        "A URL under which the index's files, `pypi.txt`, `npm.txt`, `rubygems.txt`, "
        '`packagist.txt`, `crates.txt` and `metadata.json`, are served verbatim, and the '
        "known-malicious list's under `malicious/`, as `valvur update` leaves them in the "
        'cache. Wins over the repository when both are set.'),
    'kev_url': (
        'A URL for the CISA KEV catalog JSON. Without it, an air-gapped `valvur update` tries '
        'cisa.gov, fails softly, and keeps the snapshot shipped in the image.'),
    'epss_url': (
        "A URL for FIRST's daily EPSS file, `epss_scores-current.csv.gz`, served verbatim. "
        'Without it, an air-gapped `valvur update` tries epss.cyentia.com, fails softly, and '
        'findings rank without EPSS.'),
    'osv_url': (
        "A URL under which OSV's databases are served as `<ecosystem>/all.zip`, OSV's own "
        'layout. The shim fetches them itself.'),
    'image': (
        'The image, from any registry: a mirror of `ghcr.io/maverickhq/valvur`.'),
    'fetch': (
        '`never` stops every fetch a scan would make on its own (ADR-0025); `valvur update` '
        'and the `update` tool still fetch from the mirrors when asked.'),
    'container_network': (
        'The container network the **update** container joins, when the mirror registry lives '
        'on a named one. Never applied to a scan container: `--network=none` is not '
        'negotiable. The variable still works through 1.x, and says so once.'),
}
SWITCHES = frozenset({'db_insecure', 'index_insecure'})


def settings_table() -> str:
    """The settings a mirror needs, each with its variable, from `settings.ENVIRONMENT`;
    a mirror setting the code adds and this does not describe is refused."""
    from valvur import settings

    unknown = sorted(set(MIRROR_SETTINGS) - set(settings.ENVIRONMENT))
    mirrors = {k for k in settings.ENVIRONMENT if k.endswith(("_url", "_repository", "_insecure"))}
    missing = sorted(mirrors - set(MIRROR_SETTINGS))
    if unknown or missing:
        raise SystemExit(f"MIRROR_SETTINGS: no such setting {unknown}; undescribed {missing}")

    def variable(key: str) -> str:
        name = settings.ENVIRONMENT[key] + ("=1" if key in SWITCHES else "")
        return f"`{name}`" + (", retired to the file" if key in settings.RETIRED else "")

    return _table(("key", "variable", "what it does"),
                  ((f"`{key}`", variable(key), text) for key, text in MIRROR_SETTINGS.items()))


BLOCKS: dict[str, Callable[[], str]] = {
    "mcp-tools": mcp_tools,
    "agent-rules": agent_rules,
    "mcp-clients": mcp_clients,
    "cli-commands": cli_commands,
    "protocol-paths": protocol_paths,
    "protocol-binaries": protocol_binaries,
    "protocol-labels": protocol_labels,
    "settings": settings_table,
}
FILES: tuple[Path, ...] = (
    REPO / "README.md",
    REPO / "docs" / "PROTOCOL.md",
    REPO / "docs" / "AIR-GAPPED.md",
    SKILL / "SKILL.md",
    SKILL / "references" / "tools.md",
)


def names(text: str) -> list[str]:
    return [match["name"] for match in BLOCK.finditer(text)]


def render(text: str, blocks: Mapping[str, Callable[[], str]]) -> str:
    """`text` with each block's body written afresh, set off by a blank line each side."""
    def body(match: re.Match[str]) -> str:
        if match["name"] not in blocks:
            raise SystemExit(f"no generator for the block {match['name']!r}")
        return f"{match[1]}\n{blocks[match['name']]()}\n{match[4]}"

    return BLOCK.sub(body, text)


def stale(files: Iterable[Path] = FILES,
          blocks: Mapping[str, Callable[[], str]] = BLOCKS) -> list[tuple[Path, str]]:
    """Each (file, block) whose text is not what the code writes."""
    found = []
    for path in files:
        text = path.read_text(encoding="utf-8")
        for old, new in zip(BLOCK.finditer(text), BLOCK.finditer(render(text, blocks)),
                            strict=True):
            if old[0] != new[0]:
                found.append((path, old["name"]))
    return found


def write(files: Iterable[Path] = FILES,
          blocks: Mapping[str, Callable[[], str]] = BLOCKS) -> list[tuple[Path, str]]:
    """Rewrite every stale block; return what was rewritten."""
    files = list(files)
    rewritten = stale(files, blocks)
    for path in {path for path, _ in rewritten}:
        path.write_text(render(path.read_text(encoding="utf-8"), blocks), encoding="utf-8")
    return rewritten


def main(argv: list[str]) -> int:
    rewritten = stale() if "--check" in argv else write()
    for path, name in rewritten:
        print(f"{'stale' if '--check' in argv else 'wrote'}: {name} in "
              f"{path.relative_to(REPO)}")
    return 1 if rewritten and "--check" in argv else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
