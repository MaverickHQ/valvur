"""`valvur doctor` — every precondition a first run has failed on, named before a
scan, with the fix on the failing ones (task 23.3.1).

Each check here is a failure this project met for real, in the order a scan meets
them: an interpreter that cannot verify TLS (python.org's macOS build until *Install
Certificates.command* is run — found by the 0.2.0 first-run measurement, 23.1.1); no
runtime on PATH when Podman Desktop had put one at `/opt/podman/bin`; a daemon that
is not running, indistinguishable from a missing image to `image inspect`; the rc
shim looking for an image nobody had (22.G.1); a database never fetched; an index
built before Ruby was in it; an enforcing SELinux host denying every mount (20.1).

Read-only with respect to the Workspace and the cache, and it opens no socket unless
asked (`--network`). One line per check; `fail` means a scan would not complete
here, `warn` means it would but the result would be weaker, `info` is worth knowing.
The same report is an MCP tool, so an agent can run it *before* `scan`.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from . import cache as _cache
from .version import __version__

#: What each level means, in the order they are worth reading.
LEVELS = ("fail", "warn", "info", "ok", "skip")


@dataclass(frozen=True)
class Check:
    name: str
    level: str
    detail: str
    fix: str = ""


# --------------------------------------------------------------------- probes
#
# Everything that touches the machine is one of these small functions, so the
# report's logic is tested against a healthy machine with one thing broken at a
# time, and each probe is tested against the real thing once.


def _trusted_roots() -> int:
    """How many CA certificates this interpreter would verify TLS against. Zero on
    python.org's macOS builds until their certificate script has run — measured
    2026-09-13: 0 on 3.10 and 3.12 from python.org, 128 on every interpreter that
    could fetch anything."""
    import ssl

    try:
        return int(ssl.create_default_context().cert_store_stats()["x509_ca"])
    except (ssl.SSLError, KeyError, OSError):
        return 0


def _find_runtime() -> str:
    from .runner import detect_runtime

    return detect_runtime()


def _runtime_version(runtime: str) -> str:
    import subprocess

    try:
        proc = subprocess.run([runtime, "--version"], capture_output=True, text=True,  # noqa: S603
                              timeout=30, check=False)
    except (OSError, subprocess.SubprocessError):
        return ""
    said = (proc.stdout or proc.stderr).strip()
    return said.splitlines()[0] if said else ""


def _runtime_running(runtime: str) -> tuple[bool, str]:
    """Whether the runtime can reach its daemon (or VM). `info` fails with the
    reason when it cannot; `image inspect` fails the same way as a missing image."""
    import subprocess

    try:
        proc = subprocess.run([runtime, "info"], capture_output=True, text=True,  # noqa: S603
                              timeout=60, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)
    if proc.returncode == 0:
        return True, ""
    said = proc.stderr.strip() or proc.stdout.strip()
    return False, said.splitlines()[-1][:200] if said else f"exit {proc.returncode}"


def _image_present(runtime: str, image: str) -> bool:
    import subprocess

    try:
        proc = subprocess.run([runtime, "image", "inspect", image],  # noqa: S603
                              capture_output=True, text=True, timeout=60, check=False)
    except (OSError, subprocess.SubprocessError):
        return False
    return proc.returncode == 0


def _image_label(runtime: str, image: str) -> str | None:
    from .compat import image_version

    return image_version(runtime, image)


def _image_starts(runtime: str, image: str) -> tuple[bool, str]:
    """Start the image once, with no network, to read the digest of the tree it was
    built from. The digest is information; that a container *started* is the
    measurement — the runtime, the image and this architecture, together."""
    import subprocess

    from .tree_hash import IMAGE_DIGEST_FILE

    cmd = [runtime, "run", "--rm", "--network=none", "--entrypoint", "cat", image,
           IMAGE_DIGEST_FILE]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120,  # noqa: S603
                              check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)
    if proc.returncode == 0:
        return True, proc.stdout.strip()
    if proc.returncode == 1:
        return True, ""                    # started; an image from before the digest
    detail = (proc.stderr.strip() or proc.stdout.strip() or f"exit {proc.returncode}")
    return False, detail.splitlines()[-1][:200]


def _platform() -> str:
    import platform

    return platform.system()


def _selinux_enforcing() -> bool:
    from .runner import selinux_enforcing

    return selinux_enforcing()


def _tree_label(path: Path) -> str | None:
    """The SELinux context of the Workspace directory, or None where there is none."""
    getxattr = getattr(os, "getxattr", None)
    if getxattr is None:
        return None
    try:
        return getxattr(str(path), "security.selinux").decode(errors="replace").rstrip("\0")
    except OSError:
        return None


def _reachable(host: str, port: int = 443) -> bool:
    """A bounded TCP connect — what a fetch would do first. Only when asked."""
    import socket

    try:
        socket.create_connection((host, port), timeout=3.0).close()
    except OSError:
        return False
    return True


# --------------------------------------------------------------------- checks


def _image_reference() -> str:
    """The same expression `runner.IMAGE` is built from, read now rather than at
    import, so `VALVUR_IMAGE=… valvur doctor` checks what it names."""
    from .version import default_image

    return os.environ.get("VALVUR_IMAGE") or default_image()


def run(workspace: Path, *, network: bool = False) -> list[Check]:
    workspace = Path(workspace).resolve()
    fetch_due = not _cache.db_present() or not _cache.name_index_present()
    checks: list[Check] = []

    checks.append(_check_python(fetch_due))
    runtime, runtime_check = _check_runtime()
    checks.append(runtime_check)
    image_check, image_local = _check_image(runtime)
    checks.append(image_check)
    checks.append(_check_database())
    checks.append(_check_index())
    checks.append(_check_kev())
    checks.append(_check_selinux(workspace))
    checks.append(_check_mcp(workspace))
    checks.append(_check_network(network, fetch_due=fetch_due or not image_local))
    return checks


def _check_python(fetch_due: bool) -> Check:
    import sys

    roots = _trusted_roots()
    where = f"{sys.version.split()[0]} at {sys.executable}"
    if roots > 0:
        return Check("python", "ok", f"{where}: {roots} trusted roots")
    return Check(
        "python", "fail" if fetch_due else "warn",
        f"{where}: 0 trusted roots — this interpreter cannot verify any TLS certificate, "
        "so every fetch valvur makes from the host (the database, the index, KEV) fails "
        "with CERTIFICATE_VERIFY_FAILED" + (
            "; a fetch is due, so the first scan will" if fetch_due
            else "; the cache is filled, so a scan runs, but `valvur update` will not"),
        "python.org's macOS build ships no CA bundle: run "
        "'/Applications/Python 3.x/Install Certificates.command' once. Any other "
        "interpreter: point SSL_CERT_FILE at a CA bundle (with certifi installed, "
        "python -c 'import certifi; print(certifi.where())' prints one), or use a "
        "Python from Homebrew, uv or your distribution, which trust the system store.",
    )


def _check_runtime() -> tuple[str | None, Check]:
    """Returns the runtime's path when it is found and running, else None."""
    try:
        runtime = _find_runtime()
    except Exception as exc:  # NoContainerRuntime carries the install lines
        head, _, rest = str(exc).partition("\n")
        return None, Check("runtime", "fail", head or "no container runtime found",
                           rest.strip() or "install Docker or Podman")
    version = _runtime_version(runtime) or "version unknown"
    running, why = _runtime_running(runtime)
    if not running:
        return None, Check(
            "runtime", "fail", f"{version} at {runtime}, not running: {why}",
            "start it — Docker Desktop (or `open -a Docker`), `systemctl start docker`, "
            "or `podman machine start` — and run doctor again",
        )
    return runtime, Check("runtime", "ok", f"{version} at {runtime}, running")


def _check_image(runtime: str | None) -> tuple[Check, bool]:
    """Returns the check and whether the image is local."""
    from .compat import _series

    image = _image_reference()
    if runtime is None:
        return Check("image", "skip", f"{image}: not checked without a runtime"), False
    if not _image_present(runtime, image):
        return Check(
            "image", "info", f"{image}: not local; the first scan pulls it and says so "
            "on the status line (about 220MB compressed)",
        ), False
    declared = _image_label(runtime, image)
    ours = __version__
    if declared is not None and _series(declared) != _series(ours):
        return Check(
            "image", "fail",
            f"{image}: version {declared} does not match the shim's {ours} (F1.9) — a "
            "scan refuses the pair",
            f"update both: pip install -U valvur && {runtime} pull {image}; or pin the "
            f"image to the shim: VALVUR_IMAGE=ghcr.io/maverickhq/valvur:{ours}",
        ), True
    started, digest = _image_starts(runtime, image)
    label = (f"version {declared} matches the shim" if declared is not None
             else "no version label (predates the F1.9 check)")
    if not started:
        return Check(
            "image", "fail", f"{image}: {label}; does not start: {digest}",
            f"{runtime} run --rm {image} true — the runtime's own error is the diagnosis; "
            "an 'exec format error' means the image is for another architecture",
        ), True
    built = f" (built from {digest[:8]})" if digest else ""
    return Check("image", "ok", f"{image}: {label}; starts{built}"), True


def _check_database() -> Check:
    if not _cache.db_present():
        return Check("database", "info", "not present; the first scan fetches it and says "
                     "so (about 118MB)")
    age = _cache.db_age_days()
    if age is None:
        return Check("database", "warn", "present, but its age cannot be read; a scan "
                     "that finds nothing reads inconclusive", "valvur update")
    if age > _cache.DB_STALE_AFTER_DAYS:
        return Check(
            "database", "warn",
            f"{age:.1f} days old (threshold {_cache.DB_STALE_AFTER_DAYS}); a scan that "
            "finds nothing reads inconclusive",
            "valvur update — or `valvur update --if-stale` from a hook, which costs one "
            "file read when current",
        )
    return Check("database", "ok", f"{age:.1f} days old")


def _check_index() -> Check:
    import json

    from . import name_index

    if not _cache.name_index_present():
        return Check("index", "info", "not present; the first scan fetches it and says so "
                     "(about 35MB, signed)")
    directory = _cache.name_index()
    try:
        entries = json.loads((directory / name_index.METADATA).read_text(encoding="utf-8"))
        entries = entries.get("ecosystems") or {}
    except (OSError, ValueError, AttributeError):
        entries = {}
    counts = " · ".join(
        f"{eco} {int((entries.get(eco) or {}).get('count') or 0):,}"
        for eco in name_index.FILES if (directory / name_index.FILES[eco]).is_file()
    )
    missing = [eco for eco, filename in name_index.FILES.items()
               if not (directory / filename).is_file()]
    age = _cache.name_index_age_days()
    aged = f"{age:.1f} days old" if age is not None else "age unknown"
    if missing:
        return Check(
            "index", "warn",
            f"{aged} — {counts}; no list for {', '.join(missing)}, so a project declaring "
            "those dependencies fails its existence check",
            "valvur update",
        )
    if age is None or age > _cache.NAME_INDEX_STALE_AFTER_DAYS:
        return Check(
            "index", "warn",
            f"{aged} (threshold {_cache.NAME_INDEX_STALE_AFTER_DAYS}) — {counts}; a name "
            "registered since is reported as nonexistent",
            "valvur update",
        )
    return Check("index", "ok", f"{aged} — {counts}")


def _check_kev() -> Check:
    import time

    cached = _cache.root() / "kev.json"
    if cached.is_file():
        age = (time.time() - cached.stat().st_mtime) / 86400
        return Check("kev", "info", f"host cache, {age:.1f} days old")
    return Check("kev", "info", "bundled snapshot from the image; `valvur update` "
                 "refreshes it")


def _check_selinux(workspace: Path) -> Check:
    from .runner import RELABEL_ENV

    system = _platform()
    if system != "Linux":
        return Check("selinux", "ok", f"not applicable on {system}")
    if not _selinux_enforcing():
        return Check("selinux", "ok", "not enforcing")
    label = _tree_label(workspace) or "unknown"
    context = label.split(":")[2] if label.count(":") >= 2 else label
    if "container_file_t" in label:
        return Check("selinux", "ok", f"enforcing; the workspace is labelled {context}")
    if os.environ.get(RELABEL_ENV) == "1":
        return Check(
            "selinux", "ok",
            f"enforcing; the workspace ({context}) will be relabelled container_file_t "
            f"because {RELABEL_ENV}=1 — that label persists after the scan",
        )
    return Check(
        "selinux", "fail",
        f"enforcing, and the workspace is labelled {context}, which a container may "
        "not read: every mount is denied (measured on Fedora CoreOS, task 20.1)",
        f"chcon -R -t container_file_t {workspace}   (undo: restorecon -R -F {workspace}) "
        f"— or {RELABEL_ENV}=1 valvur scan, which relabels for you and persists",
    )


# ----------------------------------------------------------------- MCP clients


def _check_mcp(workspace: Path) -> Check:
    """Which agent, if any, has been told about this server — Claude Code and Kiro,
    the two clients the README's snippets address (P6)."""
    home = Path.home()
    found: list[str] = []

    claude_disabled = _claude_disabled(workspace, home)
    for shown, path, project in (
        (".mcp.json", workspace / ".mcp.json", None),
        ("~/.claude.json", home / ".claude.json", None),
        ("~/.claude.json [this project]", home / ".claude.json", str(workspace)),
    ):
        found += _servers_in(shown, path, project=project, disabled_by=claude_disabled)
    for shown, path in (
        (".kiro/settings/mcp.json", workspace / ".kiro" / "settings" / "mcp.json"),
        ("~/.kiro/settings/mcp.json", home / ".kiro" / "settings" / "mcp.json"),
    ):
        found += _servers_in(shown, path, project=None, disabled_by={})
    if not found:
        found.append("no MCP client configuration names valvur here (Claude Code: "
                     ".mcp.json, ~/.claude.json; Kiro: .kiro/settings/mcp.json); the CLI "
                     "needs none")
    switched_off = _kiro_switched_off(workspace, home)
    if switched_off:
        found.append(f"kiroAgent.configureMCP is Disabled in {switched_off}, so Kiro "
                     "starts no MCP server at all")
    return Check("mcp", "info", "; ".join(found))


def _read_json(path: Path) -> dict | None:
    import json

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError:
        return None
    except ValueError:
        return {"__unreadable__": True}
    return data if isinstance(data, dict) else {}


def _servers_in(shown: str, path: Path, *, project: str | None,
                disabled_by: dict[str, str]) -> list[str]:
    data = _read_json(path)
    if data is None:
        return []
    if data.get("__unreadable__"):
        return [f"{shown}: unreadable (not JSON)"]
    if project is not None:
        data = (data.get("projects") or {}).get(project) or {}
    servers = data.get("mcpServers") or {}
    out = []
    for name, spec in servers.items():
        if not isinstance(spec, dict):
            continue
        command = " ".join([str(spec.get("command") or ""), *map(str, spec.get("args") or [])])
        if name != "valvur" and "valvur" not in command:
            continue
        line = f"{shown}: {name} ({command.strip()})"
        if spec.get("disabled") is True:
            line += ", DISABLED"
        elif name in disabled_by:
            line += f", DISABLED in {disabled_by[name]}"
        out.append(line)
    return out


def _claude_disabled(workspace: Path, home: Path) -> dict[str, str]:
    """Servers a Claude Code settings file has switched off, by name."""
    disabled: dict[str, str] = {}
    for shown, path in (
        (".claude/settings.json", workspace / ".claude" / "settings.json"),
        (".claude/settings.local.json", workspace / ".claude" / "settings.local.json"),
        ("~/.claude/settings.json", home / ".claude" / "settings.json"),
    ):
        data = _read_json(path) or {}
        for name in data.get("disabledMcpjsonServers") or []:
            disabled.setdefault(str(name), shown)
    return disabled


def _kiro_switched_off(workspace: Path, home: Path) -> str:
    user = (home / "Library" / "Application Support" if _platform() == "Darwin"
            else home / ".config") / "Kiro" / "User" / "settings.json"
    candidates = [(".vscode/settings.json", workspace / ".vscode" / "settings.json"),
                  ("Kiro user settings", user)]
    for shown, path in candidates:
        data = _read_json(path) or {}
        if str(data.get("kiroAgent.configureMCP", "")).lower() == "disabled":
            return shown
    return ""


# --------------------------------------------------------------------- network

#: What `full` reaches from the host and from the container: the five registries
#: the dependency-reality Check asks for first-publish age, Maven Central and the
#: Go proxy for existence, OSV for the second advisory source, FIRST for EPSS.
FULL_HOSTS = ("pypi.org", "registry.npmjs.org", "rubygems.org", "repo.packagist.org",
              "crates.io", "repo1.maven.org", "proxy.golang.org", "api.osv.dev",
              "api.first.org")


def _first_run_hosts() -> list[tuple[str, int]]:
    """The hosts a first run — or `valvur update` — fetches from, honouring every
    mirror setting the air-gapped guide documents."""
    from urllib.parse import urlsplit

    from . import name_index, oci
    from .cli import KEV_URL, KEV_URL_ENV
    from .runner import DEFAULT_DB_REPOSITORY, db_repository

    hosts: list[tuple[str, int]] = []

    def registry(reference: str) -> None:
        try:
            host = oci.Reference.parse(reference).host
        except oci.RegistryError:
            return                       # a local tag such as valvur:dev
        name, _, port = host.partition(":")
        hosts.append((name, int(port) if port.isdigit() else 443))

    def url(raw: str) -> None:
        parts = urlsplit(raw)
        if parts.hostname:
            hosts.append((parts.hostname, parts.port or (80 if parts.scheme == "http" else 443)))

    registry(_image_reference())
    registry(db_repository() or DEFAULT_DB_REPOSITORY)
    mirror = os.environ.get(name_index.MIRROR_ENV, "").strip()
    if mirror:
        url(mirror)
    else:
        registry(name_index.repository())
    url(os.environ.get(KEV_URL_ENV, "").strip() or KEV_URL)
    return list(dict.fromkeys(hosts))      # deduplicated, first occurrence's order


def _check_network(asked: bool, *, fetch_due: bool) -> Check:
    if not asked:
        return Check("network", "ok", "not probed (valvur doctor --network)")
    from concurrent.futures import ThreadPoolExecutor

    first = _first_run_hosts()
    full = [(h, 443) for h in FULL_HOSTS]
    with ThreadPoolExecutor(max_workers=8) as pool:
        first_up = list(pool.map(lambda hp: _reachable(*hp), first))
        full_up = list(pool.map(lambda hp: _reachable(*hp), full))

    def describe(label: str, hosts: list[tuple[str, int]], up: list[bool]) -> str:
        down = [h for (h, _), ok in zip(hosts, up, strict=True) if not ok]
        if not down:
            return f"{label}: {', '.join(h for h, _ in hosts)} reachable"
        others = len(hosts) - len(down)
        return (f"{label}: {', '.join(down)} UNREACHABLE"
                + (f" ({others} other{'s' if others != 1 else ''} reachable)" if others else ""))

    detail = "; ".join([
        describe("first run and `valvur update`", first, first_up),
        describe("`full`", full, full_up),
    ])
    if not all(first_up):
        return Check(
            "network", "fail" if fetch_due else "warn", detail,
            "a first run and `valvur update` need the first group; once the cache is "
            "filled, `offline` scans need none of these. Behind a mirror, see "
            "docs/AIR-GAPPED.md",
        )
    if not all(full_up):
        return Check("network", "warn", detail,
                     "`full` needs the second group; `offline` (the default) needs none")
    return Check("network", "ok", detail)


# --------------------------------------------------------------------- report


def failed(checks: list[Check]) -> bool:
    return any(c.level == "fail" for c in checks)


def render(checks: list[Check], workspace: Path | None = None) -> str:
    marks = {"fail": "FAIL", "warn": "warn", "info": "info", "ok": "ok", "skip": "skip"}
    lines = [f"valvur {__version__} doctor" + (f" — {workspace}" if workspace else "")]
    for check in checks:
        lines.append(f"  {marks[check.level]:<5} {check.name}: {check.detail}")
        if check.fix and check.level in ("fail", "warn"):
            lines.append(f"        fix: {check.fix}")
    failures = [c for c in checks if c.level == "fail"]
    lines.append("")
    if failures:
        lines.append(f"not ready: {len(failures)} check{'s' if len(failures) != 1 else ''} "
                     "would fail a scan here.")
    else:
        lines.append("ready: a scan will run here.")
    return "\n".join(lines)
