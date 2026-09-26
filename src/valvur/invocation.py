"""The contract between a Scanner's adapter and the container runner (26.2.1).

An adapter owns everything tool-specific — the command line, the report file, the
timeout, whether the tool needs a network or an executable scratch — and says so
in one `Invocation`. The runner owns everything container-specific — the runtime,
the mounts, the user, the read-only root, the SELinux labels, the kill registry —
and runs any Invocation the same way. Until this, `runner.py` carried a
`run_<tool>` method per Scanner and the adapter carried only the parser: one
Scanner, two homes, no contract between them, and `runner.py` at 860 lines.

`ScannerOutput` lives here too, so both halves import it from the same place;
`runner` re-exports it for the callers that always found it there.
"""

from __future__ import annotations

from dataclasses import dataclass

#: Phrases in a Scanner's stderr that mean "nothing to analyse" rather than "could
#: not run". OSV-Scanner reads lockfiles only, so a project with a pyproject.toml
#: and no lockfile makes it exit 128 saying "No package sources found" — a normal
#: condition that was once reported as a failure, which marked the whole scan
#: incomplete and made every lockfile-less project look broken. The mirror of the
#: Phase 8 lesson: there, missing output WAS a failure. An adapter opts into this
#: through `empty_when`; a tool that never says such a thing gets no allowance.
NOTHING_TO_SCAN: tuple[str, ...] = (
    "no package sources found",
    "no such file or directory",
    "no files to scan",
)


@dataclass(frozen=True)
class ScannerOutput:
    tool: str
    version: str
    stdout: str
    stderr: str
    exit_code: int
    #: The program and arguments the runner launched after the image name — the
    #: Invocation's `argv`, carried back so `run.json` can say what produced the
    #: raw output beside its version and duration (28.3.6). Empty when nothing
    #: was launched: a skip, an image pull, a fake.
    argv: tuple[str, ...] = ()


@dataclass(frozen=True)
class Invocation:
    """One container run, as the adapter that owns the tool describes it."""

    #: The Scanner's name as every surface reports it, and the version the image
    #: pins — the adapter states it, and a test holds it to the image's.
    tool: str
    version: str
    #: The program and its arguments, after the image name. `/workspace` is the
    #: source tree, read-only; `/results` is a scratch mount the report lands in;
    #: `/cache/trivy` and `/cache/names` are the host cache, mounted by the runner.
    argv: tuple[str, ...]
    #: The file under `/results` the tool writes its report to, read back as the
    #: output's stdout; None when the tool reports on stdout itself.
    report: str | None = None
    #: Whether the container is launched with a network interface. False is
    #: `--network=none`, and nothing the adapter says can change that (N2.1).
    network: bool = False
    timeout: int = 600
    #: Whether `/tmp` may hold executables — Opengrep unpacks and runs
    #: opengrep-core. Granted per Scanner, never to the fleet.
    allow_exec: bool = False
    #: Stderr phrases that mean an empty result, honestly earned (see
    #: NOTHING_TO_SCAN). Empty: a missing report is always a failure.
    empty_when: tuple[str, ...] = ()
    #: Files the runner writes into the scratch mount before the launch, as
    #: (name, text): a generated config the tool reads at `/results/<name>`
    #: (Gitleaks's allowlist, 29.0.1). The mount is the tool's to read and the
    #: runner's to remove, so nothing is left on the host.
    files: tuple[tuple[str, str], ...] = ()
    #: Environment the container is launched with, as (name, value): the
    #: excluded prefixes for the Checks (`exclusions.EXCLUDE_ENV`). The network
    #: grant is not here — egress sets it, and nothing an adapter says can.
    env: tuple[tuple[str, str], ...] = ()
