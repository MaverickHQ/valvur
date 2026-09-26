"""The design says what the code does: the tables in `design.md`, the README's
platform claims, the scheduled workflows' failure path, the Opengrep binaries'
checksums. Split from `test_constraints.py` (28.4.3).
"""

from __future__ import annotations

from pathlib import Path

# ------------------------------------------- the design says what the code does


DESIGN_MD = Path(__file__).resolve().parent.parent / ".kiro" / "specs" / "valvur" / "design.md"


def _design_table(header: str) -> list[list[str]]:
    """Rows of the `design.md` table whose header's first cell is `header`, each
    row as its cells with backticks stripped."""
    rows: list[list[str]] = []
    active = False
    for line in DESIGN_MD.read_text().splitlines():
        if line.startswith("|"):
            cells = [c.strip().strip("`") for c in line.strip("|").split("|")]
            if cells and cells[0].lower() == header:
                active = True
                continue
            if active and cells and set(cells[0]) <= {"-"}:
                continue
            if active:
                rows.append(cells)
        else:
            active = False
    assert rows, f"design.md has no table headed `{header}`"
    return rows


def test_the_designs_mcp_table_names_every_tool_and_no_others():
    """27.2.2. §8 listed four tools of six for the nine days since `scan_cancel`
    and `doctor` shipped (23.3.3, 23.3.1) — a joining reader's first picture of
    the MCP surface, two tools short. The table is now held to the registry."""
    from valvur.mcp.tools import registry

    listed = [row[0] for row in _design_table("tool")]

    assert set(listed) == {tool.name for tool in registry()}, \
        "design.md §8 and the MCP registry disagree about which tools exist"
    assert len(listed) == len(set(listed)), f"§8 lists a tool twice: {listed}"


def test_the_designs_dependency_reality_table_names_every_ecosystem():
    """27.2.2. §5.1 said `requirements*.txt` against PyPI and nothing else, two
    ADRs after that stopped being true (ADR-0018; five ecosystems offline since
    23.2.2 and 23.2.3, JVM and Go on `full` since 22.A.4). The ecosystems are now read
    from the table and held to `ecosystems.MANIFESTS`, so the next one added has
    to appear here."""
    from valvur import ecosystems

    listed = {row[0] for row in _design_table("ecosystem")}

    assert listed == {m.label for m in ecosystems.MANIFESTS.values()}, \
        "design.md §5.1 and ecosystems.MANIFESTS disagree about what is read"


def test_the_design_states_the_version_it_describes():
    """Every rewrite of this document has moved its version; a reader comparing
    two copies needs that to be true."""
    import re

    stated = re.search(r"\*\*Version:\*\* (\d+\.\d+)", DESIGN_MD.read_text())

    assert stated, "design.md no longer states a version"
    assert stated.group(1) >= "1.2", (
        "design.md was rewritten as built in 27.2.2; a later change should move "
        "the version again"
    )


def test_the_platform_table_claims_only_the_testing_that_exists():
    """27.2.1. The README put macOS and Linux in one row — *"tested on every commit
    against both runtimes"* — and that is true of Linux and not of macOS: every
    real-container job runs on `ubuntu-24.04` or `ubuntu-24.04-arm`, and
    `test_portability.py`'s macOS cases monkeypatch `platform.system()`, which
    cannot exercise Docker Desktop's mount sharing, a Podman VM's paths, or UID
    translation. A claim about continuous testing needs a workflow that runs
    continuously: a `macos-` runner in a job a push or a pull request starts, not
    one a human dispatches by hand."""
    import re

    readme = Path("README.md").read_text()
    table = readme.split("## Platforms", 1)[1].split("\n\n**", 1)[0]
    rows = [line for line in table.splitlines() if line.startswith("|")]
    assert rows, "the README no longer has a platform table"

    continuous = set()
    for path in sorted(Path(".github/workflows").glob("*.yml")):
        text = path.read_text()
        triggers = text.split("\njobs:", 1)[0]
        if re.search(r"^\s*(push|pull_request):", triggers, re.M):
            continuous |= set(re.findall(r"runs-on:\s*(macos-\S+)", text))

    # A row that DENIES the claim is not making it — "not on every commit" is the
    # honest form and has to survive this test, so the denial is removed before
    # the claim is looked for. (Written the other way first, and the corrected
    # row failed its own ratchet.)
    def claims_continuous(row: str) -> bool:
        without_denial = re.sub(r"not on every commit", "", row, flags=re.I)
        return "every commit" in without_denial

    claiming = [r for r in rows
                if re.search(r"\bmac ?os\b", r, re.I) and claims_continuous(r)]
    assert not claiming or continuous, (
        "the platform table says macOS is tested on every commit, and no workflow "
        f"runs a macos- runner on push or pull_request: {claiming}"
    )
def test_a_scheduled_workflows_failure_becomes_an_issue():
    """27.2.7. `index.yml` (daily) and `corpus.yml` (weekly) carry the work nobody
    is watching: a red index means the published name index stopped being rebuilt,
    and a red corpus means a rule change's false positives ship unnoticed. GitHub
    mails a scheduled failure to the workflow file's last committer and does
    nothing else, so the record of it is one person's inbox. Each now opens an
    issue — reusing the open one rather than filing a second — under
    `issues: write`, with the run link, so the failure is a tracked thing."""
    import re

    scheduled = []
    for path in sorted(Path(".github/workflows").glob("*.yml")):
        text = path.read_text()
        if re.search(r"^\s*schedule:", text.split("\njobs:", 1)[0], re.M):
            scheduled.append((path.name, text))

    # `retention.yml` (weekly) joined in 28.3.1: a red run there means the
    # packages stopped being pruned, which nobody would notice for months.
    assert {name for name, _ in scheduled} == {"index.yml", "corpus.yml", "retention.yml"}, \
        f"a scheduled workflow was added or removed: {[n for n, _ in scheduled]}"

    for name, text in scheduled:
        assert re.search(r"^\s*issues:\s*write", text, re.M), \
            f"{name} cannot open an issue: no issues: write"
        failure_steps = [block for block in text.split("      - name: ")
                         if re.search(r"^\s*if:\s*failure\(\)", block, re.M)]
        assert failure_steps, f"{name} has no `if: failure()` step"
        [step] = failure_steps
        assert "gh issue" in step, f"{name}'s failure step does not use `gh issue`"
        assert "github.run_id" in step and "$RUN" in step, \
            f"{name}'s issue does not carry a link to the run that failed"
        # One issue, not one per run: a job broken for a week is one problem.
        assert "gh issue comment" in step and "gh issue list" in step, \
            f"{name} files a new issue for every failure"
        # The permission is per job, not repository-wide: `contents: read` at the
        # top of the file is what a pull request from a fork gets.
        assert re.search(r"^permissions:\n  contents: read\n", text, re.M), \
            f"{name} grants more than read at the top level"


def test_the_opengrep_binaries_are_checksum_pinned():
    """Task 15.2. They were fetched over HTTPS and trusted, with no verification of
    any kind, beside a comment noting that Opengrep publishes them signed."""
    import re

    dockerfile = Path("Dockerfile").read_text()

    for arch in ("AMD64", "ARM64"):
        pin = re.search(rf"^ARG OPENGREP_SHA256_{arch}=([0-9a-f]{{64}})$", dockerfile, re.M)
        assert pin, f"no pinned SHA256 for {arch}"

    assert "sha256sum -c -" in dockerfile, (
        "the pinned digests are declared but never checked, which is worse than not "
        "declaring them: it reads as verification and is not"
    )


def test_only_the_needed_opengrep_binary_is_fetched():
    """Task 15.4. Both were ADDed and the unused one deleted — but layers are
    additive, so `rm` reclaims nothing. Measured at 98MB of dead weight in every
    image, for a 50MB tool."""
    dockerfile = Path("Dockerfile").read_text()

    assert "FROM opengrep-${TARGETARCH}" in dockerfile, (
        "the per-architecture stage selection is gone; both binaries will ship again"
    )
    assert "rm -f /tmp/opengrep_*" not in dockerfile


