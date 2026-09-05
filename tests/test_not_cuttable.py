"""The not-cuttable set, as tests that fail when broken (task 17.1).

`tasks.md` states of these requirements: *"Each is a test that fails the build if
broken."* That sentence was false when written — **F9.4 had no test at all**, and
several others were satisfied only by tests that never named them, so nothing
connected the claim to the check.

These are negative requirements, which is why they were skipped: it is easy to test
that a thing happens and awkward to test that a thing never does. Awkward is not the
same as unnecessary — a negative requirement with no test is a promise nobody is
keeping.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SOURCE = {p: p.read_text() for p in (REPO / "src").rglob("*.py")}


def _source_matching(pattern: str) -> list[str]:
    found = []
    for path, text in SOURCE.items():
        for number, line in enumerate(text.splitlines(), start=1):
            if line.lstrip().startswith("#"):
                continue                      # a comment saying "we do not do X"
            if re.search(pattern, line):
                found.append(f"{path.relative_to(REPO)}:{number} {line.strip()[:70]}")
    return found


# --------------------------------------------------------------- F9.4 (no watching)

def test_valvur_starts_no_scan_it_was_not_asked_to_start():
    """F9.4 — no file watching, no save hooks, no scan except by explicit invocation.

    The requirement holds today in fact: there is no watching code. It was not
    *enforced*, so nothing would have failed if someone added a watcher tomorrow —
    and ADR-0009's reasoning is that an agent driving findings to zero has cheaper
    paths than correct fixes, which a watcher would hand it on a schedule.
    """
    watching = _source_matching(
        r"\b(watchdog|inotify|FSEvents|kqueue|watchfiles|pyinotify)\b"
        r"|\bon_save\b|\bwatch_files\b|\bschedule\.\w+\("
    )

    assert not watching, "valvur appears to watch for changes: " + "; ".join(watching)


def test_no_dependency_exists_that_could_watch_files():
    """The other half. A watcher can arrive as a dependency as easily as as code, and
    a transitive one would be invisible to the test above."""
    declared = tomllib.loads((REPO / "pyproject.toml").read_text())["project"]
    runtime = declared.get("dependencies", [])

    assert runtime == [], (
        f"valvur declares runtime dependencies ({runtime}); ADR-0015 keeps them at "
        "zero, and each one is a way for a watcher to arrive unnoticed"
    )


def test_every_scan_entry_point_requires_an_explicit_call():
    """A scan starts from `valvur scan` or the `scan` MCP tool. Neither fires on a
    timer, and nothing else calls `api.scan`."""
    callers = {
        path.relative_to(REPO).as_posix()
        for path, text in SOURCE.items()
        if re.search(r"\bscan\(|_run_scan\b", text)
    }

    assert callers <= {
        "src/valvur/api.py", "src/valvur/cli.py", "src/valvur/operations.py",
    }, f"something other than the CLI or the MCP surface starts scans: {callers}"


# ------------------------------------------------------- F1.7, F1.8 (no strings)

def test_no_credential_is_required_to_scan():
    """F1.7 — no account, API key, token or credential. ADR-0008 rejected an
    otherwise credible scanner over exactly this, and applying the rule to a
    competitor while quietly breaking it ourselves would make the principle
    meaningless."""
    credentialish = _source_matching(
        r"environ(?:\.get)?\(\s*[\"'][A-Z_]*(TOKEN|API_KEY|SECRET|PASSWORD|CREDENTIAL)"
    )

    assert not credentialish, "valvur reads a credential: " + "; ".join(credentialish)


def test_no_telemetry_is_emitted_under_any_profile():
    """F1.8. The `offline` Profile is proven silent by N2.1's socket test; this is
    the broader claim, which holds on `full` too, where sockets are permitted and
    the only legitimate destinations are advisory and registry APIs."""
    phoning = _source_matching(
        r"\b(analytics|telemetry|posthog|segment\.io|mixpanel|sentry_sdk|amplitude)\b"
        r"|track_event|report_usage"
    )

    assert not phoning, "valvur appears to emit telemetry: " + "; ".join(phoning)


# ------------------------------------------------------------ F1.10 (one artifact)

def test_there_is_no_cloud_specific_code_path():
    """F1.10 — the same image, wherever it runs. Not a claim that any particular
    platform works: 12a.4 established that valvur's shim needs a container runtime,
    which serverless platforms do not expose. It is the claim that no branch anywhere
    behaves differently because of where it is."""
    cloud = _source_matching(
        r"\b(boto3|botocore|google\.cloud|azure\.|AWS_REGION|AWS_EXECUTION_ENV)\b"
        r"|\bis_aws\b|\bon_fargate\b"
    )

    assert not cloud, "a cloud-specific code path exists: " + "; ".join(cloud)
