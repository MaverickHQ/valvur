"""Phase 11 cycles 2 and 3 — coverage has not narrowed, and the offline Profile
misses nothing a networked one finds. Split from `test_constraints.py` (28.4.3).
"""

from __future__ import annotations

import pytest

from valvur import profiles
from valvur.api import scan

# ------------------------------------------ cycle 2: coverage has not narrowed

# Measured on the `full` Profile, 2026-09-05: 75 findings across nine Scanners —
# osv-scanner 38, trivy 37, checkov 13, opengrep 12, ai-artifact 6, gitleaks 2,
# dependency-reality 2, licence-file 1, valvur 1.
#
# Floors, not exact counts. Advisory databases grow, and a test that breaks whenever
# OSV publishes is a test people delete — but a Scanner reaching ZERO is never
# normal, and that is what every silent failure this project has hit looked like.
#
# Opengrep reads 12 here rather than the 14 in the golden fixture: rules ship INSIDE
# the image, so `valvur.pinning.mutable-action-ref` (added 12a.6) reaches a real scan
# only once the image is rebuilt. The golden covers the rule today; this number moves
# when 12a.7 rebuilds.
CANARY_FLOOR = {
    "osv-scanner": 20,
    "trivy": 20,
    "opengrep": 8,
    "checkov": 8,
    "ai-artifact": 5,
    "gitleaks": 2,
    "dependency-reality": 2,
    "licence-file": 1,
}


@pytest.mark.e2e
def test_the_canary_fixture_still_exercises_every_scanner(mountable_tmp):
    """The regression net for silent coverage loss.

    Every defect that mattered this week was a Scanner succeeding perfectly at
    scanning nothing: Trivy's dev-dependency exclusion, "no package sources found"
    treated as a failure, an ecosystem mismatch that double-reported everything. None
    would have been caught by a constraint test. All of them move a number here.
    """
    import collections
    import shutil

    from conftest import FIXTURES

    from valvur.runner import ContainerRunner

    ws = mountable_tmp / "canary"
    shutil.copytree(FIXTURES / "broken-repo", ws)

    run = scan(ws, runner=ContainerRunner(), profile=profiles.FULL)
    counts = collections.Counter(s for f in run.findings for s in f.sources)

    assert run.complete if hasattr(run, "complete") else not run.failures, (
        f"a Scanner failed, so the counts below are not comparable: {run.failures}"
    )
    for tool, floor in CANARY_FLOOR.items():
        assert counts[tool] >= floor, (
            f"{tool} reported {counts[tool]}, floor is {floor} — coverage has "
            f"narrowed. All counts: {dict(counts)}"
        )


@pytest.mark.e2e
def test_the_canary_covers_dev_only_dependencies(mountable_tmp):
    """Trivy excludes dev dependencies by default. On 2026-08-31 that turned a real
    project's 24 CVEs into 0, and the fixture could not have caught it — every
    package in its lockfile was a production dependency.

    `minimist` is reachable only through devDependencies, so it is reported only when
    --include-dev-deps is passed. Verified against the image both ways: without the
    flag the production tree still reports and minimist alone disappears, which is
    exactly the shape of a silent narrowing.
    """
    import shutil

    from conftest import FIXTURES

    from valvur.runner import ContainerRunner

    ws = mountable_tmp / "canary"
    shutil.copytree(FIXTURES / "broken-repo", ws)

    run = scan(ws, runner=ContainerRunner(), profile=profiles.OFFLINE)
    packages = {
        f.dependency.package for f in run.findings if f.dependency and f.dependency.package
    }

    assert "minimist" in packages, (
        "the dev-only dependency was not scanned — Trivy's --include-dev-deps has "
        "been lost, and every project whose vulnerabilities live in build tooling "
        "now reports clean"
    )


# --------------------------------------- cycle 3: the offline Profile misses nothing

@pytest.mark.e2e
def test_the_offline_profile_misses_no_vulnerable_package(mountable_tmp):
    """ADR-0016 claims `offline` gives up a second advisory source and the slopsquat
    Check, and nothing else. That claim was false until 2026-08-31, when `offline`
    returned 0 CVEs on a repository where `full` found 24 — same lockfile, same
    minute. An offline Profile that quietly finds less makes "no network required"
    worth nothing, because the honest advice becomes "run the networked one anyway".

    Asserted at package level, not advisory level. `full` legitimately reports MORE
    advisory IDs, because OSV carries records Trivy's database does not — measured
    2026-09-01: PYSEC-2023-175 on pillow. What must never happen is a vulnerable
    package disappearing, which is what the CLU failure looked like: seven packages
    to zero.
    """
    import shutil

    from conftest import FIXTURES

    from valvur.runner import ContainerRunner

    def packages(profile):
        ws = mountable_tmp / profile
        shutil.copytree(FIXTURES / "broken-repo", ws)
        run = scan(ws, runner=ContainerRunner(), profile=profile)
        return {
            f.dependency.package.lower()
            for f in run.findings
            if f.dependency and f.dependency.package
        }

    offline = packages(profiles.OFFLINE)
    full = packages(profiles.FULL)

    assert offline, "the offline Profile found no vulnerable package at all"
    assert not (full - offline), (
        f"the offline Profile missed packages that full found: {sorted(full - offline)}"
    )


