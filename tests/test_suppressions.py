"""Sub-phase 7.0 — suppression parsing and matching.

An accepted risk is a team decision, so `.security-scan.toml` is committed — unlike
the Results Folder, which never is.
"""

from datetime import date

from valvur import scan
from valvur.adapters import CheckAdapter
from valvur.suppressions import Policy, Suppression, load


def _write_policy(workspace, body):
    (workspace / ".security-scan.toml").write_text(body, encoding="utf-8")


VALID = """
[[suppress]]
fingerprint = "{fp}"
rule = "valvur.licence.missing"
path = "."
expires = 2099-12-31
reason = "Fixture repository; a licence is deliberately absent."
"""


def _licence_fingerprint():
    from valvur.fingerprint import derive

    return derive("licence", "<project>", "missing")


def test_a_suppression_requires_context_a_reviewer_can_read(workspace):
    """F8.2 — the hash is the matching key, never the whole entry.

    A pull request containing only a fingerprint tells a reviewer nothing about what
    is being accepted, which throws away the entire reason for per-class identity.
    """
    _write_policy(workspace, """
[[suppress]]
fingerprint = "abc123"
expires = 2099-12-31
reason = "because"
""")

    policy = load(workspace)

    assert policy.suppressions == []
    assert "missing rule, path" in policy.problems[0].detail


def test_a_well_formed_suppression_parses(workspace):
    _write_policy(workspace, VALID.format(fp=_licence_fingerprint()))

    policy = load(workspace)

    assert len(policy.suppressions) == 1
    assert policy.suppressions[0].rule == "valvur.licence.missing"
    assert policy.problems == []


def test_a_suppression_marks_a_finding_rather_than_removing_it(
    workspace, runner_finding_nothing
):
    """F8.6 — omitting it would let an accepted risk become an invisible one."""
    _write_policy(workspace, VALID.format(fp=_licence_fingerprint()))

    run = scan(workspace, runner=runner_finding_nothing,
               adapters=[CheckAdapter("licence-file")], profile="quick")

    licence = next(f for f in run.findings if f.rule == "valvur.licence.missing")
    assert licence.suppressed is not None
    assert "valvur.licence.missing at ." in licence.suppressed


def test_a_suppression_does_not_match_a_different_finding(workspace, runner_finding_nothing):
    _write_policy(workspace, VALID.format(fp="0" * 32))

    run = scan(workspace, runner=runner_finding_nothing,
               adapters=[CheckAdapter("licence-file")], profile="quick")

    assert all(f.suppressed is None for f in run.findings)


def test_expiry_is_inclusive_and_utc():
    """7.1.7 — ambiguity means two machines disagree about whether a build passes."""
    suppression = Suppression("fp", "rule", "path", date(2026, 6, 15), "reason")

    assert not suppression.is_expired(date(2026, 6, 15)), "expiry day is still valid"
    assert suppression.is_expired(date(2026, 6, 16))


def test_a_missing_policy_file_is_not_an_error(workspace):
    policy = load(workspace)

    assert policy == Policy([], [])
