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


# ------------------------------------------------------------- 7.1 lifecycle

def _scan(workspace, runner):
    return scan(workspace, runner=runner,
                adapters=[CheckAdapter("licence-file")], profile="quick")


def test_a_suppression_without_an_expiry_is_rejected_and_reported(
    workspace, runner_finding_nothing
):
    """F8.3 — an unexpiring suppression is how a real finding gets buried for years."""
    _write_policy(workspace, f"""
[[suppress]]
fingerprint = "{_licence_fingerprint()}"
rule = "valvur.licence.missing"
path = "."
reason = "forever, apparently"
""")

    run = _scan(workspace, runner_finding_nothing)

    assert "valvur.suppression.invalid" in [f.rule for f in run.findings]
    licence = next(f for f in run.findings if f.rule == "valvur.licence.missing")
    assert licence.suppressed is None, "a rejected suppression must not take effect"


def test_an_expired_suppression_reports_its_finding_again_and_is_itself_flagged(
    workspace, runner_finding_nothing
):
    """F8.4 — a lapsed risk acceptance is a decision someone must retake."""
    _write_policy(workspace, f"""
[[suppress]]
fingerprint = "{_licence_fingerprint()}"
rule = "valvur.licence.missing"
path = "."
expires = 2020-01-01
reason = "long past"
""")

    run = _scan(workspace, runner_finding_nothing)

    licence = next(f for f in run.findings if f.rule == "valvur.licence.missing")
    assert licence.suppressed is None, "an expired suppression must not still apply"
    assert "valvur.suppression.expired" in [f.rule for f in run.findings]


def test_a_suppression_matching_nothing_is_reported_as_stale(
    workspace, runner_finding_nothing
):
    """F8.5 — left in place, it will silently accept a future finding that matches."""
    _write_policy(workspace, VALID.format(fp="f" * 32))

    run = _scan(workspace, runner_finding_nothing)

    stale = [f for f in run.findings if f.rule == "valvur.suppression.stale"]
    assert stale
    assert "silently accept a future finding" in stale[0].evidence


def test_an_expired_suppression_is_not_also_reported_as_stale(
    workspace, runner_finding_nothing
):
    """Two findings for one problem is noise, and we spent Phase 5 removing noise."""
    _write_policy(workspace, f"""
[[suppress]]
fingerprint = "{"e" * 32}"
rule = "gone"
path = "gone.py"
expires = 2020-01-01
reason = "expired and matching nothing"
""")

    run = _scan(workspace, runner_finding_nothing)
    rules = [f.rule for f in run.findings]

    assert "valvur.suppression.expired" in rules
    assert "valvur.suppression.stale" not in rules


def test_valvur_never_writes_the_suppression_file(workspace, runner_finding_nothing):
    """F8.7 — the file is the human's. We read it and print one; we never touch it."""
    import hashlib

    _write_policy(workspace, VALID.format(fp=_licence_fingerprint()))
    path = workspace / ".security-scan.toml"
    before = hashlib.sha256(path.read_bytes()).hexdigest()

    _scan(workspace, runner_finding_nothing)

    assert hashlib.sha256(path.read_bytes()).hexdigest() == before


# ----------------------------------------------------------- 7.2 integration

def test_a_suppressed_finding_never_holds_a_ranking_position(workspace):
    """F8.9 — it would crowd out a live one, the exact noise problem F6.5 solved."""
    from valvur.findings import Exploit, Finding
    from valvur.ranking import apply

    ranked = apply([
        Finding(rule="suppressed-critical", path="a", line=0, title="t",
                severity="critical", exploit=Exploit(cve="C", kev=True),
                suppressed="accepted until 2099"),
        Finding(rule="live-low", path="b", line=0, title="t", severity="low"),
    ])

    assert ranked[0].rule == "live-low"


def test_the_summary_counts_active_and_suppressed_separately(
    workspace, runner_finding_nothing
):
    """F8.9 — 'Findings: 84' when 30 are suppressed misstates the result."""
    _write_policy(workspace, VALID.format(fp=_licence_fingerprint()))

    _scan(workspace, runner_finding_nothing)

    summary = (workspace / ".security-scan" / "SUMMARY.md").read_text()
    assert "**suppressed:** 1" in summary
    assert "## Suppressed (1)" in summary
    assert "Still reported, never hidden" in summary


def test_sarif_uses_its_own_suppression_concept(workspace, runner_finding_nothing):
    """An invented property would make IDEs show suppressed findings as live."""
    import json

    _write_policy(workspace, VALID.format(fp=_licence_fingerprint()))

    _scan(workspace, runner_finding_nothing)

    sarif = json.loads((workspace / ".security-scan" / "results.sarif").read_text())
    suppressed = [r for r in sarif["runs"][0]["results"] if r.get("suppressions")]

    assert len(suppressed) == 1
    entry = suppressed[0]["suppressions"][0]
    assert entry["kind"] == "external"
    assert entry["status"] == "accepted"
    assert "expires" in entry["justification"]


def test_the_cross_artifact_invariant_holds_with_suppressions_present(
    workspace, runner_finding_nothing
):
    """F7.13 — suppressed findings stay in findings.json, so they must stay in SARIF."""
    from test_contract import assert_artifacts_agree

    _write_policy(workspace, VALID.format(fp=_licence_fingerprint()))

    _scan(workspace, runner_finding_nothing)

    assert_artifacts_agree(workspace / ".security-scan")


def test_suppressing_a_finding_does_not_mark_it_fixed(workspace, runner_finding_nothing):
    """Suppression is a policy layer, not an identity one. If suppressing read as
    'fixed', un-suppressing would read as 'new' — and the rescan diff would lie."""
    first = _scan(workspace, runner_finding_nothing)
    assert any(f.rule == "valvur.licence.missing" for f in first.findings)

    _write_policy(workspace, VALID.format(fp=_licence_fingerprint()))
    second = _scan(workspace, runner_finding_nothing)

    assert second.fixed == [], "suppressing must not look like fixing"
    licence = next(f for f in second.findings if f.rule == "valvur.licence.missing")
    assert licence.status == "persisting"


# ------------------------------------------------------- 7.3 valvur suppress

def test_valvur_suppress_prints_a_paste_ready_block(workspace, runner_finding_nothing, capsys):
    """F8.8 — without this, writing a suppression means hand-copying 32 hex
    characters out of findings.json, which nobody will do."""
    from valvur.cli import main

    _scan(workspace, runner_finding_nothing)
    fingerprint = _licence_fingerprint()

    exit_code = main(["suppress", fingerprint, str(workspace), "--reason", "deliberate"])

    out = capsys.readouterr().out
    assert exit_code == 0
    assert "[[suppress]]" in out
    assert f'fingerprint = "{fingerprint}"' in out
    assert 'rule = "valvur.licence.missing"' in out
    assert 'reason = "deliberate"' in out


def test_the_printed_block_actually_parses_and_suppresses(
    workspace, runner_finding_nothing, capsys
):
    """The block is only useful if pasting it works. Round-trip it."""
    from valvur.cli import main

    _scan(workspace, runner_finding_nothing)
    main(["suppress", _licence_fingerprint(), str(workspace), "--reason", "deliberate"])
    block = "\n".join(
        line for line in capsys.readouterr().out.splitlines()
        if not line.startswith("#")
    )

    _write_policy(workspace, block)
    run = _scan(workspace, runner_finding_nothing)

    licence = next(f for f in run.findings if f.rule == "valvur.licence.missing")
    assert licence.suppressed is not None


def test_valvur_suppress_writes_nothing(workspace, runner_finding_nothing):
    """F8.7 — printing is not writing."""
    from valvur.cli import main

    _scan(workspace, runner_finding_nothing)
    before = sorted(p.name for p in workspace.iterdir())

    main(["suppress", _licence_fingerprint(), str(workspace)])

    assert sorted(p.name for p in workspace.iterdir()) == before
    assert not (workspace / ".security-scan.toml").exists()
