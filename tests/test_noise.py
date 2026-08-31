"""Sub-phase 10.3b — false positives found by scanning a real project.

A synthetic fixture is generous: it has no vendored dependencies, no `.env`, and
nothing a developer cannot fix. A real 260k-line codebase produced 20 findings, of
which six were numpy's own test files inside a build directory and two were secrets
in a gitignored `.env`. None of that was visible until then.
"""

from valvur.exclusions import filter_findings, is_vendored
from valvur.findings import Exploit, Finding
from valvur.ranking import apply


def _f(rule, path="src/app.py", severity="medium", **kw):
    return Finding(rule=rule, path=path, line=1, title=rule, severity=severity, **kw)


# ------------------------------------------------------- vendored code

def test_findings_in_build_directories_are_excluded():
    """30% of a real scan's findings were numpy's test fixtures inside .aws-sam/build."""
    kept, dropped = filter_findings([
        _f("generic-api-key", ".aws-sam/build/CampaignFunction/numpy/random/tests/t.py"),
        _f("generic-api-key", "node_modules/pkg/index.js"),
        _f("generic-api-key", "src/app.py"),
    ])

    assert [f.path for f in kept] == ["src/app.py"]
    assert dropped == 2


def test_exclusion_matches_path_segments_not_substrings():
    """`src/distribution/` must survive containing the letters 'dist'."""
    assert is_vendored("app/dist/bundle.js")
    assert not is_vendored("src/distribution/report.py")
    assert not is_vendored("src/building/plan.py")


def test_the_number_excluded_is_reported_not_hidden():
    """Silently dropping findings is how a scanner conceals something. A user who
    vendored a genuinely vulnerable copy deserves to know we skipped it."""
    _, dropped = filter_findings([_f("x", "vendor/lib/a.py"), _f("y", "vendor/lib/b.py")])

    assert dropped == 2


# ------------------------------------------------------- gitignored secrets

def test_a_secret_in_a_gitignored_file_is_not_critical(tmp_path):
    """Every developer has a .env. Keeping credentials out of git is the CORRECT
    practice, and flagging it critical penalises the right behaviour."""
    import subprocess

    from valvur import gitcontext

    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    (tmp_path / ".gitignore").write_text(".env\n")
    (tmp_path / ".env").write_text("TOKEN=abc\n")

    findings = gitcontext.apply(tmp_path, [_f("telegram-bot-api-token", ".env", "critical")])

    assert findings[0].severity == "medium"
    assert "git is ignoring" in findings[0].title


def test_a_secret_in_a_tracked_file_stays_critical(tmp_path):
    """In the history, on every clone, and on the remote. That is an emergency."""
    import subprocess

    from valvur import gitcontext

    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    (tmp_path / "config.py").write_text("KEY = 'x'\n")
    subprocess.run(["git", "add", "config.py"], cwd=tmp_path, check=True)

    findings = gitcontext.apply(tmp_path, [_f("aws-access-token", "config.py", "critical")])

    assert findings[0].severity == "critical"


def test_a_project_without_git_is_left_alone(tmp_path):
    from valvur import gitcontext

    findings = gitcontext.apply(tmp_path, [_f("aws-access-token", ".env", "critical")])

    assert findings[0].severity == "critical"


# ------------------------------------------------------- the ranking floor

def test_a_noisy_class_cannot_outrank_a_real_finding():
    """The floor was silently discarded: min(exploit_tier, class_weight) preferred the
    no-exploit default of 2 over any class weight above it, so a licence-unknown
    finding weighted 5 still ranked at 2."""
    ranked = apply([
        _f("valvur.licence.dependency-unknown", "sbom.cdx.json"),
        _f("CKV_AWS_18", "template.yaml"),
        _f("valvur.dependency.nonexistent", "requirements.txt"),
    ])

    assert [f.rule for f in ranked] == [
        "valvur.dependency.nonexistent", "CKV_AWS_18",
        "valvur.licence.dependency-unknown",
    ]


def test_exploit_evidence_still_wins_where_it_exists():
    """The fix must not stop KEV outranking a class floor."""
    ranked = apply([
        _f("valvur.licence.missing", "."),
        _f("CVE-2023-4863", "requirements.txt", "high",
           exploit=Exploit(cve="CVE-2023-4863", kev=True)),
    ])

    assert ranked[0].rule == "CVE-2023-4863"
