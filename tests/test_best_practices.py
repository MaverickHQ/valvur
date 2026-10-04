"""R22.2: the OpenSSF Best Practices answers, prepared (D49b).

The form at bestpractices.dev needs the owner's account (§8), so the build prepares
`docs/BEST-PRACTICES.md`: every criterion of the *passing* level answered, each with
a link to its evidence, which the link check reads. The identifiers are the
criteria's own, from the badge project's `docs/criteria.md`, read on 2026-10-04.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PAGE = REPO / "docs" / "BEST-PRACTICES.md"

#: The 68 criteria of the passing level, in the badge's order.
CRITERIA = """
homepage_url description_good interact contribution contribution_requirements floss_license
floss_license_osi license_location documentation_basics documentation_interface
sites_https discussion english maintained repo_public repo_track repo_interim
repo_distributed version_unique version_semver version_tags release_notes
release_notes_vulns report_process report_tracker report_responses
enhancement_responses report_archive vulnerability_report_process
vulnerability_report_private vulnerability_report_response build build_common_tools
build_floss_tools test test_invocation test_most test_continuous_integration
test_policy tests_are_added tests_documented_added warnings warnings_fixed
warnings_strict know_secure_design know_common_errors crypto_published crypto_call
crypto_floss crypto_keylength crypto_working crypto_weaknesses crypto_pfs
crypto_password_storage crypto_random delivery_mitm delivery_unsigned
vulnerabilities_fixed_60_days vulnerabilities_critical_fixed no_leaked_credentials
static_analysis static_analysis_common_vulnerabilities static_analysis_fixed
static_analysis_often dynamic_analysis dynamic_analysis_unsafe
dynamic_analysis_enable_assertions dynamic_analysis_fixed
""".split()
ANSWER = re.compile(r"^- \*\*(\w+)\*\*: (Met|Unmet|N/A)[.,] (.+)$", re.M)


def _answers() -> dict[str, tuple[str, str]]:
    return {m[1]: (m[2], m[3]) for m in ANSWER.finditer(PAGE.read_text(encoding="utf-8"))}


def test_every_passing_criterion_is_answered_once():
    answers = _answers()
    listed = ANSWER.findall(PAGE.read_text(encoding="utf-8"))

    assert len(CRITERIA) == 68
    assert sorted(answers) == sorted(CRITERIA), (
        f"missing {sorted(set(CRITERIA) - set(answers))}, "
        f"unknown {sorted(set(answers) - set(CRITERIA))}")
    assert len(listed) == len(answers), "a criterion is answered twice"


def test_each_answer_links_its_evidence():
    for criterion, (_, why) in _answers().items():
        assert re.search(r"\]\((?:\.\./|https://|[\w.-]+\.md|[\w-]+/)", why), criterion


def test_the_link_check_reads_it():
    import subprocess

    tracked = subprocess.run(["git", "ls-files", "docs/BEST-PRACTICES.md"], cwd=REPO,
                             capture_output=True, text=True, check=True).stdout.split()

    assert tracked == ["docs/BEST-PRACTICES.md"], "untracked, so `test_links.py` skips it"


def test_the_owner_s_queue_holds_the_form():
    queue = (REPO / ".kiro" / "specs" / "valvur" / "tasks.md").read_text().split(
        "## 8. The owner queue", 1)[1]

    assert re.search(r"^\| the OpenSSF Best Practices form .*`docs/BEST-PRACTICES\.md`",
                     queue, re.M)
