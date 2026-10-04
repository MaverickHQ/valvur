"""R38.2: every Scanner runs with the project's own ignores off (D77a).

A comment or an ignore file in the scanned project hid five of the seven findings
R38.1 planted, and nothing in valvur's report said so. Each Scanner now runs with
the switch its pinned version has for that, measured from its own help: Opengrep
`--disable-nosem`, Gitleaks `--ignore-gitleaks-allow`, an empty ignore path and a
configuration valvur writes, Trivy and OSV-Scanner an empty ignore file. Checkov has
no switch, so it runs without `--quiet` and its record of what it skipped is read.
"""

from __future__ import annotations

import tomllib

import pytest

from valvur import cache


def _env(invocation) -> dict[str, str]:
    return dict(invocation.env)


def test_opengrep_reports_lines_a_nosem_comment_marks():
    from valvur.adapters import OpengrepAdapter

    assert "--disable-nosem" in OpengrepAdapter().command(None).argv


@pytest.mark.parametrize("history", [False, True])
def test_gitleaks_reads_no_allow_comment_no_ignore_file_and_no_allowlist(tmp_path, history):
    from valvur.adapters import GitleaksAdapter

    (tmp_path / ".gitleaks.toml").write_text(
        '[extend]\nuseDefault = true\n\n'
        '[[rules]]\nid = "acme-token"\nregex = \'\'\'acme_[0-9a-f]{32}\'\'\'\n'
        '[rules.allowlist]\nregexes = [\'\'\'acme_0{32}\'\'\']\n\n'
        "[allowlist]\npaths = ['''vendored/''']\n\n"
        "[[allowlists]]\nstopwords = ['''example''']\n")
    adapter = GitleaksAdapter()
    invocation = (adapter.history_command(project_config=True, workspace=tmp_path) if history
                  else adapter.command(tmp_path))

    argv = list(invocation.argv)
    assert "--ignore-gitleaks-allow" in argv
    assert argv[argv.index("--gitleaks-ignore-path") + 1] == "/dev/null"
    assert "--config" not in argv, "the project's file, allowlists and all"
    written = tomllib.loads(_env(invocation)["GITLEAKS_CONFIG_TOML"])
    assert written["extend"] == {"useDefault": True}
    assert [rule["id"] for rule in written["rules"]] == ["acme-token"], "its own rules stay"
    assert "allowlist" not in written and "allowlists" not in written
    assert "allowlist" not in written["rules"][0]


def test_gitleaks_without_a_project_file_runs_its_defaults(tmp_path):
    from valvur.adapters import GitleaksAdapter

    written = tomllib.loads(_env(GitleaksAdapter().command(tmp_path))["GITLEAKS_CONFIG_TOML"])

    assert written == {"extend": {"useDefault": True}}


def test_trivy_reads_no_trivyignore(tmp_path, monkeypatch):
    from valvur.adapters import TrivyAdapter

    monkeypatch.setattr(cache, "db_present", lambda: True)
    argv = list(TrivyAdapter().command(tmp_path).argv)

    assert argv[argv.index("--ignorefile") + 1] == "/dev/null"


@pytest.mark.parametrize("network", [False, True])
def test_osv_scanner_reads_no_project_configuration(tmp_path, network):
    from valvur.adapters import OsvAdapter

    argv = list(OsvAdapter().for_profile(network=network).command(tmp_path).argv)

    assert argv[argv.index("--config") + 1] == "/dev/null"


def test_checkov_reports_what_it_skipped(tmp_path):
    """Checkov has no switch: its inline skips are matched before a check runs. Its
    JSON lists each one only without `--quiet`."""
    from valvur.adapters import CheckovAdapter

    assert "--quiet" not in CheckovAdapter().command(tmp_path).argv


def test_a_result_made_with_other_arguments_is_never_reused():
    """Found by R38's own measurement: the reuse key held the Scanner, its version,
    the Profile, the dependency files and the data, but not the arguments. So
    OSV-Scanner's result from before `--config /dev/null`, made with the project's
    ignore honoured, was reused after it, and the ignored advisory stayed hidden."""
    from valvur import reuse

    base = {"tool": "osv-scanner", "version": "2.6.0", "profile": "offline",
            "inputs": {"requirements.txt": "0" * 64}, "data": "PyPI 2026-10-04"}
    before = ("osv-scanner", "scan", "source", "/workspace")
    after = ("osv-scanner", "scan", "source", "--config", "/dev/null", "/workspace")

    assert reuse.key(**base, argv=before) != reuse.key(**base, argv=after)
    assert reuse.key(**base, argv=after) == reuse.key(**base, argv=after)
