"""R17.2: every requirement ID cited is defined (D43).

`scripts/check_traceability.py` checked one direction, that every requirement is cited,
and approximated the other through the ADRs. It never asked whether an ID that was cited
existed. N3.4 and N3.5 were cited by two decisions, two scripts, two test files and a
workflow for the whole R9 to R16 build, defined nowhere, and the check passed throughout
(found by R16.4). Requirement IDs are never renumbered, so an ID that resolves nowhere is
always a mistake, in the archives as much as in the code.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "check_traceability.py"


@pytest.fixture
def traceability(monkeypatch):
    spec = importlib.util.spec_from_file_location("check_traceability", SCRIPT)
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules["check_traceability"] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


#: IDs that exist nowhere, assembled here so this file does not itself cite them: the
#: repository's own check reads the tests too.
MISSING_A, MISSING_B = "F9" + ".99", "F7" + ".70"


def _repo(root: Path, files: dict[str, str]) -> Path:
    for name, text in {".kiro/specs/valvur/requirements.md":
                       "1. F1.1 — valvur SHALL scan.\n2. N2.3 — it SHALL be fast.\n",
                       **files}.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text)
    return root


def test_an_id_cited_and_defined_nowhere_is_named_with_where_it_is_first_cited(
        traceability, tmp_path):
    root = _repo(tmp_path, {
        "scripts/release.py": '"""Prepare a release (F1.1, N3.4)."""\n',
        "tests/test_release.py": "# N3.4 again, and N2.3\n",
    })

    assert traceability.undefined_citations(root) == {"N3.4": "scripts/release.py:1"}


def test_the_check_fails_on_one_and_says_which(traceability, tmp_path, monkeypatch,
                                               capsys):
    root = _repo(tmp_path, {".github/workflows/refresh.yml": "# D34 (N3.5)\n"})
    monkeypatch.setattr(traceability, "REPO", root)
    monkeypatch.setattr(traceability, "BASELINE", root / "docs" / "traceability-baseline.toml")

    assert traceability.main([]) == 1

    out = capsys.readouterr().out
    assert "N3.5" in out and ".github/workflows/refresh.yml:1" in out


def test_the_archives_and_the_requirements_get_no_exemption(traceability, tmp_path):
    """IDs are never renumbered, so the first version's IDs still resolve: an archive
    citing one that does not is as wrong as code doing so. An amendment inside
    `requirements.md` that names a missing ID is caught too."""
    root = _repo(tmp_path, {
        "docs/history/tasks-phases-0-30.md": f"- [x] **12.3** met F1.1 and {MISSING_A}\n",
    })
    (root / ".kiro/specs/valvur/requirements.md").write_text(
        f"1. F1.1 — valvur SHALL scan. *Amends {MISSING_B}.*\n")

    assert set(traceability.undefined_citations(root)) == {MISSING_A, MISSING_B}


def test_the_files_read_are_the_documents_the_code_the_tests_and_the_workflows(
        traceability):
    assert set(traceability.CITING) == {".kiro", "docs", "src", "scripts", "tests",
                                        ".github", "README.md", "CHANGELOG.md",
                                        "CONTRIBUTING.md", "CLAUDE.md", "SECURITY.md"}


def test_the_repository_passes_today(traceability):
    assert traceability.undefined_citations() == {}
