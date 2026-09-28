"""R5.5: repository hygiene is reported, not ranked (D13).

The owner's audit of the lab found no `SECURITY.md` and no Dependabot, and valvur
said nothing: OpenSSF Scorecard checks both locally, and the review asked whether
they are in scope. D13 says yes, as facts about the repository: a Hygiene section
in `SUMMARY.md` and `run.json`, never a Finding, never the Status. The third fact,
workflows with no top-level `permissions:`, is what no Finding says: they run with
the repository's default token, write-all on repositories created before February
2023, a setting nothing offline can read. An explicit `write-all` stays zizmor's
ranked Finding (R4.2).
"""

from __future__ import annotations

import json
from pathlib import Path

from valvur import api
from valvur.engine_host import LocalRuntime

FAKE_TOOLS = Path(__file__).parent / "fixtures" / "fake-tools"
WORKFLOW = ("name: ci\non: push\njobs:\n  test:\n    runs-on: ubuntu-24.04\n"
            "    steps:\n      - run: echo test\n")


def _ws(root: Path, files: dict[str, str]) -> Path:
    for name, body in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    return root


def _scan(tmp_path, monkeypatch, files):
    from valvur import cache
    from valvur.adapters import GitleaksAdapter

    monkeypatch.setattr(cache, "root", lambda: tmp_path / "cache")
    ws = _ws(tmp_path / "ws", files)
    run = api.scan(ws, runner=LocalRuntime(FAKE_TOOLS), adapters=[GitleaksAdapter()])
    return run, ws / ".security-scan"


def test_the_three_facts_are_in_the_hygiene_section_and_run_json(tmp_path, monkeypatch):
    _, results = _scan(tmp_path, monkeypatch, {
        "app.py": "print('hi')\n",
        ".github/workflows/ci.yml": WORKFLOW,
        ".github/workflows/lint.yml": "permissions:\n  contents: read\n" + WORKFLOW,
    })

    summary = (results / "SUMMARY.md").read_text()
    hygiene = summary.split("## Hygiene", 1)[1].split("\n## ", 1)[0]
    assert "`SECURITY.md`" in hygiene
    assert "dependency-update" in hygiene
    assert "1 of 2 workflows" in hygiene and "`.github/workflows/ci.yml`" in hygiene

    record = json.loads((results / "run.json").read_text())["hygiene"]
    assert record == {"security_policy": None, "dependency_updates": None,
                      "workflows": 2,
                      "default_permissions": [".github/workflows/ci.yml"]}


def test_none_of_them_changes_the_status(tmp_path, monkeypatch):
    """All three missing, and nothing found: the verdict is about the code (§7)."""
    run, results = _scan(tmp_path, monkeypatch, {
        "app.py": "print('hi')\n", ".github/workflows/ci.yml": WORKFLOW})

    assert run.hygiene["security_policy"] is None and run.hygiene["default_permissions"]
    assert run.findings == []
    assert run.status == "clean"
    assert json.loads((results / "run.json").read_text())["status"] == "clean"


def test_a_repository_with_all_three_has_no_hygiene_section(tmp_path, monkeypatch):
    _, results = _scan(tmp_path, monkeypatch, {
        "app.py": "print('hi')\n", ".github/SECURITY.md": "Report to security@example.invalid\n",
        ".github/dependabot.yml": "version: 2\n",
        ".github/workflows/ci.yml": "permissions: {}\n" + WORKFLOW})

    assert "## Hygiene" not in (results / "SUMMARY.md").read_text()
