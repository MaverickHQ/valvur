"""R13.3, through the image: planted flaws reported by vendored rules.

The task named a SQL injection planted in JavaScript. No eligible rule covers it: the
JavaScript SQL injection rules GitLab carries translate njsscan, which is LGPL-3.0
(R13.1), so none was measured and none ships. This plants what the shipped rules do
report: an SQL string built by formatting, in Python, and an `eval` of an argument, in
JavaScript.
"""

from __future__ import annotations

import pytest


@pytest.mark.e2e
def test_planted_flaws_are_reported_by_the_vendored_rules(tmp_path):
    import json
    import os
    import subprocess
    import sys

    (tmp_path / "app.py").write_text(
        "def find(cursor, name):\n"
        "    cursor.execute(\"SELECT * FROM users WHERE name = '%s'\" % name)\n")
    (tmp_path / "run.js").write_text("function run(expression) {\n"
                                     "  return eval(expression);\n}\n")
    subprocess.run([sys.executable, "-c",
                    "from valvur.cli import main; raise SystemExit(main())",
                    "scan", str(tmp_path)], check=True, capture_output=True,
                   env={**os.environ})
    results = tmp_path / ".security-scan"
    findings = json.loads((results / "findings.json").read_text())["findings"]
    by_rule = {f["rule"]: f for f in findings}

    assert by_rule["python_sql_rule-hardcoded-sql-expression"]["path"] == "app.py"
    assert by_rule["javascript_eval_rule-eval-with-expression"]["path"] == "run.js"
    assert by_rule["python_sql_rule-hardcoded-sql-expression"]["sources"] == ["opengrep"]
    assert by_rule["python_sql_rule-hardcoded-sql-expression"]["cwe"] == ["CWE-89"]  # R13.4
    run = json.loads((results / "run.json").read_text())
    assert run["rule_sets"]["gitlab-sast-rules"].startswith("53bf5cf")
