"""R13, found by the e2e golden: one flaw is one finding, whichever rules report it.

GitLab's string-built SQL rule and valvur's own `string-built-sql` both report an
f-string query. On the benchmark they are complementary: the vendored rule found five
`%`-formatted queries valvur's own never did, which is why it met D29's bar. But where
both report one line for one weakness, a user saw two findings under two rule ids,
never merged. The vendored finding now folds into valvur's: one finding, at the worse
of the two severities.
"""

from __future__ import annotations

from valvur.findings import Finding, merge


def _sql(rule: str, severity: str, line: int = 88, fingerprint: str = "") -> Finding:
    return Finding(rule=rule, path="llm_app.py", line=line, title=rule, severity=severity,
                   fingerprint=fingerprint or rule, sources=("opengrep",), cwe=("CWE-89",))


def test_a_vendored_finding_on_valvurs_line_for_the_same_weakness_folds_into_it():
    own = _sql("valvur.python.string-built-sql", "low")
    vendored = _sql("python_sql_rule-hardcoded-sql-expression", "medium")

    [one] = merge([own, vendored])

    assert one.rule == "valvur.python.string-built-sql"
    assert one.severity == "medium"


def test_another_line_or_another_weakness_stays_its_own_finding():
    own = _sql("valvur.python.string-built-sql", "low")
    elsewhere = _sql("python_sql_rule-hardcoded-sql-expression", "medium", line=90)
    other = Finding(rule="python_random_rule-random", path="llm_app.py", line=88,
                    title="random", severity="medium", fingerprint="r",
                    sources=("opengrep",), cwe=("CWE-338",))

    assert len(merge([own, elsewhere, other])) == 3
