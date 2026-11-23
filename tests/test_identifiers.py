"""R51.2: standard identifiers, mapped in one file with four levels of lookup (D82o, ADR-0037).

A Finding carried a CWE only when Opengrep reported one, and no OWASP category from any
Scanner. `src/valvur/data/identifiers.toml` maps a rule to its CWE and to OWASP's lists at
the editions read on a named day, looked up by the rule's ID, then a prefix, then its
Scanner, then its Finding Class. An entry may be `none`, and then says why. The word is
*mapped to*: a mapping is not a claim that valvur covers a category.
"""

from __future__ import annotations

import datetime
import re
import sys
from pathlib import Path

import pytest

from valvur import identifiers

REPO = Path(__file__).resolve().parents[1]
LISTS = '''
[list.top10]
name = "OWASP Top 10"
edition = "2025"
read = 2026-11-23
source = "https://top10.owasp.org/2025/"
categories = { "A01:2025" = "Broken Access Control", "A05:2025" = "Injection" }
'''
MADE = LISTS + '''
[[rule]]
id = "valvur.python.sql-injection"
cwe = ["CWE-89"]
owasp = ["A05:2025"]

[[prefix]]
prefix = "valvur.python."
cwe = []
owasp = ["A01:2025"]

[[scanner]]
scanner = "opengrep"
cwe = ["CWE-1"]
owasp = "none"
reason = "a rule of its own decides"

[[class]]
class = "static analysis"
cwe = []
owasp = "none"
reason = "nothing is known of it"
'''


def test_a_rules_own_entry_is_found():
    found = identifiers.read(MADE).of("opengrep", "valvur.python.sql-injection", "static analysis")

    assert (found.cwe, found.owasp) == (("CWE-89",), ("A05:2025",))


def test_with_none_of_its_own_its_prefixes_is():
    found = identifiers.read(MADE).of("opengrep", "valvur.python.new-rule", "static analysis")

    assert (found.cwe, found.owasp) == ((), ("A01:2025",))


def test_with_neither_its_scanners_is():
    found = identifiers.read(MADE).of("opengrep", "vendored_rule", "static analysis")

    assert (found.cwe, found.owasp, found.reason) == (("CWE-1",), (), "a rule of its own decides")


def test_with_none_of_the_three_its_classes_is():
    found = identifiers.read(MADE).of("somebody-else", "X1", "static analysis")

    assert (found.owasp, found.reason) == ((), "nothing is known of it")
    assert identifiers.read(MADE).of("somebody-else", "X1", "a class with no entry") == \
        identifiers.Identifiers((), (), "")


def test_the_longest_prefix_wins():
    table = identifiers.read(MADE + '''
[[prefix]]
prefix = "valvur."
cwe = []
owasp = ["A05:2025"]
''')

    assert table.of("opengrep", "valvur.python.x", "static analysis").owasp == ("A01:2025",)
    assert table.of("opengrep", "valvur.other.x", "static analysis").owasp == ("A05:2025",)


@pytest.mark.parametrize("broken, said", [
    (MADE.replace('reason = "a rule of its own decides"\n', ""), "says `none` and not why"),
    (MADE.replace('owasp = ["A05:2025"]', 'owasp = ["A99:2025"]', 1), "A99:2025 is in no list"),
    (MADE.replace('edition = "2025"\n', ""), "names no edition"),
    (MADE.replace("read = 2026-11-23\n", ""), "the day it was read"),
    (MADE.replace('cwe = ["CWE-89"]', 'cwe = ["89"]'), "`89` is not a CWE"),
])
def test_a_file_that_cannot_be_trusted_is_refused_when_it_is_read(broken, said):
    with pytest.raises(ValueError, match=re.escape(said)):
        identifiers.read(broken)


def test_each_list_in_the_shipped_file_names_its_edition_and_the_day_it_was_read():
    lists = identifiers.table().lists

    assert {(one.name, one.edition) for one in lists.values() if one.mapped} == {
        ("OWASP Top 10", "2025"), ("OWASP Top 10 for LLM Applications", "2025"),
        ("OWASP Top 10 for Agentic Applications", "2026")}
    assert all(one.read == datetime.date(2026, 11, 23) and one.source.startswith("https://")
               for one in lists.values())
    assert len(lists["top10"].categories) == len(lists["llm"].categories) == \
        len(lists["agentic"].categories) == 10
    [unmapped] = [one for one in lists.values() if not one.mapped]
    assert unmapped.edition == "1.1" and "T14" in unmapped.reason


def _written_by_valvur() -> set[str]:
    sys.path.insert(0, str(REPO / "scripts" / "eval"))
    import rule_precision

    rules = set(rule_precision.shipped(REPO / "rules"))
    source = "\n".join(p.read_text() for p in (REPO / "src" / "valvur").rglob("*.py"))
    checks = set(re.findall(r'"(valvur\.[a-z-]+\.[a-z0-9-]*[a-z0-9])"', source))
    return rules | checks


def test_every_rule_and_check_valvur_writes_or_vendors_has_an_entry_by_id():
    """A new rule with no entry would take its Scanner's, in silence. Each is named here."""
    entered = set(identifiers.table().rules)
    written = _written_by_valvur()

    assert len(written) >= 55
    assert sorted(written - entered) == []
    assert sorted(entered - written) == [], "an entry for a rule valvur does not have"


def test_a_rules_entry_carries_the_cwe_its_own_file_gives():
    """Two places name an Opengrep rule's CWE: its YAML, which Opengrep reports, and the
    table. They must agree, or SARIF and `findings.json` would say different things."""
    sys.path.insert(0, str(REPO / "scripts" / "eval"))
    import cwe

    table = identifiers.table()
    in_files = cwe.rule_cwes(REPO / "rules")

    assert in_files
    for rule, numbers in sorted(in_files.items()):
        if rule == "valvur.llm.model-call":
            continue        # a mark: its CWE in the file is Opengrep's requirement, not a claim
        assert {f"CWE-{n}" for n in numbers} == set(table.rules[rule].cwe), rule


def test_each_rule_mapped_by_cwe_sits_in_the_category_whose_list_holds_it():
    table = identifiers.table()

    for rule, entry in table.rules.items():
        top = [o for o in entry.owasp if o in table.lists["top10"].categories]
        by_cwe = {table.by_cwe[c] for c in entry.cwe if c in table.by_cwe}
        assert by_cwe <= set(top), (rule, by_cwe, top)


def test_a_dependency_finding_takes_the_cwe_its_advisory_gives():
    """R51.1 measured that both dependency Scanners carry one: 75 of 75 advisories in
    Trivy's golden, 88 of 149 in OSV-Scanner's. Read from the committed goldens."""
    from conftest import PINNED_VERSIONS, golden

    from valvur.adapters.osv import OsvAdapter
    from valvur.adapters.trivy import TrivyAdapter
    from valvur.runner import ScannerOutput

    trivy = TrivyAdapter().parse(ScannerOutput("trivy", PINNED_VERSIONS["trivy"],
                                                golden("trivy"), "", 0))
    osv = OsvAdapter().parse(ScannerOutput("osv-scanner", PINNED_VERSIONS["osv-scanner"],
                                           golden("osv-scanner"), "", 0))

    assert len(trivy) == 75 and all(f.cwe for f in trivy)
    assert all(re.fullmatch(r"CWE-\d+", c) for f in [*trivy, *osv] for c in f.cwe)
    assert (len(osv), sum(bool(f.cwe) for f in osv)) == (149, 88)
    by_rule = {f.rule: f.cwe for f in trivy}
    assert by_rule["CVE-2022-46175"] == ("CWE-1321",)


def test_an_advisorys_cwe_is_no_part_of_the_findings_identity():
    from conftest import PINNED_VERSIONS, golden

    from valvur import fingerprint
    from valvur.adapters.trivy import TrivyAdapter
    from valvur.runner import ScannerOutput

    found = TrivyAdapter().parse(ScannerOutput("trivy", PINNED_VERSIONS["trivy"],
                                                golden("trivy"), "", 0))

    for finding in found:
        dependency = finding.dependency
        assert finding.fingerprint == fingerprint.for_dependency_vuln(
            dependency.ecosystem, dependency.package, dependency.version, finding.rule)
