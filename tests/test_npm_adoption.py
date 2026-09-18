"""Task 23.5.4 — npm adoption on `full`: the slopsquat signal design.md specified.

F3.3 says *first published recently AND low adoption*. The age half has existed
since 19.D.1; the adoption half was stated impossible because PyPI publishes no
download counts without a third party (F1.7, ADR-0008). npm does:
`api.npmjs.org/downloads/point/last-month/<name>` is public and unauthenticated. So
for npm the signal is now both halves — asked only about names already found to be
under 90 days old, so nothing new leaves the machine — and for PyPI it stays age
only, and says so.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import valvur.checks.dependency_reality as mod
from valvur.checks.dependency_reality import DependencyRealityCheck, RegistryUnreachable

RULE = "valvur.dependency.newly-registered"


def _npm_meta(days: int) -> dict:
    return {"time": {"created": (datetime.now(UTC) - timedelta(days=days)).isoformat()}}


def _pypi_meta(days: int) -> dict:
    stamp = (datetime.now(UTC) - timedelta(days=days)).isoformat()
    return {"releases": {"1.0": [{"upload_time_iso_8601": stamp}]}}


def _repo(root: Path, files: dict[str, str]) -> Path:
    for name, body in files.items():
        (root / name).write_text(body)
    return root


@pytest.fixture
def npm_world(tmp_path, name_index, network_granted, monkeypatch):
    """One new npm package, one old one, one new PyPI package; a registry that
    answers ages, and a downloads endpoint whose answers and questions are ours."""
    name_index(npm=["fresh-pkg", "old-pkg", "@scope/fresh"], pip=["fresh-lib"])
    ages = {"fresh-pkg": 5, "old-pkg": 900, "@scope/fresh": 12, "fresh-lib": 3}
    asked: list[str] = []
    counts: dict[str, int | Exception] = {}

    def lookup(ecosystem, name):
        return _pypi_meta(ages[name]) if ecosystem == "pip" else _npm_meta(ages[name])

    def downloads(name):
        asked.append(name)
        answer = counts.get(name, 0)
        if isinstance(answer, Exception):
            raise answer
        return answer

    monkeypatch.setattr(mod, "_lookup", lookup)
    monkeypatch.setattr(mod, "_downloads", downloads)
    ws = _repo(tmp_path, {
        "package.json": json.dumps({"dependencies": {
            "fresh-pkg": "^1", "old-pkg": "^2", "@scope/fresh": "^0.1"}}),
        "requirements.txt": "fresh-lib\n",
    })
    return ws, asked, counts


def _by_name(findings):
    return {f["title"].split("'")[1]: f for f in findings}


# ------------------------------------------------------------------ the signal

def test_a_new_unadopted_npm_package_is_high_with_both_numbers(npm_world):
    ws, _, counts = npm_world
    counts["fresh-pkg"] = 12

    found = _by_name(DependencyRealityCheck().run(ws))

    fresh = found["fresh-pkg"]
    assert fresh["rule"] == RULE and fresh["severity"] == "high"
    assert "5 day(s) ago" in fresh["title"] and "12 downloads last month" in fresh["title"]
    assert "slopsquat" in fresh["evidence"].lower()


def test_a_new_but_adopted_npm_package_is_low_and_says_so(npm_world):
    """F3.3's signal is new AND unadopted. A new package with real adoption is a new
    package — reported, because the age is not nothing, but ranked below the
    signal, with the number that ranks it there."""
    ws, _, counts = npm_world
    counts["fresh-pkg"] = 48_000

    fresh = _by_name(DependencyRealityCheck().run(ws))["fresh-pkg"]

    assert fresh["severity"] == "low"
    assert "48,000 downloads last month" in fresh["title"]
    assert "adopt" in fresh["evidence"].lower()


def test_the_threshold_is_design_dot_md_s(npm_world):
    """`downloads < 1000/mo` — the row in design.md's ranking table."""
    ws, _, counts = npm_world
    assert mod.NPM_UNADOPTED_DOWNLOADS == 1000

    counts["fresh-pkg"] = 999
    assert _by_name(DependencyRealityCheck().run(ws))["fresh-pkg"]["severity"] == "high"
    counts["fresh-pkg"] = 1000
    assert _by_name(DependencyRealityCheck().run(ws))["fresh-pkg"]["severity"] == "low"


def test_no_download_statistics_at_all_is_zero_adoption(npm_world, monkeypatch):
    """The downloads API answers 404 for a package too new to have statistics.
    That is the least-adopted a package can be."""
    ws, _, _ = npm_world
    monkeypatch.setattr(mod, "_downloads", lambda name: 0)

    fresh = _by_name(DependencyRealityCheck().run(ws))["fresh-pkg"]

    assert fresh["severity"] == "high" and "0 downloads" in fresh["title"]


def test_a_downloads_api_that_cannot_be_reached_leaves_the_age_finding_at_medium(npm_world):
    """The age half stands on its own, as it did before; the evidence says which
    half is missing rather than guessing at adoption."""
    ws, _, counts = npm_world
    counts["fresh-pkg"] = RegistryUnreachable("timed out")

    fresh = _by_name(DependencyRealityCheck().run(ws))["fresh-pkg"]

    assert fresh["severity"] == "medium"
    assert "5 day(s) ago" in fresh["title"] and "downloads" not in fresh["title"]
    assert "could not be checked" in fresh["evidence"]


def test_pypi_stays_age_only_and_the_evidence_says_why(npm_world):
    ws, _, _ = npm_world

    lib = _by_name(DependencyRealityCheck().run(ws))["fresh-lib"]

    assert lib["severity"] == "medium"
    assert "downloads" not in lib["title"]
    assert "PyPI" in lib["evidence"] and "third party" in lib["evidence"]


# ------------------------------------------------- what leaves the machine

def test_downloads_are_asked_only_about_new_npm_names(npm_world):
    """Nothing new leaves the machine: the names sent to api.npmjs.org are exactly
    the npm names the registry has already dated under 90 days. Not the old one,
    not the Python one."""
    ws, asked, _ = npm_world

    DependencyRealityCheck().run(ws)

    assert sorted(asked) == ["@scope/fresh", "fresh-pkg"]


def test_downloads_are_not_asked_without_a_network(npm_world, monkeypatch):
    ws, asked, _ = npm_world
    monkeypatch.delenv("VALVUR_NETWORK", raising=False)

    found = DependencyRealityCheck().run(ws)

    assert asked == [] and found == []


def test_the_downloads_url_is_https_and_a_scoped_name_keeps_its_slash():
    """Measured: `api.npmjs.org/downloads/point/last-month/@types/node` answers with
    the slash unencoded, like the registry itself (19.D.1's finding)."""
    assert mod._downloads_url("@scope/fresh") == (
        "https://api.npmjs.org/downloads/point/last-month/@scope/fresh")
    assert mod._downloads_url("left-pad").startswith("https://api.npmjs.org/")


def test_the_downloads_answer_is_read_from_the_documented_field(monkeypatch):
    seen = {}

    def fetch(url, *, as_json=True):
        seen["url"] = url
        return {"downloads": 6360903, "start": "2026-08-18", "end": "2026-09-16",
                "package": "left-pad"}

    monkeypatch.setattr(mod, "_fetch", fetch)

    assert mod._downloads("left-pad") == 6360903
    assert seen["url"] == "https://api.npmjs.org/downloads/point/last-month/left-pad"


def test_a_404_from_the_downloads_api_is_zero_and_unreachable_is_raised(monkeypatch):
    monkeypatch.setattr(mod, "_fetch", lambda url, *, as_json=True: None)
    assert mod._downloads("brand-new") == 0

    def unreachable(url, *, as_json=True):
        raise RegistryUnreachable("503")

    monkeypatch.setattr(mod, "_fetch", unreachable)
    with pytest.raises(RegistryUnreachable):
        mod._downloads("brand-new")


def test_the_disclosure_names_the_downloads_api_and_every_index_registry(tmp_path):
    """The sentence in run.json IS the non-exfiltration claim (§3). A destination
    added without amending it makes the claim false. Ruby, PHP and Rust joined the
    index in 23.2.2-3 and their registries are asked for age on `full`; the
    sentence had not been amended for them either — found here."""
    from valvur import results
    from valvur.api import ScanRun

    results.write(tmp_path, ScanRun(findings=[], network_used=True))
    disclosed = json.loads(
        (tmp_path / ".security-scan" / "run.json").read_text())["network"]["what_left_the_machine"]

    for destination in ("api.npmjs.org", "RubyGems", "Packagist", "crates.io"):
        assert destination in disclosed, f"{destination} is reached but not disclosed"
    assert "under 90 days" in disclosed


def test_the_coverage_declaration_says_which_half_each_ecosystem_has(tmp_path, network_granted):
    declared = DependencyRealityCheck().coverage(
        _repo(tmp_path, {"package.json": "{}", "requirements.txt": "x\n"}), network=True)

    inspects, ignores = " ".join(declared.inspects), " ".join(declared.ignores)
    assert "adoption" in inspects and "api.npmjs.org" in inspects, "it is read, so it is `inspects`"
    assert "PyPI" in ignores and "age only" in ignores, "not read, so it is `ignores`"
