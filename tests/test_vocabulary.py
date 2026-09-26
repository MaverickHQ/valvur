"""The vocabulary is typed (28.4.1, A2).

Profile was a `str` with retired aliases resolved at runtime; severity and
finding status were `str`. 26.4.1 made the job state a `StrEnum` with a
transition table the code could not leave. The same for `Profile`, `Severity`
and `Status`: introduced at the boundaries — the CLI and MCP parse to the enum,
the adapters parse what a Scanner said — with the JSON output byte-identical,
which the SUMMARY, SARIF and findings goldens hold and this file spot-checks.
"""

from __future__ import annotations

import json

import pytest

from valvur import profiles
from valvur.findings import SEVERITIES, Finding, Severity, Status
from valvur.profiles import Profile


def test_severity_is_ordered_worst_first_and_parses_what_scanners_say():
    assert tuple(Severity) == SEVERITIES == ("critical", "high", "medium", "low", "info", "unknown")
    assert Severity.parse("HIGH") is Severity.HIGH
    assert Severity.parse(" Medium ") is Severity.MEDIUM
    assert Severity.parse("MODERATE") is Severity.UNKNOWN, "no guessing: a word we do not know"
    assert Severity.parse(None) is Severity.UNKNOWN and Severity.parse("") is Severity.UNKNOWN
    assert Severity.parse(Severity.LOW) is Severity.LOW


def test_a_finding_carries_the_enum_whatever_it_was_given():
    finding = Finding(rule="r", path="p", line=1, title="t", severity="high", status="persisting")

    assert finding.severity is Severity.HIGH and finding.status is Status.PERSISTING
    assert Finding(rule="r", path="p", line=1, title="t").severity is Severity.UNKNOWN
    assert Finding(rule="r", path="p", line=1, title="t").status is Status.NEW
    with pytest.raises(ValueError, match="fixed"):
        Finding(rule="r", path="p", line=1, title="t", status="fixed")


def test_the_three_statuses_are_the_ones_the_diff_produces():
    from valvur import state

    assert tuple(Status) == ("new", "persisting", "regressed")
    assert state.status_for("fp", {"fp": "t"}, set()) is Status.PERSISTING
    assert state.status_for("fp", {}, {"fp"}) is Status.REGRESSED
    assert state.status_for("fp", {}, set()) is Status.NEW


def test_profile_resolves_the_retired_names_and_refuses_the_rest():
    assert tuple(Profile) == ("offline", "full")
    assert profiles.resolve("quick") is Profile.OFFLINE
    assert profiles.resolve(" Deep ") is Profile.FULL
    assert profiles.resolve("standard") is Profile.FULL
    assert profiles.resolve(Profile.FULL) is Profile.FULL
    assert profiles.DEFAULT is Profile.OFFLINE
    with pytest.raises(ValueError, match="offline, full"):
        profiles.resolve("bogus")
    with pytest.raises(ValueError):
        profiles.resolve("")


def test_the_json_is_byte_identical_to_the_strings_it_replaced():
    assert json.dumps({"severity": Severity.HIGH, "status": Status.NEW, "profile": Profile.FULL}) \
        == '{"severity": "high", "status": "new", "profile": "full"}'
    assert f"{Severity.CRITICAL}" == "critical" and str(Profile.OFFLINE) == "offline"
    assert Severity.HIGH == "high" and "high" in {Severity.HIGH}


def test_the_boundaries_parse_to_the_enum():
    """The CLI's choices and the MCP schema's enum come from the type, not from
    a second list — and the `tools/list` snapshot holds the wire form still."""
    from valvur.mcp.tools import registry

    scan = next(t for t in registry() if t.name == "scan")
    assert scan.schema["properties"]["profile"]["enum"] == [p.value for p in Profile]
    from valvur import cli

    parser = cli.build_parser() if hasattr(cli, "build_parser") else None
    if parser is not None:
        args = parser.parse_args(["scan", ".", "--profile", "deep"])
        assert profiles.resolve(args.profile) is Profile.FULL
