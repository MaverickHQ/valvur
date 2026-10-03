"""Every other concept, once (D52b to e): the active predicate, the network grant,
the project file and the File Set per scan, and the container's flags.

The review of 2026-10-03 (§3.3) found each modelled more than once: whether a
Finding counts in six places, whether a tool may use the network in four, the
project file parsed at seven call sites of one scan, and two flag builders.
"""

from __future__ import annotations

import ast
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "src" / "valvur"

#: The six places that decided, each its own way, whether a Finding counts.
ACTIVE_SITES = ("api", "summary", "remediation", "gate", "reply", "grouping")


def _calls(module: str) -> set[str]:
    tree = ast.parse((SRC / f"{module}.py").read_text(encoding="utf-8"))
    return {ast.unparse(node.func) for node in ast.walk(tree) if isinstance(node, ast.Call)}


def test_one_predicate_decides_that_a_finding_counts():
    from valvur import verdict
    from valvur.findings import Finding

    def finding(**kw) -> Finding:
        return Finding(**{"rule": "valvur.test.rule", "severity": "high", "title": "t", "line": 1,
                          "path": "a.py", "fingerprint": "f" * 16, **kw})

    assert verdict.active(finding())
    assert not verdict.active(finding(suppressed="accepted until 2099"))
    assert not verdict.active(finding(rule="valvur.dependency.ecosystem-not-covered"))
    # The same answer for a record read back from findings.json.
    assert verdict.active({"rule": "valvur.test.rule", "suppressed": None})
    assert not verdict.active({"rule": "valvur.test.rule", "suppressed": "until 2099"})
    assert not verdict.active({"rule": "valvur.licence.unidentified"})


def test_the_six_sites_call_it_and_none_decides_for_itself():
    """`remediation` asks the other half, whether a Finding is a note: a note is not
    an action, and its proposals have always covered every other Finding."""
    for module in ACTIVE_SITES:
        assert {"verdict.active", "verdict.note"} & _calls(module), module
    deciding = []
    for path in sorted(SRC.rglob("*.py")):
        if path.name in ("verdict.py", "coverage.py"):
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Compare) and any(
                    isinstance(op, ast.In | ast.NotIn) for op in node.ops) and any(
                    ast.unparse(c).endswith("NOTE_RULES") for c in node.comparators):
                deciding.append(f"{path.relative_to(REPO)}:{node.lineno}")

    assert deciding == []


# ------------------------------------------------------------- the network grant

def _env_seen(tmp_path, monkeypatch, runtime_cls, *, inherited: bool) -> dict[str, str]:
    """What `VALVUR_NETWORK` each of two tools saw, one granted a network and one
    not, run by the engine through `runtime_cls`; with `inherited`, the variable is
    already in the host's environment, where a tool must not pick it up."""
    from valvur.engine_host import snapshot
    from valvur.invocation import Invocation

    if inherited:
        monkeypatch.setenv("VALVUR_NETWORK", "1")
    else:
        monkeypatch.delenv("VALVUR_NETWORK", raising=False)
    tmp_path = tmp_path / ("inherited" if inherited else "clean")
    ws = tmp_path / "ws"
    ws.mkdir(parents=True)
    (ws / "a.txt").write_text("a\n")
    say = ("sh", "-c", 'printf %s "${VALVUR_NETWORK:-unset}"')
    plan = [Invocation(tool="granted", version="0", argv=say, network=True),
            Invocation(tool="refused", version="0", argv=say, network=False)]
    scratch = tmp_path / "results"
    scratch.mkdir(parents=True)
    runtime_cls().run(plan, snapshot(ws, ["a.txt"]), scratch)
    return {t: (scratch / f"{t}.stdout").read_text() for t in ("granted", "refused")}


def test_the_engine_tells_each_granted_tool_and_no_other(tmp_path, monkeypatch):
    from valvur.engine_host import LocalRuntime

    for inherited in (False, True):
        assert _env_seen(tmp_path, monkeypatch, LocalRuntime, inherited=inherited) == {
            "granted": "1", "refused": "unset"}, inherited


def test_the_in_image_runtime_tells_them_too(tmp_path, monkeypatch):
    """D54(b): in the pipeline-step mode the runtime never set it, so on `full`
    dependency-reality behaved as offline there and skipped the registry."""
    from valvur import cache
    from valvur.engine_host import ImageRuntime

    monkeypatch.setattr(cache, "root", lambda: tmp_path / "cache")

    for inherited in (False, True):
        assert _env_seen(tmp_path, monkeypatch, ImageRuntime, inherited=inherited) == {
            "granted": "1", "refused": "unset"}, inherited


def test_the_container_is_not_told_the_engine_is():
    """One source: the plan's grant. The container's flags open or close the network;
    they no longer carry the variable for every tool inside."""
    from valvur import egress, profiles

    assert f"{egress.NETWORK_ENV}=1" not in egress.for_profile(profiles.FULL).container_flags()


def test_every_adapter_holds_the_grant_as_network():
    from valvur.adapters import DEFAULT_ADAPTERS

    for adapter in DEFAULT_ADAPTERS:
        assert not hasattr(adapter, "offline"), adapter.name
        granted = adapter.for_profile(network=True)
        assert getattr(granted, "network", True) is True or not getattr(
            granted, "uses_network", True), adapter.name
