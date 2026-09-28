"""R5.1: groups (F5.8, F7.5, F7.14).

The gate's scan reported 3,890 `generic-api-key` hits under one directory of
machine-written JSON, and eight distinct findings under them. A group makes the
flood one thing to look at: it drops no Finding and changes no identity, and a
flood of data files ranks below every distinct Finding. Measured on the corpus
before writing this: the most any rule repeats under one directory is 17
(`unpinned-uses` in terraform-aws-vpc's `.github/`), so a group starts at 25.
"""

from __future__ import annotations

from pathlib import Path

from valvur import grouping, pipeline
from valvur.adapters import DEFAULT_ADAPTERS
from valvur.findings import Finding

FLOOD = 3_890


def _ctx(workspace: Path) -> pipeline.Context:
    return pipeline.Context(
        workspace=workspace, profile="offline", network=False,
        declaring=[a.for_profile(network=False) for a in DEFAULT_ADAPTERS],
    )


def _hit(i: int) -> Finding:
    path = f"data/batch_{i // 1000:03}/{i:06}.json"
    return Finding(rule="generic-api-key", path=path, line=1,
                   title="Detected a Generic API Key", fingerprint=f"fp-flood-{i}",
                   severity="high", sources=("gitleaks",))


def _distinct() -> list[Finding]:
    """Eight findings of eight kinds, the weakest at `info`. The last is the same
    rule as the flood, in code: a real key that must not sink with the data."""
    def f(rule, path, severity, source):
        return Finding(rule=rule, path=path, line=3, title=f"{rule} in {path}",
                       fingerprint=f"fp-{rule}-{path}", severity=severity,
                       sources=(source,))
    return [
        f("aws-access-token", "config.py", "critical", "gitleaks"),
        f("CVE-2020-14343", "requirements.txt", "critical", "trivy"),
        f("valvur.python.subprocess-shell-true", "src/app/runner.py", "high", "opengrep"),
        f("excessive-permissions", ".github/workflows/ci.yml", "high", "zizmor"),
        f("CKV_AWS_20", "main.tf", "medium", "checkov"),
        f("unpinned-uses", ".github/workflows/ci.yml", "low", "zizmor"),
        f("valvur.python.dangerous-exec", "src/app/tools.py", "info", "opengrep"),
        f("generic-api-key", "src/app/settings.py", "high", "gitleaks"),
    ]


def test_a_flood_under_one_directory_is_one_group_ranked_below_eight_distinct(tmp_path):
    out = pipeline.run([_hit(i) for i in range(FLOOD)] + _distinct(), _ctx(tmp_path))

    [group] = grouping.describe(out.findings)
    flood = [f for f in out.findings if f.group == group.id]
    distinct = [f for f in out.findings if f.group is None]

    assert (group.rule, group.directory, group.count) == ("generic-api-key", "data/", FLOOD)
    assert group.machine_written
    assert "possibly machine-written data" in group.label
    assert len(flood) == FLOOD and len(distinct) == 8
    assert max(f.rank for f in distinct) < min(f.rank for f in flood), \
        "a distinct finding ranks below the flood"


def test_findings_json_keeps_every_finding_with_its_group_id_and_lists_the_group(tmp_path):
    """An agent queries `findings.json` one finding at a time; it must be able to
    ask for a group's members, and to learn what the group is without them."""
    import json

    from valvur import artifacts

    out = pipeline.run([_hit(i) for i in range(FLOOD)] + _distinct(), _ctx(tmp_path))
    data = json.loads(artifacts.findings_json(out.findings, status="findings",
                                              complete=True))

    [group] = data["groups"]
    members = [f for f in data["findings"] if f["group"] == group["id"]]
    assert len(data["findings"]) == FLOOD + 8
    assert len(members) == group["count"] == FLOOD
    assert group["machine_written"] is True
    assert group["directory"] == "data/" and group["files"] == FLOOD
    assert "possibly machine-written data" in group["label"]
    assert sum(f["group"] is None for f in data["findings"]) == 8
