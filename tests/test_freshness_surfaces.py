"""R11.6: every dataset's age, on every surface (D23, D24, F6.12).

R11.1 to R11.5 made each dataset's age its data's own: the database's build, the
index's and the malicious list's, KEV's release, EPSS's scoring, each OSV export's
publication. They said so only in `run.json`'s scattered fields, and never for
EPSS, the list or OSV. Now `run.json` holds them in one `data` block, `SUMMARY.md`
says them in one line, the MCP reply carries the block as fields, and the Score's
freshness gate reads it rather than three fields of its own choosing.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

from conftest import GoldenRunner, golden

from valvur import api, osv_offline, staleness
from valvur.adapters import TrivyAdapter

REPO = Path(__file__).resolve().parent.parent
DATASETS = ("database", "name_index", "malicious", "kev", "epss")


def _scan(workspace: Path):
    return api.scan(workspace, runner=GoldenRunner(trivy=golden("trivy")),
                    adapters=[TrivyAdapter()], profile="offline")


def test_run_json_holds_every_datasets_age_and_its_basis(workspace):
    _scan(workspace)

    data = json.loads((workspace / ".security-scan" / "run.json").read_text())["data"]

    assert set(DATASETS) <= set(data)
    for name in DATASETS:
        assert isinstance(data[name]["age_days"], int | float), name
    assert data["kev"]["basis"] == "released" and data["epss"]["basis"] == "scored"
    assert data["database"]["basis"] == data["name_index"]["basis"] == "built"
    assert data["osv"] == {}                       # no lockfile needed an OSV database


def test_an_osv_export_with_no_date_reads_fetched():
    path = osv_offline.path("PyPI")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"zip")

    ages = staleness.data_ages(provider=None, osv=["PyPI", "npm"])

    assert ages["osv"]["PyPI"]["basis"] == "fetched"
    assert ages["osv"]["npm"] == {"age_days": None, "basis": "absent"}


def test_summary_says_every_datasets_age_in_one_line(workspace):
    _scan(workspace)

    summary = (workspace / ".security-scan" / "SUMMARY.md").read_text()
    [line] = [line for line in summary.splitlines() if line.startswith("Data: ")]

    for said in ("vulnerability database", "package-name index", "malicious list",
                 "KEV", "EPSS"):
        assert said in line, said
    assert "(released" in line and "(scored" in line


def test_the_mcp_reply_carries_them_as_fields(workspace):
    from valvur import reply

    _scan(workspace)
    data = json.loads((workspace / ".security-scan" / "run.json").read_text())

    assert reply.fields(workspace)["data"] == data["data"]


def _eval():
    spec = importlib.util.spec_from_file_location("valvur_eval", REPO / "scripts" / "eval.py")
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(REPO / "scripts" / "eval"))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(REPO / "scripts" / "eval"))
    return module


def test_the_scores_freshness_gate_reads_them_from_run_json():
    evaluation = _eval()
    run_json = {"data": {"database": {"age_days": 1.0, "basis": "built"},
                         "name_index": {"age_days": 1.0, "basis": "built"},
                         "malicious": {"age_days": 2.5, "basis": "built"},
                         "kev": {"age_days": 0.5, "basis": "released"},
                         "epss": {"age_days": 3.2, "basis": "scored"},
                         "osv": {"PyPI": {"age_days": 1.0, "basis": "published"},
                                 "npm": {"age_days": 8.4, "basis": "published"}}}}

    ages = evaluation.data_ages(run_json)
    gates = evaluation.judge_gates({}, ages, ranking_first=True, tasks_text="")

    assert ages["osv_age_days"] == 8.4               # the oldest export decides
    reason = gates["freshness"]["reason"]
    for stale in ("malicious 2.5", "epss 3.2", "osv 8.4"):
        assert stale in reason, reason
    assert "kev" not in reason and "database" not in reason
