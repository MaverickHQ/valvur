"""R11.4: EPSS from FIRST's daily file (D25, F6.13, ADR-0027).

`full` sent the CVE identifiers found in a Workspace to FIRST's API, and `offline`,
the default, had no EPSS at all: it ranked a production CVE that attackers use beside
one nobody does. FIRST publishes every score in one file a day, 2.7 MB compressed
and 380,528 lines (measured 2026-09-29, from `epss.cyentia.com`, which redirects to
`epss.empiricalsecurity.com`). Fetched into the host cache by `valvur update` and by
a scan past two days, it is read on every Profile, and nothing of the Workspace
leaves for it.
"""

from __future__ import annotations

import gzip
import io
import json
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from conftest import GoldenRunner, golden
from test_first_run import (  # the fixture `host_cache`, reused
    _Runner,
    _scan,
    _write_db,
    _write_index,
    host_cache,  # noqa: F401
)

from valvur import cache, egress, epss, scan, settings, updating
from valvur.adapters import TrivyAdapter
from valvur.enrichment import LocalProvider
from valvur.findings import Dependency, Exploit, Finding

ROOT = Path(__file__).resolve().parent.parent


def _daily_file(scores: dict[str, float], *, scored: str = "2026-09-29T12:00:22Z") -> bytes:
    lines = [f"#model_version:v2026.06.15,score_date:{scored}", "cve,epss,percentile"]
    lines += [f"{cve},{score:.5f},0.50000" for cve, score in scores.items()]
    return gzip.compress(("\n".join(lines) + "\n").encode())


def _stamp(days_ago: float) -> str:
    return (datetime.now(UTC) - timedelta(days=days_ago)).isoformat().replace("+00:00", "Z")


class _Response(io.BytesIO):
    def __init__(self, body: bytes):
        super().__init__(body)
        self.headers: dict[str, str] = {}


@pytest.fixture
def served(monkeypatch):
    """FIRST's file, served to whatever `urlopen` is asked for, and the URLs asked."""
    asked: list[str] = []
    body = {"bytes": _daily_file({"CVE-2021-44228": 0.94358})}

    def urlopen(url, timeout=None):
        asked.append(getattr(url, "full_url", url))
        return _Response(body["bytes"])

    monkeypatch.setattr(urllib.request, "urlopen", urlopen)
    return asked, body


# ----------------------------------------------------- 1. update, and the mirror


def test_update_fetches_the_daily_file_into_the_host_cache(served):
    asked, _ = served
    said: list[str] = []

    assert updating.refresh_epss(said.append) is True

    assert asked == [epss.URL]
    assert epss.path() == cache.root() / "epss_scores.csv.gz"
    assert epss.scored() == "2026-09-29"
    assert any(line.startswith("EPSS refreshed: 1 score") for line in said), said


def test_epss_url_names_a_mirror(served, monkeypatch):
    asked, _ = served
    monkeypatch.setenv("VALVUR_EPSS_URL", "http://files.internal/epss_scores-current.csv.gz")

    assert updating.refresh_epss(lambda _: None) is True

    assert asked == ["http://files.internal/epss_scores-current.csv.gz"]
    assert settings.ENVIRONMENT["epss_url"] == "VALVUR_EPSS_URL"


def test_a_download_that_is_not_the_file_keeps_the_copy_in_use_and_says_so(served):
    _, body = served
    assert updating.refresh_epss(lambda _: None)
    body["bytes"] = b"<html>captive portal</html>"
    said: list[str] = []

    assert updating.refresh_epss(said.append) is False

    assert epss.scored() == "2026-09-29"
    assert any(line.startswith("EPSS refresh skipped") for line in said), said


def test_valvur_update_fetches_it_and_says_so(served, monkeypatch):
    from valvur.runner import ScannerOutput

    class Runner:
        def image_present(self):
            return True

        fetches = True                 # it fetches before a scan (24.1)

        def update_db(self):
            return ScannerOutput("trivy-db", "", "", "", 0)

    monkeypatch.setattr(updating, "refresh_kev", lambda say: True)
    monkeypatch.setattr(updating, "refresh_index", lambda say, **_: True)

    updated = updating.run(lambda _: None, Runner())

    assert "EPSS scores" in updated.fetched and updated.ok


def _steady(root: Path, fresh_kev: str) -> None:
    """A cache `valvur update` filled today: only EPSS is left for a test to age."""
    _write_db(root)
    _write_index(root, built_at=_stamp(0))
    (root / "kev.json").write_text(fresh_kev)


def test_a_scan_refreshes_scores_older_than_two_days_and_records_it(
        workspace, host_cache, served, _fresh_kev):  # noqa: F811
    root = host_cache
    _steady(root, _fresh_kev)
    (root / "epss_scores.csv.gz").write_bytes(_daily_file({}, scored=_stamp(3)))

    run, said = _scan(workspace, _Runner(root))

    assert any(line.startswith("refreshing EPSS (3 days old)") for line in said), said
    assert [f["what"] for f in run.fetched] == ["EPSS scores"]
    assert run.fetched[0]["source"] == epss.URL


def test_a_scan_with_fresh_scores_fetches_nothing(
        workspace, host_cache, served, _fresh_kev):  # noqa: F811
    asked, _ = served
    root = host_cache
    _steady(root, _fresh_kev)
    (root / "epss_scores.csv.gz").write_bytes(_daily_file({}, scored=_stamp(1)))

    run, _ = _scan(workspace, _Runner(root))

    assert asked == [] and run.fetched == []


# ------------------------------------------------ 2. read on every Profile


def _cve(cve: str, severity: str, scope: str = "production") -> Finding:
    return Finding(rule=cve, path="requirements.txt", line=0, title=cve, severity=severity,
                   exploit=Exploit(cve=cve),
                   dependency=Dependency(ecosystem="pip", package="p", version="1",
                                         scope=scope))


def test_a_findings_epss_comes_from_the_file(tmp_path):
    epss.path().write_bytes(_daily_file({"CVE-2021-44228": 0.94358,
                                         "CVE-2019-20477": 0.00041}))

    provider = LocalProvider()
    enriched = provider.enrich([_cve("CVE-2021-44228", "critical"),
                                _cve("CVE-2019-20477", "critical"),
                                _cve("CVE-2099-0001", "low")])

    assert [f.exploit.epss for f in enriched] == [0.94358, 0.00041, None]
    assert enriched[0].exploit.epss_date == "2026-09-29"
    assert provider.epss_scored == "2026-09-29"


def test_with_no_file_there_is_no_score_and_no_request(served):
    asked, _ = served
    epss.path().unlink()

    enriched = LocalProvider().enrich([_cve("CVE-2021-44228", "critical")])

    assert enriched[0].exploit.epss is None
    assert asked == []


def _order(workspace: Path, profile: str) -> list[str]:
    run = scan(workspace, runner=GoldenRunner(trivy=golden("trivy")),
               adapters=[TrivyAdapter()], profile=profile)
    return [f.rule for f in sorted(run.findings, key=lambda f: f.rank)]


def test_the_readme_ranking_example_ranks_the_same_on_offline_as_on_full(workspace):
    """The README's illustration: a medium that attackers use outranks the criticals
    nobody does. It held on `full` alone, where the API answered; now on both."""
    criticals = ["CVE-2022-37601", "CVE-2023-50447", "CVE-2019-20477",
                 "CVE-2020-14343", "CVE-2020-1747"]
    epss.path().write_bytes(_daily_file(
        {"CVE-2023-45803": 0.92, **dict.fromkeys(criticals, 0.0004)}))

    offline, full = _order(workspace, "offline"), _order(workspace, "full")

    assert offline == full
    assert offline.index("CVE-2023-45803") < min(offline.index(c) for c in criticals)
    run = json.loads((workspace / ".security-scan" / "run.json").read_text())
    assert run["enrichment"]["epss_scored"] == "2026-09-29"


# --------------------------------------------- 3. nothing to FIRST's API on full


def test_a_full_scan_asks_firsts_api_nothing(workspace, served):
    asked, _ = served

    _order(workspace, "full")

    assert asked == []


def test_the_disclosure_no_longer_names_first_or_cve_identifiers():
    sentence = egress.disclosure(used=True)

    assert "api.first.org" not in egress.FULL_HOSTS
    assert "FIRST" not in sentence and "CVE identifiers" not in sentence


# ------------------------------------ 4. the hosts, known where they are checked


def test_egress_and_both_proofs_know_the_files_hosts_and_not_the_api():
    assert egress.EPSS_HOSTS == ("epss.cyentia.com", "epss.empiricalsecurity.com")
    assert epss.URL.startswith(f"https://{egress.EPSS_HOSTS[0]}/")
    for script in ("egress.py", "verify-offline.py", "verify-mirror.py"):
        source = next(ROOT.glob(f"*/**/{script}")).read_text()
        assert "api.first.org" not in source, script
    offline = (ROOT / "scripts" / "verify-offline.py").read_text()
    assert all(host in offline for host in egress.EPSS_HOSTS)
    assert '"epss_url"' in (ROOT / "scripts" / "verify-mirror.py").read_text()


def test_verify_offline_lets_a_scan_fetch_public_data_and_nothing_else(monkeypatch):
    """Since R11.3 a scan refreshes data past two days, so the proof's poisoned scan
    failed on any machine not updated in two days. It now permits the hosts of the
    recorded fetches, the EPSS file's two among them, and refuses the rest."""
    import importlib.util
    import socket

    spec = importlib.util.spec_from_file_location(
        "verify_offline", ROOT / "scripts" / "verify-offline.py")
    script = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(script)
    for name in ("getaddrinfo", "create_connection"):
        monkeypatch.setattr(socket, name, getattr(socket, name))   # restored after
    for name in ("connect", "connect_ex"):
        monkeypatch.setattr(socket.socket, name, getattr(socket.socket, name))
    answer = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.7", 443))]
    monkeypatch.setitem(script._REAL, "getaddrinfo", lambda host, *a, **k: answer)
    monkeypatch.setitem(script._REAL, "connect", lambda sock, address: None)

    script._poison(script.PUBLIC_DATA)

    for host in egress.EPSS_HOSTS:
        assert socket.getaddrinfo(host, 443) == answer
    socket.socket.connect(None, ("192.0.2.7", 443))                # an address resolved
    with pytest.raises(script.Connected):
        socket.getaddrinfo("api.first.org", 443)
    with pytest.raises(script.Connected):
        socket.socket.connect(None, ("198.51.100.1", 443))         # one never resolved
    assert script.fetched_from == list(egress.EPSS_HOSTS)
