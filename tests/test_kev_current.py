"""R28.6: KEV is current while it is CISA's newest (D76).

CISA releases the catalog on working days, so from Sunday afternoon Friday's catalog is
past D24's two days although nothing newer exists. R26's exit measured what followed:
the Score's freshness gate failed every weekend, a release's `verify` with it, and a
scan refetched the same catalog every time. Now a refresh asks conditionally, and a
check within two days that finds no newer catalog makes KEV current. Its age is still
the catalog's own (ADR-0027), and every surface says when it is CISA's newest.

The server here stands in for CISA's host: it serves one catalog, with a
`Last-Modified`, and answers `If-Modified-Since` with 304, as a static host does.
"""

from __future__ import annotations

import http.server
import json
import threading
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime, parsedate_to_datetime

import pytest

from valvur import cache, datasets, enrichment, staleness, summary, updating
from valvur.api import ScanRun

THREE_DAYS_AGO = datetime.now(UTC) - timedelta(days=3)


def _catalog(released: datetime) -> dict:
    return {"catalogVersion": released.strftime("%Y.%m.%d"),
            "dateReleased": released.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "vulnerabilities": [{"cveID": "CVE-2026-0001", "dateAdded": "2026-09-01",
                                 "knownRansomwareCampaignUse": "Unknown"}]}


class _Cisa:
    """A static host: one catalog, its `Last-Modified`, and 304 when not newer. With
    `conditional=False` it ignores `If-Modified-Since`, as some mirrors do."""

    def __init__(self, released: datetime, *, conditional: bool = True) -> None:
        self.released, self.conditional = released, conditional
        self.requests: list[dict[str, str]] = []
        cisa = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                cisa.requests.append(dict(self.headers))
                since = self.headers.get("If-Modified-Since")
                if cisa.conditional and since and \
                        parsedate_to_datetime(since) >= cisa.released.replace(microsecond=0):
                    self.send_response(304)
                    self.end_headers()
                    return
                body = json.dumps(_catalog(cisa.released)).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Last-Modified", format_datetime(cisa.released, usegmt=True))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/kev.json"

    def close(self) -> None:
        """Gone: its port refuses, as a host that is down does."""
        if self.server.socket.fileno() != -1:
            self.server.shutdown()
            self.server.server_close()


@pytest.fixture
def cisa(tmp_path, monkeypatch):
    """The stand-in host on loopback, which the unit suite allows openers and, here,
    `urlopen` to reach (conftest's rule): nothing else is reachable."""
    import urllib.error
    import urllib.parse
    import urllib.request

    import conftest

    def loopback_only(request, *args, **kwargs):
        url = getattr(request, "full_url", request)
        if urllib.parse.urlsplit(url).hostname != "127.0.0.1":
            raise urllib.error.URLError(f"unit tests do not open sockets (tried {url})")
        return conftest.REAL_URLOPEN(request, *args, **kwargs)

    monkeypatch.setattr(urllib.request, "urlopen", loopback_only)
    monkeypatch.setenv("VALVUR_CACHE", str(tmp_path / "cache"))
    monkeypatch.setattr(enrichment, "_BUNDLED", tmp_path / "no-bundle.json")
    server = _Cisa(THREE_DAYS_AGO)
    monkeypatch.setenv("VALVUR_KEV_URL", server.url)
    yield server
    server.close()


def _cached() -> dict:
    return json.loads((cache.root() / "kev.json").read_text())


def _age_the_check(days: float) -> None:
    data = _cached()
    data["checked"] = (datetime.now(UTC) - timedelta(days=days)).isoformat()
    (cache.root() / "kev.json").write_text(json.dumps(data))


def test_a_check_that_finds_no_newer_catalog_makes_kev_current(cisa):
    assert updating.refresh_kev(lambda _: None)
    _age_the_check(2.5)                   # the last check was before the weekend
    assert datasets.KEV.due(datasets.KEV.age()), "three days old, checked 2.5 days ago"

    said = []
    assert updating.refresh_kev(said.append)

    assert cisa.requests[-1].get("If-Modified-Since") == format_datetime(
        THREE_DAYS_AGO.replace(microsecond=0), usegmt=True), "asked conditionally"
    assert "CISA's newest" in said[-1]
    age = datasets.KEV.age()
    assert age == pytest.approx(3, abs=0.01), "its age is still the catalog's own"
    assert not datasets.KEV.due(age)
    assert datasets.KEV.newest()


def test_a_host_that_ignores_the_condition_is_compared_by_its_release_date(cisa):
    cisa.conditional = False
    updating.refresh_kev(lambda _: None)
    _age_the_check(2.5)

    said = []
    assert updating.refresh_kev(said.append)

    assert "CISA's newest" in said[-1]
    assert datasets.KEV.newest() and not datasets.KEV.due(datasets.KEV.age())


def test_a_newer_catalog_is_fetched_as_before(cisa):
    updating.refresh_kev(lambda _: None)
    cisa.released = datetime.now(UTC) - timedelta(hours=2)

    said = []
    assert updating.refresh_kev(said.append)

    assert said[-1].startswith("KEV refreshed")
    assert datasets.KEV.age() == pytest.approx(2 / 24, abs=0.01)


def test_a_failed_check_changes_nothing_and_two_days_without_one_is_stale(cisa):
    updating.refresh_kev(lambda _: None)
    _age_the_check(1.0)
    before = _cached()
    cisa.close()                                       # CISA unreachable

    assert not updating.refresh_kev(lambda _: None)
    assert _cached() == before
    assert datasets.KEV.newest(), "checked a day ago: still current"

    _age_the_check(2.5)
    assert not datasets.KEV.newest()
    assert datasets.KEV.due(datasets.KEV.age()), "as before D76"


def test_with_fetch_never_nothing_is_asked_and_nothing_changes(cisa, monkeypatch):
    from valvur import fetching

    updating.refresh_kev(lambda _: None)
    _age_the_check(2.5)
    asked = len(cisa.requests)
    monkeypatch.setenv("VALVUR_FETCH", "never")

    class Runner:
        fetches = True

    assert fetching.ensure_data(Runner(), None) == ([], {})
    assert len(cisa.requests) == asked
    assert not datasets.KEV.newest() and datasets.KEV.due(datasets.KEV.age())


def test_every_surface_shows_the_catalog_s_date_and_says_it_is_cisa_s_newest(cisa):
    from valvur import doctor

    updating.refresh_kev(lambda _: None)

    kev = staleness.data_ages()["kev"]
    assert kev["basis"] == "released" and kev["age_days"] == pytest.approx(3, abs=0.01)
    assert kev["newest"] is True and kev["checked_days"] == pytest.approx(0, abs=0.01)

    line = summary._data_line({"kev": kev})
    assert "KEV 3.0 days (released; CISA's newest)" in line

    check = doctor._check_kev()
    assert THREE_DAYS_AGO.strftime("%Y-%m-%d") in check.detail
    assert "CISA's newest" in check.detail

    text = summary.render(ScanRun(data_ages={"kev": kev}))
    assert "CISA's newest" in text


def test_a_kev_not_checked_lately_says_nothing_of_newest(cisa):
    updating.refresh_kev(lambda _: None)
    _age_the_check(2.5)

    kev = staleness.data_ages()["kev"]

    assert kev["newest"] is False
    assert "newest" not in summary._data_line({"kev": kev})


def test_the_freshness_gate_passes_on_a_weekend(cisa):
    """Against a catalog three days old and unchanged: D76's exit."""
    import importlib.util
    from pathlib import Path

    spec = importlib.util.spec_from_file_location(
        "eval_script", Path(__file__).resolve().parent.parent / "scripts" / "eval.py")
    evaluation = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(evaluation)

    updating.refresh_kev(lambda _: None)
    run_json = {"data": staleness.data_ages()}
    data = evaluation.data_ages(run_json)
    assert data["kev_age_days"] > 2

    gates = evaluation.judge_gates({}, data, ranking_first=True, tasks_text="")
    assert gates["freshness"]["ok"], gates["freshness"]

    _age_the_check(2.5)
    data = evaluation.data_ages({"data": staleness.data_ages()})
    gates = evaluation.judge_gates({}, data, ranking_first=True, tasks_text="")
    assert not gates["freshness"]["ok"] and "kev" in gates["freshness"]["reason"]
