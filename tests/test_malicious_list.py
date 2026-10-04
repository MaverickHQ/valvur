"""R11.5: the malicious list, published daily (D26, F3.14, ADR-0027).

A package published to attack whoever installs it runs at install, and OSV's offline
database, refreshed past seven days, could be a week behind the attack. ossf's
malicious-packages repository (Apache-2.0) records each one as an OSV record:
238,545 of them on 2026-09-29, 93% npm. `index.yml` builds from it, daily, a sorted
list per ecosystem the index covers, and publishes it beside the index. The
dependency-reality Check reads it offline, by bisection, and reports a declared or
locked package in it as critical, one finding with OSV-Scanner's for the same package.

Measured first: the repository's tarball is 46 MB and arrives in 1.8 s; OSV's exports
for the same ecosystems are 296 MB. The tarball is read as a stream, since unpacking
its 238,545 files took 72 s on this Mac.
"""

from __future__ import annotations

import json
import re
import tarfile
from pathlib import Path

import pytest
from conftest import GoldenRunner
from fixture_copy import copy_fixture
from test_first_run import host_cache  # noqa: F401 — the fixture, registered by import

from valvur import api, cache, name_index, updating
from valvur.checks.dependency_reality import DependencyRealityCheck
from valvur.name_index import malicious

REPO = Path(__file__).resolve().parent.parent
FIXTURE = Path(__file__).parent / "fixtures" / "malicious-packages"


def _build(names: Path, source: Path | str = FIXTURE) -> None:
    assert malicious._main(["build-malicious", str(names), str(source)]) == 0


def _lines(names: Path, file: str) -> list[str]:
    return (names / "malicious" / file).read_text(encoding="utf-8").splitlines()


def _record(root: Path, ecosystem: str, name: str, mal: str, **affected) -> None:
    directory = root / "osv" / "malicious" / ecosystem.lower() / name
    directory.mkdir(parents=True, exist_ok=True)
    extra = {k: affected.pop(k) for k in ("withdrawn",) if k in affected}
    (directory / f"{mal}.json").write_text(json.dumps({
        "id": mal, **extra,
        "affected": [{"package": {"ecosystem": ecosystem, "name": name}, **affected}]}))


# ------------------------------------------------ 1. built from OSV records


def test_the_lists_are_built_sorted_per_ecosystem_from_osv_records(tmp_path):
    names = tmp_path / "names"

    _build(names)

    assert _lines(names, "npm.txt") == [
        "@hyperion-util/cookies\t77.77.79\tMAL-2023-1",   # its versions only
        "arpan-package\t*\tMAL-2022-1122",               # a range from 0: every version
        "atez\t*\tMAL-2022-1153",
    ]
    assert _lines(names, "pypi.txt") == [
        "barcodeqrgen\t1.0.3\tMAL-2023-1355",
        "security-util-py\t0.0.5,0.0.6\tMAL-2023-10",
    ]
    assert _lines(names, "crates.txt") == ["aovine\t*\tMAL-2026-14332"]
    assert _lines(names, "rubygems.txt") == ["1-as-identity_function\t1.0.1\tMAL-2024-6265"]
    assert _lines(names, "packagist.txt") == ["intercom/intercom-php\t5.0.2\tMAL-2026-3637"]
    for file in malicious.FILES.values():
        lines = _lines(names, file)
        assert lines == sorted(lines, key=lambda line: line.encode()), file
    metadata = json.loads((names / "malicious" / "metadata.json").read_text())
    assert metadata["ecosystems"]["npm"]["count"] == 3
    assert metadata["passed_over"] == {"NuGet": 1}     # no ecosystem valvur indexes
    assert metadata["built_at"] and metadata["source"] == str(FIXTURE)


def test_the_tarball_index_yml_reads_builds_the_same_lists(tmp_path):
    tarball = tmp_path / "main.tar.gz"
    with tarfile.open(tarball, "w:gz") as archive:
        archive.add(FIXTURE / "malicious-packages-main", arcname="malicious-packages-main")

    _build(tmp_path / "tree")
    _build(tmp_path / "tar", tarball)

    for file in malicious.FILES.values():
        assert _lines(tmp_path / "tree", file) == _lines(tmp_path / "tar", file), file


def test_withdrawn_records_and_a_directory_named_like_a_record_are_passed_over(tmp_path):
    source = tmp_path / "source"
    copy_fixture(FIXTURE, source)
    root = source / "malicious-packages-main"
    _record(root, "npm", "left-pad-ok", "MAL-2099-1", withdrawn="2099-01-01T00:00:00Z",
            versions=["1.0.0"])
    (root / "osv" / "malicious" / "npm" / "formatters.json").mkdir()   # measured: nine
    names = tmp_path / "names"

    _build(names, source)

    assert not any(line.startswith("left-pad-ok\t") for line in _lines(names, "npm.txt"))
    assert not any(line.startswith("0x2ai-demo1\t") for line in _lines(names, "npm.txt"))


def test_a_range_is_kept_as_the_versions_it_covers(tmp_path):
    root = tmp_path / "source" / "repo"
    _record(root, "npm", "kite-public", "MAL-2099-2",
            ranges=[{"type": "SEMVER", "events": [{"introduced": "7.6.6"}]}])
    _record(root, "npm", "fixed-later", "MAL-2099-3",
            ranges=[{"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "1.0.5"}]}])
    names = tmp_path / "names"

    _build(names, tmp_path / "source")

    with malicious.open_list(names, "npm") as listed:
        kite, later = listed.lookup("kite-public"), listed.lookup("fixed-later")
    assert kite.names("7.6.6") and kite.names("8.0.0") and not kite.names("7.6.5")
    assert later.names("1.0.4") and not later.names("1.0.5") and not later.names("0.9.9")
    assert not kite.names(None)                  # declared, not locked: no version to match


# --------------------------------------------------------- 3. the reader


def test_the_reader_answers_names_and_versions_by_bisection(tmp_path):
    names = tmp_path / "names"
    _build(names)

    with malicious.open_list(names, "npm") as listed:
        cookies = listed.lookup("@hyperion-util/cookies")
        atez = listed.lookup("atez")
        assert listed.lookup("react") is None
        assert listed.lookup("ate") is None and listed.lookup("atez-extra") is None
        assert listed.lookup("") is None

    assert cookies.ids == ("MAL-2023-1",)
    assert cookies.names("77.77.79") and not cookies.names("1.0.0")
    assert atez.names("9.9.9") and atez.names(None)
    assert malicious.open_list(names, "gomod") is None


def test_every_name_of_a_long_list_is_found_and_none_between_them(tmp_path):
    directory = tmp_path / "names" / "malicious"
    directory.mkdir(parents=True)
    listed = sorted(f"pkg-{n:05d}" for n in range(0, 20_000, 2))
    (directory / "npm.txt").write_text("".join(f"{n}\t*\tMAL-1\n" for n in listed))

    with malicious.open_list(tmp_path / "names", "npm") as found:
        assert all(found.lookup(n) for n in listed[::97])
        assert not any(found.lookup(f"pkg-{n:05d}") for n in range(1, 20_000, 194))


# ------------------------------------------ 4 and 5. the Check, and the merge


@pytest.fixture
def listed_index(name_index):
    """A test's own index, with the fixture's malicious lists beside it."""
    directory = name_index(npm=["react", "atez", "arpan-package"], pip=["requests"])
    _build(directory)
    return directory


def _repository_8(root: Path, version: str = "77.77.79") -> Path:
    """Acceptance repository 8's shape: the name declared and locked."""
    name = "@hyperion-util/cookies"
    (root / "package.json").write_text(json.dumps(
        {"name": "acceptance-8", "version": "1.0.0", "dependencies": {name: version}}))
    (root / "package-lock.json").write_text(json.dumps({
        "name": "acceptance-8", "version": "1.0.0", "lockfileVersion": 3,
        "packages": {"": {"dependencies": {name: version}},
                     f"node_modules/{name}": {"version": version}}}))
    return root


def _osv_mal_2023_1() -> str:
    return json.dumps({"results": [{
        "source": {"path": "/workspace/package-lock.json", "type": "lockfile"},
        "packages": [{"package": {"name": "@hyperion-util/cookies", "version": "77.77.79",
                                  "ecosystem": "npm"},
                      "vulnerabilities": [{"id": "MAL-2023-1",
                                           "summary": "Malicious code"}]}]}]})


def test_repository_8_is_one_critical_finding_naming_both_scanners(workspace, listed_index):
    from valvur.adapters import OsvAdapter
    from valvur.adapters.check import CheckAdapter

    _repository_8(workspace)

    run = api.scan(workspace, runner=GoldenRunner(**{"osv-scanner": _osv_mal_2023_1()}),
                   adapters=[OsvAdapter(), CheckAdapter("dependency-reality")],
                   profile="offline")

    about = [f for f in run.findings if "hyperion" in f.title + f.evidence]
    assert len(about) == 1, [(f.rule, f.sources) for f in about]
    [finding] = about
    assert finding.rule == "valvur.dependency.malicious"
    assert finding.severity == "critical"
    assert set(finding.sources) == {"dependency-reality", "osv-scanner"}
    assert "MAL-2023-1" in finding.title
    assert finding.rank == 1


def _malicious(workspace: Path) -> dict[str, dict]:
    return {f["title"].split()[0]: f for f in DependencyRealityCheck().run(workspace)
            if f["rule"] == "valvur.dependency.malicious"}


@pytest.fixture
def empty(tmp_path) -> Path:
    """A workspace holding only what a test writes."""
    root = tmp_path / "ws"
    root.mkdir()
    return root


def test_a_version_scoped_entry_flags_only_the_locked_version_it_names(empty, listed_index):
    workspace = _repository_8(empty, "1.0.0")
    (workspace / "requirements.txt").write_text("barcodeqrgen\nsecurity-util-py==0.0.5\n")

    found = _malicious(workspace)

    assert "@hyperion-util/cookies" not in found      # 1.0.0 is not a version it names
    assert "barcodeqrgen" not in found                # declared, no version locked
    assert found["security-util-py"]["severity"] == "critical"
    assert found["security-util-py"]["path"] == "requirements.txt"


def test_a_whole_package_entry_flags_it_declared_or_locked(empty, listed_index):
    workspace = empty
    (workspace / "package.json").write_text(json.dumps({"dependencies": {"atez": "^1.0.0"}}))
    (workspace / "yarn.lock").write_text('arpan-package@^2.0.0:\n  version "2.0.1"\n')

    found = _malicious(workspace)

    assert set(found) == {"atez", "arpan-package"}
    assert found["atez"]["path"] == "package.json"
    assert found["arpan-package"]["path"] == "yarn.lock"
    assert "MAL-2022-1153" in found["atez"]["title"]


def test_a_malicious_name_is_not_also_called_nonexistent(empty, listed_index):
    workspace = _repository_8(empty)             # absent from this test's npm index

    rules = [f["rule"] for f in DependencyRealityCheck().run(workspace)]

    assert rules == ["valvur.dependency.malicious"]


# --------------------------------------------- 6. fetched with the index


def test_valvur_update_fetches_it_with_the_index(monkeypatch):
    called: list[dict] = []
    monkeypatch.setattr(name_index.build, "refresh", lambda *a, **k: {})
    monkeypatch.setattr(malicious, "refresh",
                        lambda directory, **kwargs: called.append(kwargs) or {})

    assert updating.refresh_index(lambda _: None) is True

    assert [(c["build"], c["fallback"]) for c in called] == [(False, True)]


def test_until_main_publishes_it_an_update_builds_it_from_the_source(monkeypatch, tmp_path):
    built: list[str] = []

    def unpublished(*args, **kwargs):
        raise name_index.IndexUnavailable("ghcr.io/maverickhq/valvur-index:malicious: 404")

    monkeypatch.setattr(malicious, "fetch_published", unpublished)
    monkeypatch.setattr(malicious, "build_lists",
                        lambda directory, source, **_: built.append(source))

    malicious.refresh(tmp_path / "names", fallback=True)
    with pytest.raises(name_index.IndexUnavailable):
        malicious.refresh(tmp_path / "names", fallback=False)       # a scan never builds

    assert built == [malicious.SOURCE]


def test_a_scan_refreshes_a_list_past_two_days_and_records_it(
        workspace, host_cache, monkeypatch, _fresh_kev, _fresh_epss):  # noqa: F811
    from test_first_run import _Runner, _scan, _write_db, _write_index

    _write_db(host_cache)
    _write_index(host_cache)
    (host_cache / "kev.json").write_text(_fresh_kev)
    (host_cache / "epss_scores.csv.gz").write_bytes(_fresh_epss)
    _build(host_cache / "names")
    metadata = host_cache / "names" / "malicious" / "metadata.json"
    stale = json.loads(metadata.read_text())
    stale["built_at"] = "2026-09-01T00:00:00Z"
    metadata.write_text(json.dumps(stale))
    asked: list[bool] = []
    monkeypatch.setattr(malicious, "refresh",
                        lambda directory, **kwargs: asked.append(kwargs["fallback"]) or {})

    run, said = _scan(workspace, _Runner(host_cache))

    assert asked == [False]
    assert any(line.startswith("refreshing the malicious list") for line in said), said
    assert [f["what"] for f in run.fetched] == ["malicious list"]


# ---------------------------------------------- 2 and 7. the workflows


def _job(name: str) -> str:
    """One job of index.yml, from its header to the next job's."""
    text = (REPO / ".github" / "workflows" / "index.yml").read_text()
    jobs = re.split(r"^  (?=[a-z])", text.split("\njobs:\n", 1)[1], flags=re.M)
    [job] = [j for j in jobs if j.startswith(f"{name}:")]
    return job


def test_index_yml_publishes_the_list_only_after_its_round_trip():
    job = _job("malicious")
    order = [job.index(step) for step in (
        "valvur.name_index build-malicious", 'oras push "$REPOSITORY:malicious-candidate"',
        "cosign sign", "valvur.name_index pull-malicious", "cmp ",
        'oras tag "$REPOSITORY@$DIGEST" "malicious-$DATE" malicious')]
    assert order == sorted(order), order
    guard = "if: github.ref == 'refs/heads/main'"
    steps = job.split("\n      - ")
    for fragment in ("oras push", "cosign sign", "pull-malicious", "oras tag"):
        [step] = [s for s in steps if fragment in s]
        assert guard in step, f"{fragment!r} runs off main"
    assert 'os.environ["DIGEST"]' in job


def test_retention_keeps_six_weeks_of_both_tags():
    text = (REPO / ".github" / "workflows" / "retention.yml").read_text()
    step = text.split("package-name: valvur-index", 1)[1]
    keep = int(re.search(r"min-versions-to-keep:\s*(\d+)", step).group(1))

    # Each day pushes an index and a list, each signed: four versions a day.
    assert keep >= 4 * 42


def test_notice_credits_the_source():
    notice = (REPO / "NOTICE").read_text()
    assert "ossf/malicious-packages" in notice and "Apache License 2.0" in notice
    assert "Fetched on demand on the `full` profile" not in notice      # R11.4's EPSS


def test_the_list_is_read_where_the_index_is_mounted():
    assert malicious.directory(cache.name_index()) == cache.name_index() / "malicious"

