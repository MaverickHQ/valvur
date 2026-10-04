"""R27.2: no manifest under `tests/` reads as one (D63a).

Scorecard's Vulnerabilities check runs OSV-Scanner over the repository and scored 0
on 44 advisories, 43 of them in manifests planted under `tests/fixtures` for valvur's
own tests to find (R27.1). So each is stored as `<name>.fixture`, a name no scanner
reads as a manifest, and `scripts/fixtures.py` copies a fixture with its real names
back. The one real advisory, python-ecdsa's in Checkov's lock, is recorded where
OSV-Scanner reads ignores, with its reason.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent


@pytest.mark.e2e
def test_osv_scanner_reads_no_manifest_under_tests():
    """The checkout as OSV-Scanner walks it, by its git view, from the image and with
    no network: it reads the repository's own locks and nothing under `tests/`."""
    from valvur.runner import IMAGE, detect_runtime

    probe = subprocess.run(
        [detect_runtime(), "run", "--rm", "--network=none", "-v", f"{REPO}:/workspace:ro",
         "-e", "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/tmp/none",
         "--entrypoint", "osv-scanner", IMAGE, "scan", "source", "--recursive",
         "--offline-vulnerabilities", "--format", "json", "/workspace"],
        capture_output=True, text=True, timeout=300, check=False)

    read = re.findall(r"^Scanned /workspace/(\S+) file", probe.stderr, re.M)
    assert "uv.lock" in read, f"the probe read nothing it should: {probe.stderr[-500:]}"
    assert [path for path in read if path.startswith("tests/")] == []


def test_the_helper_copies_a_fixture_with_its_real_names_and_leaves_the_tree(tmp_path):
    from fixture_copy import copy_fixture

    stored = sorted(p.name for p in (REPO / "tests/fixtures/broken-repo").iterdir())
    copied = copy_fixture("broken-repo", tmp_path / "ws")

    names = {p.name for p in copied.iterdir()}
    assert {"requirements.txt", "requirements-ai.txt", "requirements-dev.txt",
            "package-lock.json"} <= names
    assert not any(name.endswith(".fixture") for name in names)
    assert sorted(p.name for p in (REPO / "tests/fixtures/broken-repo").iterdir()) == stored


def test_no_manifest_under_tests_is_stored_under_its_real_name():
    """What OSV-Scanner reads as a manifest, by name, from its extractors' list of
    the ecosystems valvur's fixtures plant; the e2e test asks OSV-Scanner itself."""
    manifests = {"requirements.txt", "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
                 "Pipfile.lock", "poetry.lock", "uv.lock", "Gemfile.lock", "composer.lock",
                 "Cargo.lock", "go.mod", "pom.xml", "gradle.lockfile", "packages.lock.json"}
    tracked = subprocess.run(["git", "-C", str(REPO), "ls-files", "tests"],
                             capture_output=True, text=True, check=True).stdout.splitlines()
    found = [path for path in tracked if Path(path).name in manifests
             or re.fullmatch(r"requirements[\w.-]*\.txt", Path(path).name)]
    assert found == [], found


def test_every_copy_of_a_fixture_goes_through_the_helper():
    """A test that copied a fixture with `shutil.copytree` would scan its manifests
    under their stored names and find nothing, silently."""
    copies = re.compile(r"copytree\([^,\n]*(?:fixtures|FIXTURES?\b|BROKEN)")
    for path in sorted([*REPO.glob("tests/*.py"), *REPO.glob("scripts/**/*.py")]):
        if path.name in {"fixtures.py", "fixture_copy.py"}:
            continue
        assert not copies.search(path.read_text()), f"{path.name} copies a fixture itself"


def test_checkovs_accepted_advisory_is_recorded_once_where_osv_scanner_reads_ignores():
    """The one real advisory of the 44, accepted since Checkov's lock moved, and now
    recorded in the file OSV-Scanner, and so Scorecard, reads. valvur honours a
    project's own tool configuration, as it does `.gitleaks.toml`, so its scan of
    itself reads the same ignore, and a second record in `.security-scan.toml` matched
    nothing (measured: `valvur.suppression.stale`). One record, then, with its reason
    and its review date: OSV-Scanner stops ignoring it on that date, and it comes back
    in Scorecard and in valvur's own scan alike. Nothing else is ignored there."""
    import datetime
    import tomllib

    ignored = tomllib.loads((REPO / "osv-scanner.toml").read_text())["IgnoredVulns"]
    suppressed = tomllib.loads((REPO / ".security-scan.toml").read_text())["suppress"]

    assert [entry["id"] for entry in ignored] == ["PYSEC-2026-1325"]
    [entry] = ignored
    assert "CVE-2024-23342" in entry["reason"] and "requirements-checkov.txt" in entry["reason"]
    assert "no fix" in entry["reason"] and "Revisit if" in entry["reason"]
    review = entry["ignoreUntil"].date()
    assert datetime.date.today() < review <= datetime.date.today() + datetime.timedelta(days=366)
    assert not [s for s in suppressed if s["rule"] == "CVE-2024-23342"], "recorded twice"


@pytest.mark.e2e
def test_osv_scanner_honours_the_ignore_on_checkovs_lock():
    from valvur import osv_offline
    from valvur.runner import IMAGE, detect_runtime

    database = osv_offline.directory()
    if not (database / "osv-scalibr" / "PyPI" / "all.zip").is_file():
        pytest.skip("OSV's PyPI database is not in this cache; `valvur update` fetches it")
    probe = subprocess.run(
        [detect_runtime(), "run", "--rm", "--network=none", "-v", f"{REPO}:/workspace:ro",
         "-v", f"{database}:/cache/osv:ro", "-e", "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/cache/osv",
         "--entrypoint", "osv-scanner", IMAGE, "scan", "source", "--lockfile",
         "requirements.txt:/workspace/requirements-checkov.txt", "--offline-vulnerabilities",
         "--format", "json"],
        capture_output=True, text=True, timeout=300, check=False)

    import json

    found = [v["id"] for result in json.loads(probe.stdout or "{}").get("results", [])
             for package in result["packages"] for v in package.get("vulnerabilities", [])]
    assert probe.returncode == 0, probe.stderr[-800:]
    assert "PYSEC-2026-1325" not in found and found == [], found
