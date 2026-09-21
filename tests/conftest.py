import json
import os
import platform
import shutil
import tempfile
from pathlib import Path
from typing import ClassVar

import pytest

from valvur.adapters.base import ScannerAdapter

#: The real `urlopen` and opener, for the two falsifiability tests that poison the
#: socket layer themselves and need the HTTP layer to actually try (see
#: `record_connections`).
REAL_URLOPEN = None
REAL_OPENER_OPEN = None

# ------------------------------------------------ the package-name index (ADR-0018)

#: Names the default test index says exist, per ecosystem. PyPI's come from the
#: popular list shipped in the image (3,000 real names); the others have no such
#: list, so a few real ones are enough for the fixtures. Anything else does not
#: exist — which is the point.
KNOWN_NPM = (
    "react", "react-dom", "lodash", "express", "axios", "chalk", "typescript",
    "eslint", "jest", "webpack", "vue", "next", "left-pad", "@types/node",
    "@types/react", "commander", "debug", "moment", "uuid", "semver",
)
KNOWN_GEMS = ("rails", "rack", "sinatra", "rspec", "puma", "nokogiri", "rake", "bundler")
KNOWN_COMPOSER = ("monolog/monolog", "symfony/console", "laravel/framework",
                  "guzzlehttp/guzzle", "phpunit/phpunit")
KNOWN_CRATES = ("serde", "serde_json", "tokio", "clap", "anyhow", "regex", "rand")


def write_name_index(directory: Path, *, built_at=None, **names) -> Path:
    """Write an index in the exact on-disk format `valvur update` produces, so tests
    exercise the same reader against the same bytes. `names` is per ecosystem
    (`pip=[...]`, `gem=[...]`); every ecosystem's file is written, empty when not
    given, so a Workspace declaring one is checked against nothing rather than
    failing for want of an index."""
    from valvur.checks.dependency_reality import _index_form
    from valvur.name_index import FILES, METADATA, _now

    directory.mkdir(parents=True, exist_ok=True)
    unknown = set(names) - set(FILES)
    assert not unknown, f"no index for {unknown}"
    stamp = built_at or _now()
    entries = {}
    for ecosystem, filename in FILES.items():
        given = tuple(names.get(ecosystem, ()))
        ordered = sorted({_index_form(ecosystem, n).encode() for n in given})
        (directory / filename).write_bytes(b"".join(n + b"\n" for n in ordered))
        entries[ecosystem] = {"built_at": stamp, "count": len(given), "source": "test"}
    (directory / METADATA).write_text(json.dumps({"schema": 1, "ecosystems": entries}))
    return directory


@pytest.fixture(scope="session")
def default_name_index(tmp_path_factory) -> Path:
    from valvur.checks.dependency_reality import _popular

    return write_name_index(
        tmp_path_factory.mktemp("names"), pip=_popular().values(), npm=KNOWN_NPM,
        gem=KNOWN_GEMS, composer=KNOWN_COMPOSER, cargo=KNOWN_CRATES,
    )


@pytest.fixture(autouse=True)
def _no_sockets_from_unit_tests(monkeypatch):
    """The unit suite never opens a socket. Anything that needs one is `e2e`.

    Made explicit after ADR-0018: the fake runners now run the dependency-reality
    Check in-process with the network grant the Profile gives it, so a `full` scan
    against a fake runner would otherwise reach PyPI from a unit test. It fails
    loudly here instead — as `RegistryUnreachable`, which is what the Check does
    with a dead network in production too.
    """
    import urllib.error
    import urllib.parse
    import urllib.request

    global REAL_URLOPEN, REAL_OPENER_OPEN
    REAL_URLOPEN = urllib.request.urlopen
    REAL_OPENER_OPEN = urllib.request.OpenerDirector.open

    def refuse(request, *args, **kwargs):
        url = getattr(request, "full_url", request)
        raise urllib.error.URLError(f"unit tests do not open sockets (tried {url})")

    monkeypatch.setattr(urllib.request, "urlopen", refuse)

    # The OCI client (`valvur.oci`) builds its own opener, for the redirect rule a
    # registry needs, so `urlopen` above does not cover it. Openers may reach
    # loopback and nothing else: the registry tests run a real `http.server` on
    # 127.0.0.1, because a 401 challenge and a cross-host redirect are HTTP
    # behaviour worth exercising for real, and loopback cannot leak anything.
    def loopback_only(self, fullurl, *args, **kwargs):
        url = getattr(fullurl, "full_url", fullurl)
        host = urllib.parse.urlsplit(url).hostname
        if host not in ("127.0.0.1", "localhost", "::1"):
            raise urllib.error.URLError(f"unit tests do not open sockets (tried {url})")
        return REAL_OPENER_OPEN(self, fullurl, *args, **kwargs)

    monkeypatch.setattr(urllib.request.OpenerDirector, "open", loopback_only)


@pytest.fixture(scope="session")
def default_trivy_db(tmp_path_factory) -> Path:
    """A vulnerability database that is *present* — an empty file where Trivy's
    would be — so `cache.db_present()` answers True without a 1.3GB download.
    Since 26.2.1 the Trivy adapter refuses before launching when the database is
    absent, and that refusal reaches every fake; the first CI run of the move
    found the unit job has no database and every Trivy fake answering the refusal
    instead. A test about the absent database patches `cache.trivy_db` itself."""
    root = tmp_path_factory.mktemp("trivy")
    (root / "db").mkdir()
    (root / "db" / "trivy.db").write_bytes(b"")
    (root / "db" / "metadata.json").write_text(
        '{"UpdatedAt": "2099-01-01T00:00:00Z", "NextUpdate": "2099-01-02T00:00:00Z"}')
    return root


@pytest.fixture(autouse=True)
def _installed_name_index(default_name_index, default_trivy_db, monkeypatch):
    """Every test runs as on a machine that has done `valvur update`: an index and
    a database are present, fresh, and the Checks and Trivy read them. Without
    this, the dependency-reality Check fails loudly on the offline Profile —
    correctly, and in every scan test — and Trivy refuses before launching.

    The network grant is cleared too, so a developer's shell cannot leak one in.
    Pointing `trivy_db` at a temporary directory also stops a unit test that
    builds container flags from creating `~/.cache/valvur/trivy` on the machine.
    """
    from valvur import cache

    monkeypatch.setenv("VALVUR_NAME_INDEX", str(default_name_index))
    monkeypatch.delenv("VALVUR_NETWORK", raising=False)
    monkeypatch.setattr(cache, "name_index", lambda: default_name_index)
    monkeypatch.setattr(cache, "trivy_db", lambda: default_trivy_db)


@pytest.fixture
def name_index(tmp_path, monkeypatch):
    """A test's own index: `name_index(pip=[...], npm=[...])` — those names exist and
    nothing else does. Replaces the default for this test only."""
    from valvur import cache

    def build(*, built_at=None, **names) -> Path:
        directory = write_name_index(tmp_path / "names", built_at=built_at, **names)
        monkeypatch.setenv("VALVUR_NAME_INDEX", str(directory))
        monkeypatch.setattr(cache, "name_index", lambda: directory)
        return directory

    return build


@pytest.fixture
def no_name_index(tmp_path, monkeypatch):
    """A machine that has never run `valvur update`."""
    from valvur import cache

    empty = tmp_path / "no-names"
    empty.mkdir()
    monkeypatch.setenv("VALVUR_NAME_INDEX", str(empty))
    monkeypatch.setattr(cache, "name_index", lambda: empty)
    return empty


@pytest.fixture
def network_granted(monkeypatch):
    """What the runner does to a container on the `full` Profile."""
    monkeypatch.setenv("VALVUR_NETWORK", "1")


def run_checks_in_process(names, workspace: Path, *, network: bool) -> dict:
    """What the container's batch does, in-process: each Check isolated, so one
    refusing costs nothing to the others (F2.5)."""
    from valvur.runner import ScannerOutput

    outputs = {}
    for name in names:
        try:
            outputs[name] = run_check_in_process(name, workspace, network=network)
        except RuntimeError as exc:
            outputs[name] = ScannerOutput(name, "0.1.0.dev0", "", str(exc), 1)
    return outputs


def run_check_in_process(name: str, workspace: Path, *, network: bool):
    """Run one of valvur's Checks here rather than in a container, telling it what
    the runner would have told it: whether it was given a network (ADR-0018)."""
    from valvur.checks import REGISTRY
    from valvur.runner import ScannerOutput

    check = REGISTRY.get(name)
    if check is None:
        return ScannerOutput(name, "0.1.0.dev0", "[]", "", 0)
    previous = os.environ.get("VALVUR_NETWORK")
    if network:
        os.environ["VALVUR_NETWORK"] = "1"
    else:
        os.environ.pop("VALVUR_NETWORK", None)
    try:
        payload = json.dumps(check.run(workspace))
    finally:
        if previous is None:
            os.environ.pop("VALVUR_NETWORK", None)
        else:
            os.environ["VALVUR_NETWORK"] = previous
    return ScannerOutput(name, "0.1.0.dev0", payload, "", 0)

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def mountable_tmp(tmp_path):
    """A temp directory every container runtime can actually mount.

    Podman on macOS runs a VM that shares only certain host paths. pytest's tmp_path
    lives under /var/folders, which it does not share, so the workspace mounts as an
    empty directory and the scan correctly refuses to report it. That is an
    environment limit rather than a regression — but leaving these tests red hides
    the real regressions they exist to catch.
    """
    if platform.system() != "Darwin":
        yield tmp_path
        return
    base = Path("/private/tmp/valvur-tests")
    base.mkdir(parents=True, exist_ok=True)
    made = Path(tempfile.mkdtemp(dir=base))
    try:
        yield made
    finally:
        shutil.rmtree(made, ignore_errors=True)


@pytest.fixture
def workspace(mountable_tmp):
    """A disposable copy of the broken fixture repo."""
    ws = mountable_tmp / "ws"
    shutil.copytree(FIXTURES / "broken-repo", ws)
    return ws


@pytest.fixture
def clean_workspace(mountable_tmp):
    ws = mountable_tmp / "clean"
    shutil.copytree(FIXTURES / "clean-repo", ws)
    return ws


GITLEAKS_ONE_SECRET = json.dumps([
    {
        "RuleID": "aws-access-token",
        "Description": "AWS Access Token",
        "File": "/workspace/config.py",
        "StartLine": 3,
        "Secret": "AKIAV7Q2XR4TVBN6WLKJ",
        "Match": 'AWS_ACCESS_KEY_ID = "AKIAV7Q2XR4TVBN6WLKJ"',
    }
])


class LegacyDispatch:
    """The fakes' `run_<tool>(workspace)` methods, reached through the one
    `run(invocation, workspace)` the adapters call since 26.2.1. A fake keeps
    describing what a tool answers; this maps the Invocation to that answer."""

    _BY_TOOL: ClassVar[dict[str, str]] = {
        "gitleaks": "run_gitleaks", "trivy": "run_trivy", "osv-scanner": "run_osv",
        "checkov": "run_checkov", "syft": "run_syft", "opengrep": "run_opengrep",
    }

    def run(self, invocation, workspace):
        method = self._BY_TOOL.get(invocation.tool)
        if method is None:
            raise AssertionError(f"this fake answers no Invocation for {invocation.tool!r}")
        return getattr(self, method)(workspace)


class FakeRunner(LegacyDispatch):
    """Stands in for the container runtime — a system boundary, so faking is fair game.

    SDK-style: one method per scanner operation, each returning one shape.
    """

    def __init__(self, gitleaks_stdout: str = "[]", exit_code: int = 0):
        self._stdout = gitleaks_stdout
        self._exit_code = exit_code

    def run_gitleaks(self, workspace: Path):
        from valvur.runner import ScannerOutput

        return ScannerOutput(
            tool="gitleaks", version="8.30.1",
            stdout=self._stdout, stderr="", exit_code=self._exit_code,
        )

    def _quiet(self, tool, version, payload):
        from valvur.runner import ScannerOutput

        return ScannerOutput(tool=tool, version=version, stdout=payload,
                             stderr="", exit_code=0)

    def run_trivy(self, workspace: Path):
        """Quiet by default. Tests exercising a Scanner use GoldenRunner instead."""
        return self._quiet("trivy", "0.74.0", '{"Results": []}')

    def run_osv(self, workspace: Path):
        return self._quiet("osv-scanner", "2.6.0", '{"results": []}')

    def run_checkov(self, workspace: Path):
        return self._quiet("checkov", "3.3.17", '{"results": {"failed_checks": []}}')

    def run_syft(self, workspace: Path):
        return self._quiet("syft", "1.51.1", "")

    def run_opengrep(self, workspace: Path):
        return self._quiet("opengrep", "1.29.0", '{"results": []}')

    def run_check(self, name: str, workspace: Path, *, network: bool = False):
        """Runs valvur's own Checks in-process. They are functions of the Workspace
        and of what the runner tells them, so that is all the boundary to fake."""
        return run_check_in_process(name, workspace, network=network)

    def run_checks(self, names, workspace: Path, *, network: bool = False):
        """The batch (23.4.2), so the suite exercises the production path: the
        real runner runs these in one container; here they run in-process."""
        return run_checks_in_process(names, workspace, network=network)


@pytest.fixture
def runner_finding_one_secret():
    return FakeRunner(GITLEAKS_ONE_SECRET, exit_code=1)  # gitleaks exits 1 when it finds something


@pytest.fixture
def runner_finding_nothing():
    return FakeRunner("[]", exit_code=0)


@pytest.fixture
def git_workspace(workspace):
    """A Workspace that is a real git repo with a clean tree."""
    import subprocess

    def git(*args):
        subprocess.run(["git", *args], cwd=workspace, check=True,
                       capture_output=True, env={"HOME": str(workspace), "PATH": "/usr/bin:/bin"})

    git("init", "-q", "-b", "main")
    git("-c", "user.email=t@example.com", "-c", "user.name=t",
        "-c", "commit.gpgsign=false", "add", "-A")
    git("-c", "user.email=t@example.com", "-c", "user.name=t",
        "-c", "commit.gpgsign=false", "commit", "-q", "-m", "fixture")
    return workspace


def gitleaks_output(*, line=3, file="/workspace/config.py", secret="AKIAV7Q2XR4TVBN6WLKJ",
                    rule="aws-access-token", match=None):
    """Build gitleaks-shaped output, so tests can vary one thing at a time."""
    return json.dumps([{
        "RuleID": rule,
        "Description": "AWS Access Token",
        "File": file,
        "StartLine": line,
        "Secret": secret,
        "Match": match if match is not None else f'AWS_ACCESS_KEY_ID = "{secret}"',
    }])


class CrashingAdapter(ScannerAdapter):
    """A Scanner that dies. Not a mock of an internal collaborator — a real adapter
    whose tool fails, which is the only way to exercise fleet failure isolation."""

    name = "exploding-scanner"

    def __init__(self, reason="container exited 137 (OOM)"):
        self._reason = reason

    def run(self, runner, workspace):
        raise RuntimeError(self._reason)

    def parse(self, output):  # pragma: no cover - never reached
        return []


# Golden fixtures carry the Scanner version in the filename. If a Scanner is upgraded
# without recapturing, this mismatch fails loudly rather than silently re-baselining
# parsing behaviour (task 3.4.1).
PINNED_VERSIONS = {
    "trivy": "0.74.0", "gitleaks": "8.30.1", "osv-scanner": "2.6.0",
    "checkov": "3.3.17", "syft": "1.51.1", "opengrep": "1.29.0",
}


def golden(tool: str) -> str:
    version = PINNED_VERSIONS[tool]
    path = FIXTURES / "golden" / f"{tool}-{version}.json"
    if not path.is_file():
        raise AssertionError(
            f"No golden fixture for {tool} {version}. If you upgraded {tool}, "
            f"recapture it and review the diff — parsing behaviour may have changed."
        )
    return path.read_text(encoding="utf-8")


class GoldenRunner(LegacyDispatch):
    """Serves captured real Scanner output, so adapters are tested against reality."""

    def __init__(self, **by_tool):
        self._by_tool = by_tool

    def _out(self, tool):
        from valvur.runner import ScannerOutput

        return ScannerOutput(tool, PINNED_VERSIONS.get(tool, ""),
                             self._by_tool.get(tool, ""), "", 0)

    def run_trivy(self, workspace):
        return self._out("trivy")

    def run_gitleaks(self, workspace):
        return self._out("gitleaks")

    def run_osv(self, workspace):
        return self._out("osv-scanner")

    def run_checkov(self, workspace):
        return self._out("checkov")

    def run_syft(self, workspace):
        return self._out("syft")

    def run_opengrep(self, workspace):
        return self._out("opengrep")

    def run_check(self, name, workspace, *, network=False):
        return run_check_in_process(name, workspace, network=network)

    def run_checks(self, names, workspace, *, network=False):
        return run_checks_in_process(names, workspace, network=network)
