"""Task 23.3.1 — `valvur doctor`: every precondition a first run has failed on, named
before a scan, with the fix on the failing ones.

Each of these checks is a failure this project has met for real: no runtime on PATH
(Podman Desktop at /opt/podman/bin), a daemon not running, the rc shim looking for an
image nobody had, a database that was never fetched, an index built before Ruby was
in it, an enforcing SELinux host denying every mount (20.1), and — found by the
0.2.0 first-run measurement (23.1.1) — a python.org interpreter with no CA bundle,
failing every host-side fetch while `pip` worked.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from conftest import write_name_index

from valvur import cache, doctor, name_index
from valvur.version import __version__

# ------------------------------------------------------------------ fixtures


@pytest.fixture
def healthy(tmp_path, monkeypatch):
    """A machine on which a scan will run: everything present and fresh, every
    probe answering as Docker Desktop does. Tests break one thing at a time."""
    root = tmp_path / "cache"
    monkeypatch.setattr(cache, "root", lambda: root)
    monkeypatch.setattr(cache, "trivy_db", lambda: root / "trivy")
    monkeypatch.setattr(cache, "name_index", lambda: root / "names")
    _write_db(root, age_days=0.3)
    write_name_index(root / "names", pip=["requests"], npm=["react"], gem=["rack"],
                     composer=["monolog/monolog"], cargo=["serde"])
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()
    monkeypatch.delenv("VALVUR_IMAGE", raising=False)
    monkeypatch.delenv("VALVUR_RUNTIME", raising=False)
    monkeypatch.delenv(name_index.reader.MIRROR_ENV, raising=False)
    monkeypatch.delenv(name_index.reader.INDEX_REPOSITORY_ENV, raising=False)

    monkeypatch.setattr(doctor, "_trusted_roots", lambda: 128)
    monkeypatch.setattr(doctor, "_find_runtime", lambda: "/usr/local/bin/docker")
    monkeypatch.setattr(doctor, "_runtime_version", lambda runtime: "Docker version 29.2.1")
    monkeypatch.setattr(doctor, "_runtime_running", lambda runtime: (True, ""))
    monkeypatch.setattr(doctor, "_image_present", lambda runtime, image: True)
    monkeypatch.setattr(doctor, "_image_label", lambda runtime, image: __version__)
    monkeypatch.setattr(doctor, "_image_protocol", lambda runtime, image: None)
    monkeypatch.setattr(doctor, "_image_starts", lambda runtime, image: (True, "0be0b0f0456f7f"))
    monkeypatch.setattr(doctor, "_superseded_images", lambda runtime: [])   # 28.3.7
    from valvur import runner as _runner

    # A roomy runtime, faked (29.1.3): `docker info` is a probe like the others.
    _runner.runtime_resources.cache_clear()
    monkeypatch.setattr(_runner, "runtime_resources", lambda runtime: (8 * 2**30, 8))
    from valvur import compat

    monkeypatch.setattr(compat, "shim_inputs", lambda: "0be0b0f0456f7f")   # the same tree (23.4.4)
    monkeypatch.setattr(doctor, "_selinux_enforcing", lambda: False)
    monkeypatch.setattr(doctor, "_platform", lambda: "Darwin")
    monkeypatch.setattr(doctor, "_reachable", lambda host, port=443: pytest.fail(f"probed {host}"))
    workspace = tmp_path / "ws"
    workspace.mkdir()
    return workspace


def _write_db(root: Path, *, age_days: float) -> None:
    db = root / "trivy" / "db"
    db.mkdir(parents=True, exist_ok=True)
    now = datetime.now(UTC)
    (db / "trivy.db").write_bytes(b"bolt")
    (db / "metadata.json").write_text(json.dumps({
        "UpdatedAt": (now - timedelta(days=age_days)).isoformat().replace("+00:00", "Z"),
        "NextUpdate": (now - timedelta(days=age_days - 1)).isoformat().replace("+00:00", "Z"),
    }))


def _by_name(checks) -> dict[str, doctor.Check]:
    return {c.name: c for c in checks}


# ------------------------------------------------------------- a healthy machine


def test_a_healthy_machine_is_ready_and_every_line_says_what_was_measured(healthy):
    checks = doctor.run(healthy)
    text = doctor.render(checks, healthy)

    assert not doctor.failed(checks)
    assert [c.level for c in checks if c.level == "fail"] == []
    by = _by_name(checks)
    assert by["python"].detail.endswith("128 trusted roots")
    assert by["runtime"].detail == (
        "Docker version 29.2.1 at /usr/local/bin/docker, running; 8.0 GiB, 8 CPUs — scans "
        "run 8 Scanners at a time (VALVUR_JOBS, or --jobs, to change)")
    assert by["image"].detail == (f"ghcr.io/maverickhq/valvur:{__version__}: version "
                                  f"{__version__} matches the shim; starts (built from 0be0b0f0, "
                                  "the tree this shim was built from)")
    assert by["database"].detail.startswith("0.3 days old; ")
    assert by["database"].detail.endswith(" on disk (118 MB to fetch)")   # 29.3.2
    assert by["index"].detail.startswith(
        "0.0 days old — pip 1 · npm 1 · gem 1 · composer 1 · cargo 1; "
        + cache.human_size(cache._tree_size(cache.name_index())) + " on disk (34 MB to fetch)")
    assert by["selinux"].detail == "not applicable on Darwin"
    assert by["network"].detail == "not probed (valvur doctor --network)"
    assert text.startswith(f"valvur {__version__} doctor — {healthy}\n")
    assert "  ok    runtime: Docker version 29.2.1" in text
    assert text.rstrip().endswith("ready: a scan will run here.")
    assert "fix:" not in text


# ------------------------------------------------------------------ TLS (23.1.1)


def test_an_interpreter_with_no_trusted_roots_fails_when_a_fetch_is_due(healthy, monkeypatch):
    """python.org's macOS build until *Install Certificates.command* is run: zero
    CA certificates, so every HTTPS verification fails. Measured 2026-09-13 —
    `cert_store_stats()["x509_ca"] == 0` on 3.10 and 3.12 from python.org, 128 on
    the interpreters that worked. With the database absent the first scan's fetch
    is next, and it will fail."""
    monkeypatch.setattr(doctor, "_trusted_roots", lambda: 0)
    import shutil
    shutil.rmtree(cache.trivy_db())

    checks = doctor.run(healthy)

    python = _by_name(checks)["python"]
    assert python.level == "fail"
    assert "0 trusted roots" in python.detail
    assert "Install Certificates.command" in python.fix and "SSL_CERT_FILE" in python.fix
    assert doctor.failed(checks)


def test_no_trusted_roots_is_a_warning_when_everything_is_already_cached(healthy, monkeypatch):
    """A scan with the data present never opens a socket on `offline`; the broken
    interpreter breaks `valvur update`, not this scan. Said, not failed."""
    monkeypatch.setattr(doctor, "_trusted_roots", lambda: 0)

    checks = doctor.run(healthy)

    assert _by_name(checks)["python"].level == "warn"
    assert not doctor.failed(checks)


def test_trusted_roots_are_counted_from_the_default_context(monkeypatch):
    """The real probe, on this interpreter: whatever it says must be what
    `ssl.create_default_context()` would verify with — and it is that context that
    is asked, not a number remembered from a machine that worked."""
    import ssl

    assert doctor._trusted_roots() == ssl.create_default_context().cert_store_stats()["x509_ca"]

    class Context:
        def cert_store_stats(self):
            return {"x509": 7, "crl": 0, "x509_ca": 7}

    monkeypatch.setattr(ssl, "create_default_context", lambda: Context())
    assert doctor._trusted_roots() == 7


# --------------------------------------------------------------------- runtime


def test_no_runtime_is_a_failure_with_the_install_lines(healthy, monkeypatch):
    from valvur.runner import NoContainerRuntime

    def missing():
        raise NoContainerRuntime("No container runtime found. valvur needs Docker or Podman.\n"
                                 "  macOS:  brew install --cask docker")

    monkeypatch.setattr(doctor, "_find_runtime", missing)

    checks = doctor.run(healthy)

    runtime = _by_name(checks)["runtime"]
    assert runtime.level == "fail"
    assert "brew install --cask docker" in runtime.fix
    # Nothing downstream can be measured without a runtime, and nothing pretends to.
    assert _by_name(checks)["image"].level == "skip"
    assert doctor.failed(checks)


def test_a_runtime_that_is_not_running_is_told_apart_from_a_missing_image(healthy, monkeypatch):
    """`docker image inspect` fails the same way when the daemon is down as when
    the image is absent; a doctor that said "image absent, the first scan pulls it"
    would send the user to wait for a pull that cannot start."""
    monkeypatch.setattr(doctor, "_runtime_running",
                        lambda runtime: (False, "Cannot connect to the Docker daemon at "
                                                "unix:///var/run/docker.sock"))
    monkeypatch.setattr(doctor, "_image_label", lambda r, i: pytest.fail("asked the daemon"))

    checks = doctor.run(healthy)

    runtime = _by_name(checks)["runtime"]
    assert runtime.level == "fail"
    assert "not running" in runtime.detail and "Cannot connect" in runtime.detail
    assert "Docker Desktop" in runtime.fix and "podman machine start" in runtime.fix
    assert _by_name(checks)["image"].level == "skip"


def test_the_runtime_probes_ask_the_binary_itself(tmp_path):
    fake = tmp_path / "docker"
    fake.write_text("#!/bin/sh\ncase \"$1\" in --version) echo 'Docker version 29.2.1, build a5c';;"
                    " info) echo 'Cannot connect to the Docker daemon' >&2; exit 1;; esac\n")
    fake.chmod(0o755)

    assert doctor._runtime_version(str(fake)) == "Docker version 29.2.1, build a5c"
    running, why = doctor._runtime_running(str(fake))
    assert running is False and "Cannot connect" in why


# ----------------------------------------------------------------------- image


def test_an_absent_image_is_information_not_failure_since_the_first_scan_pulls_it(
    healthy, monkeypatch
):
    monkeypatch.setattr(doctor, "_image_label", lambda runtime, image: None)
    monkeypatch.setattr(doctor, "_image_protocol", lambda runtime, image: None)
    monkeypatch.setattr(doctor, "_image_present", lambda runtime, image: False)

    checks = doctor.run(healthy)

    image = _by_name(checks)["image"]
    assert image.level == "info"
    assert "not local; the first scan pulls it" in image.detail
    assert not doctor.failed(checks)


def test_an_incompatible_image_fails_with_both_versions_and_the_fix(healthy, monkeypatch):
    """F1.9's refusal, before a scan rather than as its first error."""
    monkeypatch.setattr(doctor, "_image_label", lambda runtime, image: "0.1.0rc1")
    monkeypatch.setattr(doctor, "_image_starts", lambda r, i: pytest.fail("started a mismatch"))

    checks = doctor.run(healthy)

    image = _by_name(checks)["image"]
    assert image.level == "fail"
    assert "0.1.0rc1" in image.detail and __version__ in image.detail
    assert "docker pull" in image.fix and "pip install -U valvur" in image.fix


def test_an_image_that_will_not_start_fails_with_the_runtimes_words(healthy, monkeypatch):
    monkeypatch.setattr(doctor, "_image_starts",
                        lambda r, i: (False, "exec format error"))

    checks = doctor.run(healthy)

    image = _by_name(checks)["image"]
    assert image.level == "fail"
    assert "does not start: exec format error" in image.detail


def test_the_image_override_is_what_is_checked(healthy, monkeypatch):
    seen: list[str] = []
    monkeypatch.setenv("VALVUR_IMAGE", "registry.internal/mirror/valvur:9")
    monkeypatch.setattr(doctor, "_image_label",
                        lambda runtime, image: seen.append(image) or __version__)

    doctor.run(healthy)

    assert seen == ["registry.internal/mirror/valvur:9"]


# ------------------------------------------------------------- database, index


def test_an_absent_database_is_information_since_the_first_scan_fetches_it(healthy):
    import shutil
    shutil.rmtree(cache.trivy_db())

    database = _by_name(doctor.run(healthy))["database"]

    assert database.level == "info"
    assert "the first scan fetches it" in database.detail and "118 MB to fetch" in database.detail


def test_a_stale_database_warns_with_the_refresh_command(healthy, monkeypatch):
    _write_db(cache.root(), age_days=45)

    database = _by_name(doctor.run(healthy))["database"]

    assert database.level == "warn"
    assert "45.0 days old" in database.detail
    assert "valvur update" in database.fix
    assert "inconclusive" in database.detail


def test_an_index_missing_an_ecosystem_warns_and_names_it(healthy):
    """A cache built before 23.2.2 has no Ruby, PHP or Rust list; a scan of a
    Gemfile fails its dependency check for want of one. Named here first."""
    (cache.name_index() / "rubygems.txt").unlink()
    (cache.name_index() / "crates.txt").unlink()

    index = _by_name(doctor.run(healthy))["index"]

    assert index.level == "warn"
    assert "no list for gem, cargo" in index.detail
    assert "valvur update" in index.fix


def test_an_absent_index_is_information(healthy):
    import shutil
    shutil.rmtree(cache.name_index())

    index = _by_name(doctor.run(healthy))["index"]

    assert index.level == "info"
    assert "the first scan fetches it" in index.detail


def test_a_stale_index_warns(healthy):
    write_name_index(cache.name_index(), pip=["requests"], npm=["react"], gem=["rack"],
                     composer=["monolog/monolog"], cargo=["serde"],
                     built_at="2026-01-01T00:00:00Z")

    index = _by_name(doctor.run(healthy))["index"]

    assert index.level == "warn" and "days old" in index.detail


def test_kev_names_which_copy_a_scan_would_rank_with(healthy):
    kev = _by_name(doctor.run(healthy))["kev"]
    assert kev.level == "info" and "bundled snapshot" in kev.detail

    (cache.root() / "kev.json").write_text('{"entries": {}}')
    kev = _by_name(doctor.run(healthy))["kev"]
    assert "host cache, 0.0 days old" in kev.detail


# --------------------------------------------------------------------- SELinux


def test_an_enforcing_host_with_an_unlabelled_tree_fails_with_the_measured_fix(
    healthy, monkeypatch
):
    monkeypatch.setattr(doctor, "_platform", lambda: "Linux")
    monkeypatch.setattr(doctor, "_selinux_enforcing", lambda: True)
    monkeypatch.setattr(doctor, "_tree_label", lambda path: "unconfined_u:object_r:user_home_t:s0")
    monkeypatch.delenv("VALVUR_SELINUX_RELABEL", raising=False)

    selinux = _by_name(doctor.run(healthy))["selinux"]

    assert selinux.level == "fail"
    assert "user_home_t" in selinux.detail
    assert "chcon -R -t container_file_t" in selinux.fix
    assert "VALVUR_SELINUX_RELABEL=1" in selinux.fix


def test_an_enforcing_host_with_a_labelled_tree_is_fine(healthy, monkeypatch):
    monkeypatch.setattr(doctor, "_platform", lambda: "Linux")
    monkeypatch.setattr(doctor, "_selinux_enforcing", lambda: True)
    monkeypatch.setattr(doctor, "_tree_label",
                        lambda path: "unconfined_u:object_r:container_file_t:s0")

    selinux = _by_name(doctor.run(healthy))["selinux"]

    assert selinux.level == "ok" and "container_file_t" in selinux.detail


def test_an_enforcing_host_with_relabelling_requested_is_fine_and_says_what_it_costs(
    healthy, monkeypatch
):
    monkeypatch.setattr(doctor, "_platform", lambda: "Linux")
    monkeypatch.setattr(doctor, "_selinux_enforcing", lambda: True)
    monkeypatch.setattr(doctor, "_tree_label", lambda path: "unconfined_u:object_r:user_home_t:s0")
    monkeypatch.setenv("VALVUR_SELINUX_RELABEL", "1")

    selinux = _by_name(doctor.run(healthy))["selinux"]

    assert selinux.level == "ok"
    assert "will be relabelled" in selinux.detail and "persists" in selinux.detail


def test_a_linux_host_not_enforcing_says_so(healthy, monkeypatch):
    monkeypatch.setattr(doctor, "_platform", lambda: "Linux")

    assert _by_name(doctor.run(healthy))["selinux"].detail == "not enforcing"


# ---------------------------------------------------------------- MCP clients


def test_claude_code_and_kiro_configurations_are_found_and_read(healthy, tmp_path):
    (healthy / ".mcp.json").write_text(json.dumps({"mcpServers": {
        "valvur": {"command": "uvx", "args": ["--from", "valvur", "valvur-mcp"]}}}))
    kiro = healthy / ".kiro" / "settings"
    kiro.mkdir(parents=True)
    (kiro / "mcp.json").write_text(json.dumps({"mcpServers": {
        "security": {"command": "valvur-mcp", "args": [], "disabled": True}}}))
    home = Path(tmp_path / "home")
    (home / ".claude.json").write_text(json.dumps({
        "mcpServers": {"other": {"command": "x"}},
        "projects": {str(healthy): {"mcpServers": {"valvur": {"command": "valvur-mcp"}}}},
    }))

    mcp = _by_name(doctor.run(healthy))["mcp"]

    assert mcp.level == "info"
    assert ".mcp.json: valvur (uvx --from valvur valvur-mcp)" in mcp.detail
    assert "~/.claude.json [this project]: valvur (valvur-mcp)" in mcp.detail
    assert ".kiro/settings/mcp.json: security (valvur-mcp), DISABLED" in mcp.detail


def test_a_claude_code_server_disabled_in_settings_is_said(healthy):
    (healthy / ".mcp.json").write_text(json.dumps({"mcpServers": {
        "valvur": {"command": "uvx", "args": ["--from", "valvur", "valvur-mcp"]}}}))
    (healthy / ".claude").mkdir()
    (healthy / ".claude" / "settings.local.json").write_text(json.dumps({
        "disabledMcpjsonServers": ["valvur"]}))

    mcp = _by_name(doctor.run(healthy))["mcp"]

    assert (".mcp.json: valvur (uvx --from valvur valvur-mcp), DISABLED in "
            ".claude/settings.local.json") in mcp.detail


def test_kiro_with_mcp_switched_off_entirely_is_said(healthy):
    kiro = healthy / ".kiro" / "settings"
    kiro.mkdir(parents=True)
    (kiro / "mcp.json").write_text(json.dumps({"mcpServers": {
        "valvur": {"command": "uvx", "args": ["--from", "valvur", "valvur-mcp"]}}}))
    (healthy / ".vscode").mkdir()
    (healthy / ".vscode" / "settings.json").write_text(json.dumps({
        "kiroAgent.configureMCP": "Disabled"}))

    mcp = _by_name(doctor.run(healthy))["mcp"]

    assert "kiroAgent.configureMCP is Disabled in .vscode/settings.json" in mcp.detail


def test_no_client_configuration_is_information_not_failure(healthy):
    mcp = _by_name(doctor.run(healthy))["mcp"]

    assert mcp.level == "info"
    assert "no MCP client configuration names valvur" in mcp.detail
    assert "the CLI needs none" in mcp.detail


def test_a_configuration_that_is_not_json_is_named_rather_than_crashing(healthy):
    (healthy / ".mcp.json").write_text("{ not json")

    mcp = _by_name(doctor.run(healthy))["mcp"]

    assert ".mcp.json: unreadable" in mcp.detail


# --------------------------------------------------------------------- network


def test_the_network_is_probed_only_when_asked_and_per_purpose(healthy, monkeypatch):
    probed: list[str] = []

    def reachable(host, port=443):
        probed.append(host)
        return host != "api.first.org"

    monkeypatch.setattr(doctor, "_reachable", reachable)

    network = _by_name(doctor.run(healthy, network=True))["network"]

    assert network.level == "warn"
    assert ("first run and `valvur update`: ghcr.io, mirror.gcr.io, www.cisa.gov "
            "reachable") in network.detail
    assert "`full`: api.first.org UNREACHABLE" in network.detail
    assert "pypi.org" in probed and "registry.npmjs.org" in probed and "api.osv.dev" in probed
    assert "full" in network.fix and "offline" in network.fix


def test_mirrors_are_probed_in_place_of_the_public_hosts(healthy, monkeypatch):
    probed: list[str] = []
    monkeypatch.setattr(doctor, "_reachable",
                        lambda host, port=443: probed.append((host, port)) or True)
    monkeypatch.setenv("VALVUR_DB_REPOSITORY", "registry.internal:5000/mirror/trivy-db:2")
    monkeypatch.setenv(name_index.reader.INDEX_REPOSITORY_ENV, "registry.internal:5000/mirror/idx")
    monkeypatch.setenv("VALVUR_KEV_URL", "http://files.internal/kev.json")
    monkeypatch.setenv("VALVUR_IMAGE", "registry.internal:5000/mirror/valvur:0.2.0")

    doctor.run(healthy, network=True)

    assert ("registry.internal", 5000) in probed and ("files.internal", 80) in probed
    hosts = [host for host, _ in probed]
    assert "mirror.gcr.io" not in hosts and "ghcr.io" not in hosts and "www.cisa.gov" not in hosts


def test_a_first_run_host_that_is_unreachable_fails_when_a_fetch_is_due(healthy, monkeypatch):
    import shutil
    shutil.rmtree(cache.trivy_db())
    monkeypatch.setattr(doctor, "_reachable", lambda host, port=443: host != "mirror.gcr.io")

    checks = doctor.run(healthy, network=True)

    assert _by_name(checks)["network"].level == "fail"
    assert doctor.failed(checks)


def test_reachable_is_a_bounded_tcp_connect(monkeypatch):
    import socket

    calls: list[tuple] = []

    class Sock:
        def close(self):
            calls.append("closed")

    def connect(address, timeout):
        calls.append((address, timeout))
        if address[0] == "down.invalid":
            raise OSError("no route")
        return Sock()

    monkeypatch.setattr(socket, "create_connection", connect)

    assert doctor._reachable("up.example") is True
    assert doctor._reachable("down.invalid") is False
    assert calls == [(("up.example", 443), 3.0), "closed", (("down.invalid", 443), 3.0)]


# ------------------------------------------------------------ the two surfaces


def test_the_cli_prints_the_report_and_exits_non_zero_only_on_a_failure(
    healthy, monkeypatch, capsys
):
    from valvur import cli

    assert cli.main(["doctor", str(healthy)]) == 0
    assert "ready: a scan will run here." in capsys.readouterr().out

    monkeypatch.setattr(doctor, "_find_runtime",
                        lambda: (_ for _ in ()).throw(RuntimeError("no runtime")))
    assert cli.main(["doctor", str(healthy)]) == 1
    out = capsys.readouterr().out
    assert "FAIL  runtime" in out and "not ready" in out
    assert "\n        fix: install Docker or Podman" in out


def test_the_mcp_tool_is_the_same_report(healthy):
    from valvur.mcp.tools import registry
    from valvur.operations import doctor as doctor_tool

    [tool] = [t for t in registry() if t.name == "doctor"]
    assert tool.handler is doctor_tool
    assert tool.schema["properties"]["network"]["type"] == "boolean"

    text = doctor_tool({"workspace": str(healthy)})

    assert text == doctor.render(doctor.run(healthy), healthy)


def test_a_failed_scan_points_the_agent_at_doctor(tmp_path, monkeypatch):
    """The `scan_status` failure branch names the tool, so an agent whose first scan
    failed has somewhere to go other than the user."""
    import time

    from valvur.mcp import jobs
    from valvur.operations import scan_status

    monkeypatch.setattr(jobs, "STATUS_WAIT_SECONDS", 0.1)

    def work(workspace, profile, progress):
        raise RuntimeError("No container runtime found.")

    jobs.start(tmp_path, "offline", work)
    time.sleep(0.2)
    status = scan_status({"workspace": str(tmp_path)})
    jobs.reset()

    assert status.startswith("FAILED after")
    assert "No container runtime found." in status
    assert "`doctor`" in status and "valvur doctor" in status


def test_doctor_writes_nothing_and_opens_no_socket_unless_asked(healthy, monkeypatch):
    """Read-only with respect to the Workspace and the cache (F1.1, F9.2); the
    `healthy` fixture already fails the test on any probe."""
    before = sorted(p.relative_to(healthy) for p in healthy.rglob("*"))
    cache_before = sorted(p.relative_to(cache.root()) for p in cache.root().rglob("*"))

    doctor.run(healthy)

    assert sorted(p.relative_to(healthy) for p in healthy.rglob("*")) == before
    assert sorted(p.relative_to(cache.root()) for p in cache.root().rglob("*")) == cache_before


# ------------------------------------------------- which way the imports point


def test_doctor_imports_without_the_cli(tmp_path):
    """27.3.1. `doctor` is a pre-flight diagnostic; `cli` is an entry point. The
    KEV constants lived in `cli`, so `doctor` reached up into the layer above it
    to answer which hosts a first run touches — and could not be imported without
    dragging the whole CLI tree in. A subprocess, because `sys.modules` in this
    one is full of everything the suite has already imported."""
    import subprocess
    import sys

    probe = tmp_path / "probe.py"
    probe.write_text(
        # The KEV import was lazy, inside the check, so importing the module was
        # never enough to see it: the hosts have to be ASKED for, and only then is
        # `sys.modules` worth looking at. Written the other way round first, and it
        # passed against the defect it was written for.
        "import sys\n"
        "import valvur.doctor\n"
        "hosts = valvur.doctor._first_run_hosts()\n"
        "assert hosts, 'the hosts are still answered'\n"
        "assert any(h == 'www.cisa.gov' for h, _ in hosts), hosts\n"
        "assert 'valvur.cli' not in sys.modules, 'asking doctor a question pulled in cli'\n"
        "print('ok')\n"
    )
    done = subprocess.run([sys.executable, str(probe)], capture_output=True, text=True,
                          timeout=60, check=False)

    assert done.returncode == 0, done.stderr
    assert done.stdout.strip() == "ok"


def test_nothing_but_the_entry_points_imports_the_cli():
    """The ratchet, over the package's own import graph: `cli` is where a person's
    command line becomes calls, and a module that imports it has either put
    presentation below the logic or taken a constant from the wrong home. The two
    exceptions are the entry points themselves."""
    import ast

    source = Path(__file__).resolve().parent.parent / "src" / "valvur"
    allowed = {"__main__.py", "cli.py"}
    offenders = []
    for path in sorted(source.rglob("*.py")):
        if path.name in allowed:
            continue
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and (node.module or "").endswith("cli"):
                offenders.append(f"{path.relative_to(source)}:{node.lineno}")
            if isinstance(node, ast.Import):
                offenders += [f"{path.relative_to(source)}:{node.lineno}"
                              for alias in node.names if alias.name.endswith("valvur.cli")]

    assert not offenders, f"these import the CLI: {offenders}"


def test_doctor_names_a_memory_ceiling_it_could_not_apply(healthy, monkeypatch):
    """28.0.3. Rootless Podman on cgroup v1 refuses `--memory`, so the runner drops
    the memory half of the ceiling there; a user on such a host is told, in the
    runtime line, rather than left to assume every Scanner is bounded."""
    from valvur import doctor, runner

    monkeypatch.setattr(runner, "memory_ceiling_note",
                        lambda rt: "memory ceiling not applied: rootless Podman on cgroup v1 "
                                   "refuses --memory; the PID limit and no-new-privileges "
                                   "still hold")
    _, check = doctor._check_runtime()

    assert check.level == "ok"
    assert "memory ceiling not applied" in check.detail
    assert "PID limit" in check.detail


def test_doctor_says_nothing_about_the_ceiling_where_it_applies(healthy, monkeypatch):
    from valvur import doctor, runner

    monkeypatch.setattr(runner, "memory_ceiling_note", lambda rt: None)
    _, check = doctor._check_runtime()

    assert check.level == "ok" and "ceiling" not in check.detail
