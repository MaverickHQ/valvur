"""26.2.2 — one authority on what leaves the machine (N2.1, ADR-0010).

The decision was `profiles.ALLOWS_NETWORK`; six places restated it — the runner's
flag builder, Gitleaks' own hard-coded flag (gone with 26.2.1), the two probes in
`compat.py` and `doctor.py`, `doctor.FULL_HOSTS`, and `run.json`'s
`what_left_the_machine` sentence — and 23.5.4 found the sentence had lagged the
truth for a week. Now `egress.py` answers all of it from one table: whether a
Profile has a network, the container flag that enforces it, the hosts it may
reach, and the sentence that discloses them. Everything else calls in.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

from valvur import egress, profiles

# ---------------------------------------------------------------- one table


@pytest.mark.parametrize("profile", [profiles.OFFLINE, profiles.FULL, "quick", "standard"])
def test_the_profile_table_and_the_egress_answer_agree(profile):
    e = egress.for_profile(profile)
    assert e.network is profiles.ALLOWS_NETWORK[profiles.resolve(profile)]


def test_offline_is_no_interface_no_hosts_and_the_word_nothing(monkeypatch):
    monkeypatch.delenv(egress.CONTAINER_NETWORK_ENV, raising=False)
    e = egress.for_profile(profiles.OFFLINE)

    assert e.network is False
    assert e.container_flags() == ["--network=none"]
    assert e.hosts() == ()
    assert egress.disclosure(used=False) == "nothing"


def test_full_is_told_not_probed_and_reaches_exactly_the_listed_hosts(monkeypatch):
    monkeypatch.delenv(egress.CONTAINER_NETWORK_ENV, raising=False)
    monkeypatch.delenv(egress.DB_REPOSITORY_ENV, raising=False)
    e = egress.for_profile(profiles.FULL)

    flags = e.container_flags()
    assert "--network=none" not in flags
    assert flags[:2] == ["--env", f"{egress.NETWORK_ENV}=1"], flags
    assert e.hosts() == egress.FULL_HOSTS
    assert len(egress.FULL_HOSTS) == 10


def test_a_networked_container_joins_the_named_network_and_carries_the_mirror(monkeypatch):
    """Both settings the air-gapped guide documents, applied only with a network:
    the user-defined network the mirror lives on, and the mirror itself, handed
    to Trivy inside the container."""
    monkeypatch.setenv(egress.CONTAINER_NETWORK_ENV, "airgap")
    monkeypatch.setenv(egress.DB_REPOSITORY_ENV, "registry.internal/trivy-db:2")

    full = egress.for_profile(profiles.FULL).container_flags()
    offline = egress.for_profile(profiles.OFFLINE).container_flags()

    assert "--network=airgap" in full
    assert ["--env", f"{egress.DB_REPOSITORY_ENV}=registry.internal/trivy-db:2"] == full[2:4]
    assert offline == ["--network=none"], "a scan container never joins anything"


def test_the_disclosure_names_every_host_full_may_reach():
    """The sentence IS the non-exfiltration claim (§3). A host added to the list
    without a name in the sentence is the drift 23.5.4 found — three registries
    missing for a week — so the two are held together here."""
    sentence = egress.disclosure(used=True)

    for host, spoken_as in egress.SPOKEN_AS.items():
        assert spoken_as in sentence, f"{host} ({spoken_as!r}) is not disclosed"
    assert set(egress.SPOKEN_AS) == set(egress.FULL_HOSTS), "a host has no spoken name"
    assert "Never source code" in sentence


# ------------------------------------------------------ everything else calls in


def test_no_code_outside_egress_carries_the_network_flag_literal():
    """The flag is written in one place. A second copy is a second decision.
    `scripts/verify-offline.py` is exempt on purpose: it is the reviewer's
    independent check and must keep the literal, or it would only be asking
    egress whether egress agrees with itself."""
    offenders = []
    for path in Path("src/valvur").rglob("*.py"):
        if path.name == "egress.py":
            continue
        for number, line in enumerate(path.read_text().splitlines(), start=1):
            if re.search(r'"--network=', line):
                offenders.append(f"{path}:{number}")
    assert offenders == [], f"the network flag is written outside egress.py: {offenders}"


def test_the_runner_and_both_probes_launch_with_egress_flags(monkeypatch, tmp_path):
    from valvur import compat, doctor
    from valvur.runner import ContainerRunner

    launched: list[list[str]] = []

    def capture(cmd, **kwargs):
        launched.append(list(cmd))
        return subprocess.CompletedProcess(cmd, 0, "abc\n", "")

    from valvur import cache

    monkeypatch.setattr(subprocess, "run", capture)
    monkeypatch.setattr(cache, "root", lambda: tmp_path / "cache")

    runner = ContainerRunner(image="x/y:1", runtime="/usr/local/bin/docker")
    runner._base_flags(tmp_path, str(tmp_path / "scratch"), network=False)
    compat.image_inputs("/usr/local/bin/docker", "x/y:1")
    doctor._image_starts("/usr/local/bin/docker", "x/y:1")

    probes = [cmd for cmd in launched if "--entrypoint" in cmd]
    assert len(probes) == 2, launched
    for cmd in probes:
        assert "--network=none" in cmd, cmd


def test_run_json_discloses_what_egress_says(workspace, runner_finding_nothing):
    import json

    from valvur import scan

    scan(workspace, runner=runner_finding_nothing, profile=profiles.OFFLINE)
    run = json.loads((workspace / ".security-scan" / "run.json").read_text())

    assert run["network"]["what_left_the_machine"] == egress.disclosure(used=False)


def test_doctor_reaches_the_hosts_egress_lists():
    from valvur import doctor

    assert doctor.FULL_HOSTS is egress.FULL_HOSTS
