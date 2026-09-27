"""R1.6: Trivy never reports to its vendor (N2.1, ADR-0010).

Measured 2026-09-27 inside the image: with a network, `trivy fs` logs *Running version
check and sending anonymous telemetry*; with `--disable-telemetry --skip-version-check`
it logs *Version check and telemetry are disabled, skipping request*. Every Trivy scan
runs with no network today, and the one networked Trivy command, the database fetch,
logged no telemetry when run to completion. The flags make that true by construction
rather than by the current code path, before R3.8 adds a networked container.
"""

from __future__ import annotations

FLAGS = ("--disable-telemetry", "--skip-version-check")


def test_every_trivy_command_carries_both_flags(tmp_path, monkeypatch):
    from valvur import cache
    from valvur.adapters import TrivyAdapter
    from valvur.adapters.trivy import database_fetch

    monkeypatch.setattr(cache, "db_present", lambda: True)
    for invocation in (TrivyAdapter().command(tmp_path), database_fetch()):
        for flag in FLAGS:
            assert flag in invocation.argv, (flag, invocation.argv)
