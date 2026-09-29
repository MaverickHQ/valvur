"""R7.2: `verify-mirror.py` permits every mirror a scan can fetch from.

It read three environment variables. Since R4.6 an `offline` scan also fetches
OSV's database for each ecosystem present, from `osv_url` when a mirror is named,
and since R6.7 every mirror may be set in the machine's settings file instead.
The script refused OSV's mirror, so an honest air-gapped setup failed its proof.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "verify-mirror.py"


def _script():
    spec = importlib.util.spec_from_file_location("verify_mirror", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_every_mirror_setting_is_permitted_from_the_file_or_the_environment(
        tmp_path, monkeypatch):
    from valvur import settings

    for name in settings.ENVIRONMENT.values():
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    (tmp_path / "valvur").mkdir()
    (tmp_path / "valvur" / "config.toml").write_text(
        'osv_url = "http://osv.mirror.internal/osv"\n'
        'db_repository = "registry.mirror.internal:5000/trivy-db"\n')
    monkeypatch.setenv("VALVUR_KEV_URL", "http://kev.mirror.internal/kev.json")
    monkeypatch.setenv("VALVUR_EPSS_URL", "http://epss.mirror.internal/epss.csv.gz")

    hosts = _script().mirror_hosts()

    assert {"osv.mirror.internal", "registry.mirror.internal",
            "kev.mirror.internal", "epss.mirror.internal"} <= hosts
