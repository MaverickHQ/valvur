"""R6.7: two settings files (D11).

Project policy is `.security-scan.toml`, committed; machine settings are
`~/.config/valvur/config.toml` (or under `$XDG_CONFIG_HOME`). Environment
variables stay as overrides for the image, the cache, the runtime, debugging,
fetching and the mirrors; the others are retired to the file, still work for one
release, and say so once. `doctor` prints what is in effect and where it came from.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from valvur import settings

RETIRED = {"VALVUR_JOBS": ("jobs", "3"), "VALVUR_CONTAINER_NETWORK": ("container_network", "proxy"),
           "VALVUR_SELINUX_RELABEL": ("selinux_relabel", "1")}


@pytest.fixture
def config(tmp_path, monkeypatch) -> Path:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    for name in (*settings.ENVIRONMENT.values(),):
        monkeypatch.delenv(name, raising=False)
    settings.reset()
    path = tmp_path / "xdg" / "valvur" / "config.toml"
    path.parent.mkdir(parents=True)
    yield path
    settings.reset()


def test_machine_settings_are_read_from_the_config_file(config):
    config.write_text('fetch = "never"\njobs = 2\nkev_url = "http://mirror.internal/kev.json"\n')

    assert settings.fetch() == settings.NEVER
    assert settings.get("jobs") == "2"
    assert settings.get("kev_url") == "http://mirror.internal/kev.json"
    assert settings.source("fetch") == str(config)


def test_an_override_wins_over_the_file_and_says_where_it_came_from(config, monkeypatch):
    config.write_text('fetch = "never"\n')
    monkeypatch.setenv("VALVUR_FETCH", "auto")

    assert settings.fetch() == "auto"
    assert settings.source("fetch") == "VALVUR_FETCH"


@pytest.mark.parametrize("name", sorted(RETIRED))
def test_a_retired_variable_still_works_and_says_so_once(config, monkeypatch, capsys, name):
    key, value = RETIRED[name]
    monkeypatch.setenv(name, value)

    assert settings.get(key) == value
    assert settings.get(key) == value
    said = [line for line in capsys.readouterr().err.splitlines() if name in line]

    assert len(said) == 1, said
    assert f"{key} = " in said[0] and "config.toml" in said[0]


def test_an_override_says_nothing(config, monkeypatch, capsys):
    monkeypatch.setenv("VALVUR_IMAGE", "valvur:dev")

    assert settings.get("image") == "valvur:dev"
    assert capsys.readouterr().err == ""


def test_doctor_prints_the_effective_settings_and_where_each_came_from(config, monkeypatch,
                                                                         tmp_path):
    from valvur import doctor

    config.write_text('fetch = "never"\n')
    monkeypatch.setenv("VALVUR_IMAGE", "valvur:dev")

    [line] = [c for c in doctor.run(tmp_path) if c.name == "settings"]

    assert "fetch = never (" + str(config) + ")" in line.detail
    assert "image = valvur:dev (VALVUR_IMAGE)" in line.detail


def test_an_unreadable_config_file_is_said_and_not_a_crash(config):
    config.write_text("fetch = [unclosed\n")

    assert settings.get("fetch") is None
    assert "cannot be read" in settings.problem()
