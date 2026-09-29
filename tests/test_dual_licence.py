"""R10.7: a dual licence is one licence (the Score's corpus labels, R9.5).

ripgrep declares `Unlicense OR MIT` in `Cargo.toml`, and its `COPYING` says it is
"dual-licensed under the Unlicense and MIT licenses". The licence-file Check read
the file as MIT and reported a contradiction at medium: one of the 24 false alarms on
the corpus, and the only one valvur owns outright.
"""

from __future__ import annotations

import json
from pathlib import Path

from valvur.checks.licence_file import LicenceFileCheck


def _repo(root: Path, files: dict[str, str]) -> Path:
    for name, body in files.items():
        (root / name).write_text(body)
    return root


def test_a_licence_file_naming_one_of_an_or_expression_matches_it(tmp_path):
    repo = _repo(tmp_path, {
        "Cargo.toml": '[package]\nname = "rg"\nlicense = "Unlicense OR MIT"\n',
        "COPYING": "This project is dual-licensed under the Unlicense and MIT licenses.\n\n"
                   "You may use this code under the terms of either license.\n"})

    assert LicenceFileCheck().run(repo) == []


def test_cargo_s_older_slash_form_is_the_same_expression(tmp_path):
    repo = _repo(tmp_path, {
        "Cargo.toml": '[package]\nname = "x"\nlicense = "MIT/Apache-2.0"\n',
        "LICENSE": "MIT License\n\nPermission is hereby granted, free of charge, ...\n"})

    assert LicenceFileCheck().run(repo) == []


def test_a_real_contradiction_still_reports(tmp_path):
    repo = _repo(tmp_path, {
        "package.json": json.dumps({"name": "x", "license": "MIT"}),
        "LICENSE": "                                 Apache License\n"
                   "                           Version 2.0, January 2004\n"})

    [finding] = LicenceFileCheck().run(repo)
    assert finding["rule"] == "valvur.licence.mismatch"
