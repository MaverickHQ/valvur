"""R29.2: three of valvur's own licence false positives, found by the wider corpus.

The licence-file Check reported on three maintained projects what was not so: got's
licence is in `license`, lowercase, which the Check did not look for; aiohttp declares
`Apache-2.0 AND MIT` for the MIT code it vendors, and its LICENSE.txt is the Apache
half; and MkDocs's LICENSE is BSD-2-Clause, which the Check read as BSD-3-Clause and
called a contradiction of what MkDocs declares.
"""

from __future__ import annotations

from pathlib import Path

from valvur.checks.licence_file import LicenceFileCheck

MIT = "MIT License\n\nPermission is hereby granted, free of charge, to any person ...\n"
APACHE = "                                 Apache License\n           Version 2.0, January 2004\n"
BSD = ("Copyright (c) 2014, someone.\n\nRedistribution and use in source and binary forms, "
       "with or without modification, are permitted provided that the following conditions "
       "are met:\n\nRedistributions of source code must retain the above copyright notice, "
       "this list of conditions and the following disclaimer.\nRedistributions in binary "
       "form must reproduce the above copyright notice.\n")
THIRD = ("Neither the name of the copyright holder nor the names of its contributors may be "
         "used to endorse or promote products derived from this software.\n")


def _repo(root: Path, files: dict[str, str]) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    for name, body in files.items():
        (root / name).write_text(body)
    return root


def test_a_lowercase_licence_file_is_found(tmp_path):
    repo = _repo(tmp_path, {"license": MIT, "package.json": '{"license": "MIT"}'})

    assert LicenceFileCheck().run(repo) == []


def test_a_file_holding_one_part_of_an_and_expression_agrees_with_it(tmp_path):
    repo = _repo(tmp_path, {"LICENSE.txt": APACHE,
                            "pyproject.toml": 'license = "Apache-2.0 AND MIT"\n'})

    assert LicenceFileCheck().run(repo) == []


def test_two_clause_bsd_is_told_from_three(tmp_path):
    two = _repo(tmp_path / "two", {"LICENSE": BSD,
                                   "pyproject.toml": 'license = "BSD-2-Clause"\n'})
    three = _repo(tmp_path / "three", {"LICENSE": BSD + THIRD,
                                       "pyproject.toml": 'license = "BSD-3-Clause"\n'})
    crossed = _repo(tmp_path / "crossed", {"LICENSE": BSD,
                                           "pyproject.toml": 'license = "BSD-3-Clause"\n'})

    assert LicenceFileCheck().run(two) == []
    assert LicenceFileCheck().run(three) == []
    [finding] = LicenceFileCheck().run(crossed)
    assert finding["rule"] == "valvur.licence.mismatch" and "BSD-2-Clause" in finding["title"]
