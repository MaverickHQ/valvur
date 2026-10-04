"""What kind of file a path is: its class (D56).

`source`, `test`, `fixture`, `docs`, `example`, `vendored` or `generated`, decided by
whole segments and the file's name, never by substring: the OWASP Benchmark's cases
live in `testcode/`, and `latest/` and `contest/` are source too. `generated` needs
the file or `.gitattributes`, so the File Set adds it (`fileset.classes`); this module
reads nothing. A finding carries its path's class as `context`, which is not identity.
"""

from __future__ import annotations

import re

SOURCE, TEST, FIXTURE, DOCS, EXAMPLE, VENDORED, GENERATED = (
    "source", "test", "fixture", "docs", "example", "vendored", "generated")
CLASSES = (SOURCE, TEST, FIXTURE, DOCS, EXAMPLE, VENDORED, GENERATED)

#: Each directory name that gives a path its class, in the order they are asked: a
#: vendored test is vendored, and a test's fixture is a fixture (D47b's segments).
_DIRECTORIES: tuple[tuple[str, frozenset[str]], ...] = (
    (VENDORED, frozenset({"vendor", "third_party", "node_modules"})),
    (FIXTURE, frozenset({"fixtures", "testdata"})),
    (TEST, frozenset({"tests", "test", "__tests__", "spec"})),
    (EXAMPLE, frozenset({"examples", "example"})),
    (DOCS, frozenset({"docs"})),
)
_TEST_NAME = re.compile(r"^test_|_test\.[^.]+$")


def of(path: str) -> str:
    """`path`'s class, from its segments and its name alone."""
    *directories, name = path.lower().split("/")
    for klass, names in _DIRECTORIES:
        if names.intersection(directories):
            return klass
    return TEST if _TEST_NAME.search(name) else SOURCE
