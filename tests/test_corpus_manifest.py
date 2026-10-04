"""R29.2: a wider corpus (D65a).

Track 8 judged 16 findings on 13 projects, too few to tell one rule from another. The
corpus is now at least 40 real projects, mostly Python and JavaScript or TypeScript,
the languages valvur's own rules cover. Each is pinned by commit, with its licence read
from its own checkout and its size recorded, and fetched into the build cache, never
into the tree.
"""

from __future__ import annotations

import importlib.util
import re
import tomllib
from collections import Counter
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
ENTRIES = tomllib.loads((REPO / "tests" / "corpus" / "corpus.toml").read_text())["repo"]

#: Permissive licences only (D65a): the corpus is someone else's code, read and judged,
#: and its findings are quoted in labels and records.
LICENCES = {"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "CC0-1.0",
            "Unlicense", "0BSD"}
LANGUAGES = {"python", "javascript", "typescript", "go", "java", "rust", "ruby", "php",
             "terraform", "markdown"}
#: A checkout over this is too much of someone else's code for one track's runtime.
MAX_MB = 50


def _harness():
    spec = importlib.util.spec_from_file_location("corpus_harness",
                                                  REPO / "scripts" / "corpus.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_at_least_forty_projects_each_named_once():
    names = [e["name"] for e in ENTRIES]

    assert len(names) >= 40
    assert len(set(names)) == len(names)


@pytest.mark.parametrize("entry", ENTRIES, ids=lambda e: e["name"])
def test_every_entry_is_pinned_with_its_licence_language_and_size(entry):
    assert re.fullmatch(r"https://github\.com/[\w.-]+/[\w.-]+", entry["url"])
    assert re.fullmatch(r"[0-9a-f]{40}", entry["commit"]), "pinned by commit"
    assert entry["licence"] in LICENCES
    assert entry["language"] in LANGUAGES
    assert isinstance(entry["size_mb"], (int, float)) and 0 < entry["size_mb"] <= MAX_MB
    assert entry["why"].strip()


def test_most_are_in_the_languages_valvur_s_rules_cover():
    languages = Counter(e["language"] for e in ENTRIES)

    assert languages["python"] >= 15
    assert languages["javascript"] + languages["typescript"] >= 15


def test_the_checkouts_live_in_the_build_cache_never_in_the_tree(monkeypatch, tmp_path):
    monkeypatch.delenv("VALVUR_CORPUS", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    assert _harness().checkouts() == tmp_path / ".cache" / "valvur-build" / "corpus"

    monkeypatch.setenv("VALVUR_CORPUS", str(tmp_path / "elsewhere"))
    assert _harness().checkouts() == tmp_path / "elsewhere"


def test_a_tenth_of_the_labels_is_drawn_for_the_owner_to_audit_the_same_each_time():
    labels = tomllib.loads((REPO / "tests" / "eval" / "labels" / "corpus.toml")
                           .read_text())["label"]
    spec = importlib.util.spec_from_file_location("audit_sample",
                                                  REPO / "scripts" / "audit_sample.py")
    audit = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(audit)

    drawn = audit.sample(labels)

    assert len(drawn) == -(-len(labels) // 10)
    assert drawn == audit.sample(list(reversed(labels))), "the order read changes nothing"
    tasks = (REPO / ".kiro" / "specs" / "valvur" / "tasks.md").read_text()
    assert "scripts/audit_sample.py" in tasks.split("## 8. The owner queue", 1)[1]


def test_every_label_matches_a_project_in_the_corpus():
    labels = tomllib.loads((REPO / "tests" / "eval" / "labels" / "corpus.toml")
                           .read_text())["label"]

    assert {label["repo"] for label in labels} <= {e["name"] for e in ENTRIES}
