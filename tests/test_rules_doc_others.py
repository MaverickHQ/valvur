"""R48.4: `docs/RULES.md` lists every rule that fired on the corpus, with two measurements (D82a).

The page gave valvur's Opengrep rules alone. Gitleaks', Checkov's and zizmor's rules fire on
the corpus too, and the reader had no number for them. Each gets a row: its counts on
maintained code, from the eighth track's labels, apart from its counts on the planted
tracks, where a Finding on a vulnerable case is true and one on a safe case is false.
"""

from __future__ import annotations

import json

from test_eval_run import _flag_the_config_files, _harness
from test_rules_doc import _doc, _measured, _row


def test_a_run_counts_another_scanners_rule_on_the_planted_cases(tmp_path):
    """The secrets track plants 20 secrets, 10 of them in files under `config/`, which the
    faked Gitleaks finds, and 20 placeholders, which it does not."""
    result = _harness().run(["secrets"], tmp_path / "work", scan=_flag_the_config_files,
                            image="valvur:dev", image_id=lambda image: "sha256:abc")

    assert result["planted"] == [
        {"scanner": "gitleaks", "rule": "generic-api-key", "tp": 10, "fp": 0}]


def _report() -> dict:
    return {
        "image": {"id": "sha256:abc"},
        "rules": {"valvur.a": {"places": {place: {} for place in (
            "sast-python", "sast-js", "corpus", "llm-output")}}},
        "planted": [{"scanner": "gitleaks", "rule": "private-key", "tp": 2, "fp": 0},
                    {"scanner": "gitleaks", "rule": "never-on-the-corpus", "tp": 4, "fp": 0}],
        "tracks": {"real-code-precision": {
            "repositories": 48,
            "by_rule": [{"scanner": "gitleaks", "rule": "private-key", "tp": 0, "fp": 35},
                        {"scanner": "opengrep", "rule": "valvur.a", "tp": 1, "fp": 1}],
            "hygiene": [{"scanner": "zizmor", "rule": "unpinned-uses", "findings": 318,
                         "judged": 25, "tp": 24, "fp": 1, "sampled": True}]}}}


def test_the_measurement_holds_a_rules_corpus_counts_apart_from_its_planted_counts(tmp_path):
    path = tmp_path / "rules-measured.json"

    _harness().rules_measured(_report(), path, today="2026-11-22")

    assert json.loads(path.read_text())["others"] == [
        {"scanner": "gitleaks", "rule": "private-key",
         "corpus": {"findings": 35, "judged": 35, "tp": 0, "fp": 35, "sampled": False},
         "planted": {"tp": 2, "fp": 0}},
        {"scanner": "zizmor", "rule": "unpinned-uses",
         "corpus": {"findings": 318, "judged": 25, "tp": 24, "fp": 1, "sampled": True},
         "planted": {"tp": 0, "fp": 0}}]


def _others(*rows: dict) -> dict:
    return {**_measured(valvur_a=_row(tp=9, fp=3)), "others": list(rows)}


def _other(scanner: str, rule: str, corpus: tuple[int, int], planted: tuple[int, int] = (0, 0),
           *, findings: int | None = None) -> dict:
    judged = sum(corpus)
    return {"scanner": scanner, "rule": rule,
            "corpus": {"findings": findings or judged, "judged": judged, "tp": corpus[0],
                       "fp": corpus[1], "sampled": (findings or judged) > judged},
            "planted": {"tp": planted[0], "fp": planted[1]}}


def _line(page: str, rule: str) -> str:
    return next(line for line in page.splitlines() if line.startswith(f"| `{rule}` |"))


def test_the_page_gives_the_two_measurements_in_separate_columns():
    page = _doc().render(_others(_other("gitleaks", "private-key", (0, 35), (2, 0))))

    assert "| rule | Scanner | on maintained code | on planted cases | note |" in page
    assert _line(page, "private-key") == "| `private-key` | Gitleaks | 0 / 35 | 2 / 0 | |"


def test_a_rule_with_fewer_than_five_judged_findings_reads_unmeasured_there():
    page = _doc().render(_others(_other("gitleaks", "jwt", (1, 3)),
                                 _other("gitleaks", "pkcs12-file", (2, 3))))

    assert _line(page, "jwt") == "| `jwt` | Gitleaks | 1 / 3, unmeasured there | 0 / 0 | |"
    assert _line(page, "pkcs12-file") == "| `pkcs12-file` | Gitleaks | 2 / 3 | 0 / 0 | |"
    # And in the first table: a shipped rule's corpus cell, 0 true and 3 false.
    assert "| 9 / 0 | 0 / 0 | 0 / 3, unmeasured there | 0 / 0 | 0.75 | active |" in _line(
        page, "valvur.a")


def test_a_sampled_rule_is_on_the_page_marked_sampled():
    page = _doc().render(_others(_other("checkov", "CKV_DOCKER_2", (24, 1), findings=40)))

    assert _line(page, "CKV_DOCKER_2") == (
        "| `CKV_DOCKER_2` | Checkov | 24 / 1 | 0 / 0 | sampled: 25 of 40 judged |")


def test_the_page_says_four_places_are_summed_for_the_bar():
    page = " ".join(_doc().render(_others()).split())

    assert ("**The bar** is ADR-0029's: at least one true positive and a precision of at least "
            "0.5, over four places summed: tracks 1, 2 and 9 and the corpus.") in page
    assert "over the three" not in page and "any of the three" not in page


def test_a_measurement_written_before_the_second_table_still_renders():
    assert "| rule | Scanner |" not in _doc().render(_measured(valvur_a=_row(tp=9, fp=3)))
