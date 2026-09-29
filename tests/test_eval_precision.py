"""R9.5: real-code precision, the Score's eighth track (ADR-0026, D21).

On the corpus, every active finding of a rule valvur owns, or of Gitleaks, is
labelled `tp` or `fp` with a reason. The track is precision times 100. A finding with
no label fails the track and is named; other Scanners' findings are counted.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

EVAL = Path(__file__).resolve().parent.parent / "scripts" / "eval"


def _precision():
    spec = importlib.util.spec_from_file_location("precision", EVAL / "precision.py")
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules["precision"] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def _f(fingerprint: str, rule: str, source: str, **extra) -> dict:
    return {"fingerprint": fingerprint, "rule": rule, "path": "x.py", "sources": [source],
            "suppressed": None, "status": "new", **extra}


LABELS = """
[[label]]
repo = "flask"
fingerprint = "a1"
rule = "valvur.python.dangerous-exec"
verdict = "fp"
reason = "Flask loads its own config files with exec; that is the feature."

[[label]]
repo = "requests"
fingerprint = "b2"
rule = "private-key"
verdict = "tp"
reason = "A key committed to the tree; rotate it even if it is a test key."
"""


def test_precision_over_the_labelled_findings_of_valvur_s_rules_and_gitleaks(tmp_path):
    p = _precision()
    (tmp_path / "labels.toml").write_text(LABELS)
    labels = p.load(tmp_path / "labels.toml")

    result = p.judge({"flask": [_f("a1", "valvur.python.dangerous-exec", "opengrep"),
                                _f("c3", "CVE-2023-30861", "trivy")],
                      "requests": [_f("b2", "private-key", "gitleaks")]}, labels)

    assert (result.tp, result.fp, result.score) == (1, 1, 50.0)
    assert result.unlabelled == []
    assert result.others == {"trivy": 1}


def test_an_unlabelled_finding_fails_the_track_and_is_named(tmp_path):
    p = _precision()
    (tmp_path / "labels.toml").write_text(LABELS)

    result = p.judge({"flask": [_f("a1", "valvur.python.dangerous-exec", "opengrep"),
                                _f("zz", "valvur.python.weak-hash", "opengrep",
                                   path="src/flask/sessions.py")]},
                     p.load(tmp_path / "labels.toml"))

    assert result.unlabelled == ["flask: valvur.python.weak-hash at src/flask/sessions.py (zz)"]


def test_a_label_without_a_reason_or_a_verdict_is_refused(tmp_path):
    p = _precision()
    (tmp_path / "labels.toml").write_text(
        '[[label]]\nrepo = "flask"\nfingerprint = "a1"\nrule = "r"\nverdict = "maybe"\n')

    with pytest.raises(ValueError, match="flask a1"):
        p.load(tmp_path / "labels.toml")
