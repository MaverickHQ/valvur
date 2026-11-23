"""Where valvur stops following a model's output (R49.7, D82j, Requirement 6).

The `valvur.llm.*` rules follow a model's output to a sink inside one function. A flow that
passes through a call to another function is not followed, and five published advisories
are of that shape. So one rule, `valvur.llm.model-call`, marks where a model is called and
reports nothing by itself: its Findings never leave this module. When a Scan Run has a
model call and a sink to review, and no flow between them was reported, it gains one
coverage note that says so. A note, and not a doubt: a project that calls a model can
still be `clean`.
"""

from __future__ import annotations

from . import fingerprint as _fp
from .findings import Finding, Severity
from .verdict import MODEL_OUTPUT_RULE

CALL_RULE = "valvur.llm.model-call"
#: The rules that report a flow from a model call into a sink.
_FLOW = ("valvur.llm.output-", "valvur.js.output-")


def apply(findings: list[Finding]) -> list[Finding]:
    """The Findings without the model-call marks, and with the note when a model is
    called, a sink is named and no flow joins them."""
    calls = sorted({f.path for f in findings if f.rule == CALL_RULE})
    kept = [f for f in findings if f.rule != CALL_RULE]
    if not calls or not any(f.inventory for f in kept) \
            or any(f.rule.startswith(_FLOW) for f in kept):
        return kept
    shown = ", ".join(calls[:5]) + (f" and {len(calls) - 5} more" if len(calls) > 5 else "")
    return [*kept, Finding(
        rule=MODEL_OUTPUT_RULE, path=calls[0], line=0, severity=Severity.LOW,
        title=f"This project calls a model in at least {len(calls)} file(s). valvur follows "
              "a model's output to a sink inside one function, and not through a call to another",
        evidence=f"A model is called in {shown}, and this scan lists code-execution, shell or "
                 "query sinks to review. No flow between them was reported, which is not "
                 "the same as none existing: read the sinks with the model's output in mind.",
        fingerprint=_fp.derive("model_output_not_followed", "project"),
        sources=("opengrep",))]
