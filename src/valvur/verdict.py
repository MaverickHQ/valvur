"""What counts toward the verdict (D52b, F7.16): one predicate, for a Finding in
memory and for a record read back from `findings.json`.

A **suppressed** Finding is a risk the project recorded a decision about: still
reported, never hidden, and not a live problem. A **coverage note** is valvur's own
limit, not the user's defect: counting "we have no existence check for Rust" against
their code would make the verdict permanently negative for something they cannot
fix (task 19.C.1). Neither is active. Until R23.6 six modules decided this each its
own way.
"""

from __future__ import annotations

from typing import Any

RULE = "valvur.dependency.ecosystem-not-covered"
#: Dependencies present, but nothing Trivy reads for vulnerabilities — no lockfile.
#: Found by the public corpus on its first run: Express read `clean` (task 22.E.1).
VULNERABILITY_RULE = "valvur.dependency.vulnerabilities-unchecked"
#: Statements about what valvur could *read* of the licences, not about the code
#: (task 23.5.5). "Licences could not be determined for 600 of 618 dependencies" is a
#: fact about the lockfile's metadata; "no known licence signature matched" is a fact
#: about our signatures. Measured on the corpus: an active Finding on eight of twelve
#: real repositories, and one read `findings` on nothing else.
LICENCE_STATEMENT_RULES = frozenset({
    "valvur.licence.dependencies-unreadable",
    "valvur.licence.dependency-unknown",
    "valvur.licence.unidentified",
})
#: A private registry's packages, which valvur does not look up publicly (R10.3,
#: D27). A statement about where the project installs from; it casts no doubt on a
#: verdict, because a name bound to a private registry cannot be taken publicly.
PRIVATE_RULE = "valvur.dependency.private-registry"
#: Every rule that is a statement about valvur rather than about the scanned code.
#: Never active: none of them makes a status `findings` or fails a gate.
NOTE_RULES = frozenset({RULE, VULNERABILITY_RULE, PRIVATE_RULE}) | LICENCE_STATEMENT_RULES
#: The notes that make a nil result `inconclusive` — we did not look, so `clean` is
#: not ours to claim. A licence statement is deliberately not one: a licence we could
#: not read is not a vulnerability we did not look for, and the verdict is about
#: security. The two sets are pinned apart by test, so a new note has to choose.
DOUBT_RULES = frozenset({RULE, VULNERABILITY_RULE})


def _field(finding: Any, name: str) -> Any:
    return finding.get(name) if isinstance(finding, dict) else getattr(finding, name)


def note(finding: Any) -> bool:
    """A statement about valvur, suppressed or not."""
    return _field(finding, "rule") in NOTE_RULES


def active(finding: Any) -> bool:
    """About the scanned project, live: neither suppressed nor a coverage note."""
    return not _field(finding, "suppressed") and not note(finding)
