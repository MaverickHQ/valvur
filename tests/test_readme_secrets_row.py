"""R1.7: the README says what the secrets step reads (P2; the owner's C10).

Gitleaks runs in `dir` mode and the image has no `git` (ADR-0005), so no scan has
ever read a commit; the README's tool table said *Secrets, including git history*.
The row follows the adapter: while there was only the `dir` pass, it claimed no
history. R3.7 added the history pass and restored the claim, with its bounds.
"""

from __future__ import annotations

from pathlib import Path

README = Path(__file__).resolve().parent.parent / "README.md"


def test_the_readmes_gitleaks_row_claims_only_what_the_adapter_reads(tmp_path):
    """Since R3.7 the tree is read in `dir` mode and history by a second pass, so
    the row claims history with the bounds that limit it, and no more."""
    from valvur import history
    from valvur.adapters import GitleaksAdapter

    row = next(line for line in README.read_text().splitlines()
               if line.startswith("| [Gitleaks]"))
    if not hasattr(GitleaksAdapter, "history_command"):
        assert "history" not in row.lower(), row
        return
    assert "git history" in row, row
    assert f"{history.MAX_COMMITS:,} commits" in row, row
    assert f"{history.MAX_BYTES // 2**20} MB" in row, row
