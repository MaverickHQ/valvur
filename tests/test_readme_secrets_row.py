"""R1.7: the README says what the secrets step reads (P2; the owner's C10).

Gitleaks runs in `dir` mode and the image has no `git` (ADR-0005), so no scan has
ever read a commit; the README's tool table said *Secrets, including git history*.
The row follows the adapter: while the mode is `dir`, the row claims no history.
R3.7 scans history and restores the claim with the mode that earns it.
"""

from __future__ import annotations

from pathlib import Path

README = Path(__file__).resolve().parent.parent / "README.md"


def test_the_readmes_gitleaks_row_claims_only_what_the_adapter_reads(tmp_path):
    from valvur.adapters import GitleaksAdapter

    mode = GitleaksAdapter().command(tmp_path).argv[1]
    row = next(line for line in README.read_text().splitlines()
               if line.startswith("| [Gitleaks]"))
    if mode == "dir":
        assert "history" not in row.lower(), row
