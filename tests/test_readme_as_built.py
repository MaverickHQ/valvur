"""R7.1: the README, rewritten against what exists (P6).

Three behaviours, each held here rather than by reading its prose: every number
the README cites is the acceptance set's or the code's own limit, its tool table
is the image's Scanners and Checks, and its client table is the one `doctor`
reads.
"""

from __future__ import annotations

from pathlib import Path

from valvur.mcp import clients

REPO = Path(__file__).resolve().parent.parent
README = REPO / "README.md"


def test_the_client_block_keeps_each_notes_case():
    """`str.capitalize()` lowercased every note after its first letter, so the README
    told Kiro's users to enable `kiroagent.configuremcp` and VS Code's that the key
    is not `mcpservers`. Only the first letter changes."""
    block = clients.readme_section()

    for entry in clients.CLIENTS:
        assert entry.after[1:] in block, entry.key
        assert entry.verified[1:] in block, entry.key
