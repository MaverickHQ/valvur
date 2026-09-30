"""R15.4: `valvur init --write` adds the skill (D40, ADR-0031).

Claude Code reads a project's skills from `.claude/skills/<name>/`, and Kiro from
`.kiro/skills/<name>/` (kiro.dev/docs/skills/, read 2026-09-30). `--write` writes the
package's skill there for each client it writes, within the exception `CLAUDE.md`
§10 gives `init --write`, and as it writes everything else: never over a file that is
there. `init` alone says where the skill goes, and `doctor` says whether a project
has it and whether it is this valvur's.
"""

from __future__ import annotations

from pathlib import Path

from test_init import _tree, project  # noqa: F401 — the fixture, registered by import

from valvur import cli, skill


def _copy(root: Path) -> dict[str, bytes]:
    return {p.relative_to(root).as_posix(): p.read_bytes()
            for p in sorted(root.rglob("*")) if p.is_file()}


def test_write_adds_the_skill_for_claude_code_and_for_kiro(project, capsys):  # noqa: F811
    assert cli.main(["init", str(project), "--write",
                     "--client", "claude-code", "--client", "kiro"]) == 0
    out = capsys.readouterr().out

    for where in (".claude/skills/valvur", ".kiro/skills/valvur"):
        assert _copy(project / where) == skill.files(), where
        assert f"wrote the skill to {where}/" in out


def test_by_default_it_follows_the_clients_found_here(project, capsys):  # noqa: F811
    """The fixture's project has `.kiro/` and nothing of Claude Code's."""
    assert cli.main(["init", str(project), "--write"]) == 0

    assert (project / ".kiro" / "skills" / "valvur" / "SKILL.md").is_file()
    assert not (project / ".claude").exists()


def test_the_skill_is_never_written_over_what_is_there(project, capsys):  # noqa: F811
    """A project's own skill of that name, or an older valvur's, is left whole and
    said, its version named; a second `--write` changes nothing."""
    mine = project / ".claude" / "skills" / "valvur" / "SKILL.md"
    mine.parent.mkdir(parents=True)
    mine.write_text('---\nname: valvur\nmetadata:\n  version: "0.9.0"\n---\nmine\n')

    assert cli.main(["init", str(project), "--write", "--client", "claude-code"]) == 0
    out = capsys.readouterr().out

    assert mine.read_text().endswith("mine\n")
    assert _copy(mine.parent) == {"SKILL.md": mine.read_bytes()}
    assert "left .claude/skills/valvur/ as it is: it exists, version 0.9.0" in out
    before = _tree(project)
    assert cli.main(["init", str(project), "--write", "--client", "claude-code"]) == 0
    assert _tree(project) == before


def test_init_alone_names_where_the_skill_goes(project, capsys):  # noqa: F811
    before = _tree(project)

    assert cli.main(["init", str(project)]) == 0
    out = capsys.readouterr().out

    assert _tree(project) == before
    assert "Kiro reads the skill from .kiro/skills/valvur/" in out
    assert "valvur init --write" in out and "/plugin install valvur@valvur" in out
