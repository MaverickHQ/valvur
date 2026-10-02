"""R18.2: install commands, read before they run (D44).

The hook sees the text of a shell command an agent is about to run. When it installs
named packages, the hook checks them as `valvur check` does, before the install runs
anything. This is the reading: which packages a command would install, in which
ecosystem, at which version when one is named. Nothing is executed.
"""

from __future__ import annotations

from pathlib import Path

from valvur.installs import packages


def _read(command: str, cwd: Path | None = None) -> list[tuple[str, str, str | None]]:
    return packages(command, cwd or Path("."))


def test_npm_pnpm_yarn_and_bun_names_with_versions_tags_and_scopes():
    assert _read("npm install left-pad") == [("npm", "left-pad", None)]
    assert _read("npm i express@4.21.0 @types/node@^22 lodash@latest") == [
        ("npm", "express", "4.21.0"), ("npm", "@types/node", "^22"),
        ("npm", "lodash", "latest")]
    assert _read("npm add --save-dev @scope/tool") == [("npm", "@scope/tool", None)]
    assert _read("pnpm add -D vitest") == [("npm", "vitest", None)]
    assert _read("yarn add react react-dom@19.0.0") == [
        ("npm", "react", None), ("npm", "react-dom", "19.0.0")]
    assert _read("yarn global add typescript") == [("npm", "typescript", None)]
    assert _read("bun add zod") == [("npm", "zod", None)]
    assert _read("npm install --registry https://registry.example.test lpad") == [
        ("npm", "lpad", None)]
