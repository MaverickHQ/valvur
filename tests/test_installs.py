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


def test_pip_uv_and_poetry_names_with_specifiers_and_extras():
    assert _read("pip install requests") == [("pip", "requests", None)]
    assert _read("pip3 install 'fastapi[standard]==0.115.0' 'pydantic>=2' uvicorn") == [
        ("pip", "fastapi", "0.115.0"), ("pip", "pydantic", None), ("pip", "uvicorn", None)]
    assert _read("python -m pip install --upgrade --index-url https://pypi.example.test "
                 "-c constraints.txt numpy") == [("pip", "numpy", None)]
    assert _read("uv pip install httpx==0.27.2") == [("pip", "httpx", "0.27.2")]
    assert _read("uv add --dev pytest 'ruff>=0.6'") == [
        ("pip", "pytest", None), ("pip", "ruff", None)]
    assert _read("poetry add django@^5.1 --group dev black") == [
        ("pip", "django", "^5.1"), ("pip", "black", None)]


def test_a_requirements_file_is_read_as_the_file_it_names(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "# pinned for the demo\n"
        "--index-url https://pypi.example.test/simple\n"
        "flask==3.1.0  # the web layer\n"
        "-r base.txt\n"
        "-e .\n"
        "git+https://example.test/repo.git#egg=thing\n"
        "requests>=2 ; python_version >= '3.11'\n")
    (tmp_path / "base.txt").write_text("attrs\n")

    assert _read("pip install -r requirements.txt", tmp_path) == [
        ("pip", "flask", "3.1.0"), ("pip", "attrs", None), ("pip", "requests", None)]
    assert _read("uv pip install --requirement=requirements.txt six", tmp_path)[-1] == \
        ("pip", "six", None)
    assert _read("pip install -r missing.txt", tmp_path) == []


def test_cargo_gem_and_composer_names():
    assert _read("cargo add serde@1.0.210 --features derive tokio") == [
        ("cargo", "serde", "1.0.210"), ("cargo", "tokio", None)]
    assert _read("cargo add --git https://example.test/crate.git thing") == []
    assert _read("gem install rails -v 8.0.1 rack") == [
        ("gem", "rails", "8.0.1"), ("gem", "rack", None)]
    assert _read("composer require monolog/monolog:^3.0 --dev symfony/console") == [
        ("composer", "monolog/monolog", "^3.0"), ("composer", "symfony/console", None)]


def test_each_command_of_a_chain_is_read_on_its_own():
    assert _read("cd web && npm install axios; pip install rich | tee log") == [
        ("npm", "axios", None), ("pip", "rich", None)]
    assert _read("FOO=1 sudo npm i -g pm2 || echo failed") == [("npm", "pm2", None)]
    assert _read("(cd api && uv add 'starlette==0.41.0')") == [("pip", "starlette", "0.41.0")]
    assert _read("echo 'npm install not-run'") == []


def test_flags_urls_paths_and_git_references_are_never_names():
    assert _read("npm install ./local-pkg ../other /abs/path file:../x "
                 "git+https://example.test/r.git github:owner/repo owner/repo "
                 "https://example.test/pkg.tgz pkg.tgz --save-exact") == []
    assert _read("pip install . ./dist/thing-1.0-py3-none-any.whl -e ../lib "
                 "'thing @ https://example.test/thing.zip' --no-deps") == []
    assert _read("pip install --target vendored requests") == [("pip", "requests", None)]


def test_a_command_that_names_no_packages_yields_nothing():
    """A bare install reads the lockfile, whose packages are the scan's to check."""
    for command in ("npm ci", "npm install", "npm i --production", "yarn install", "yarn",
                    "pnpm install", "pip install", "pip install -r", "uv sync", "poetry install",
                    "npm run build", "pip list", "ls -la", "git commit -m 'npm install x'",
                    "", "npm install 'unterminated"):
        assert _read(command) == [], command
