"""D61g: a commit signed by a key the signers file does not name is passed over.

A Claude Code cloud session signs its commits with its own SSH key, which GitHub
verifies and `.github/allowed_signers` does not name (measured 2026-10-03, the cloud
pre-flight). The signers test then verified the session's commit and failed, in the
session's gate and on `main` once such a commit lands. Like Dependabot's GPG-signed
commits, they are nobody's claim about the maintainer's key: the test looks past them
for the newest commit the file verifies. It also verifies with `ssh-keygen` by name,
since a session's configured signing program can only sign.
"""

from __future__ import annotations

import importlib.util
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

TRUST = Path(__file__).resolve().parent / "test_release_trust.py"


def _trust():
    spec = importlib.util.spec_from_file_location("release_trust", TRUST)
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules["release_trust"] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


@pytest.fixture
def chain(tmp_path):
    """A repository whose maintainer-signed commit sits under one signed by another
    key and one not signed, with a signers file naming the maintainer alone."""
    git, keygen = shutil.which("git"), shutil.which("ssh-keygen")
    if git is None or keygen is None:
        pytest.skip("git or ssh-keygen is not installed")
    keys = {}
    for name in ("maintainer", "session"):
        keys[name] = tmp_path / name
        subprocess.run([keygen, "-q", "-t", "ed25519", "-N", "", "-f", str(keys[name])],
                       check=True)
    signers = tmp_path / "allowed_signers"
    public = keys["maintainer"].with_suffix(".pub").read_text().split()
    signers.write_text(f"maintainer@example.invalid {public[0]} {public[1]}\n")
    repo = tmp_path / "repo"
    repo.mkdir()

    def run(*args: str) -> str:
        done = subprocess.run([git, "-C", str(repo), *args],
                              capture_output=True, text=True, check=False)
        assert done.returncode == 0, (args, done.stderr)
        return done.stdout.strip()

    run("init", "-q")
    run("config", "user.email", "t@example.invalid")
    run("config", "user.name", "t")
    run("config", "gpg.format", "ssh")
    commits = {}
    for name, key in (("maintainer", keys["maintainer"]), ("session", keys["session"]),
                      ("unsigned", None)):
        (repo / name).write_text(name)
        run("add", name)
        if key is None:
            run("commit", "-q", "--no-gpg-sign", "-m", name)
        else:
            run("-c", f"user.signingkey={key.with_suffix('.pub')}", "commit", "-q", "-S",
                "-m", name)
        commits[name] = run("rev-parse", "HEAD")
    return git, keygen, repo, signers, commits


def test_the_newest_commit_the_file_verifies_is_found_past_another_signers(chain):
    git, keygen, repo, signers, commits = chain

    verified, passed = _trust()._newest_verified(git, keygen, repo, signers, "HEAD")

    assert verified == commits["maintainer"]
    assert passed == [commits["session"]]


def test_a_chain_signed_only_by_others_reports_what_it_passed_over(chain):
    git, keygen, repo, signers, commits = chain

    verified, passed = _trust()._newest_verified(git, keygen, repo, signers, "HEAD",
                                                 limit=2)

    assert verified is None and passed == [commits["session"]]


def test_a_signing_program_that_cannot_verify_is_not_used_to_verify(chain):
    """The session's program answered only `-Y sign`; verifying through it failed every
    signature. `ssh-keygen` is named for verification whatever git is configured with."""
    git, keygen, repo, signers, commits = chain
    subprocess.run([git, "-C", str(repo), "config", "gpg.ssh.program", "false"], check=True)

    verified, _ = _trust()._newest_verified(git, keygen, repo, signers, "HEAD")

    assert verified == commits["maintainer"]
