"""Write access is not release authority (task 28.0.2, D1).

Measured 2026-09-23, four facts that were fine alone and an open door together: no
tag protection; `verify` checking only that the tag matched `pyproject.toml`; the
`release` environment with no reviewer; and a cosign identity of
`^https://github.com/MaverickHQ/valvur/` — in the shim, the README and both
workflows — which matches **every workflow on every branch**. A write-scoped token
could push `v9.9.9` on any commit and the pipeline would sign it under the identity
users are told to trust. These tests hold the door shut from the tree's side; the
ruleset test holds it from GitHub's.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from valvur import oci

REPO = Path(__file__).resolve().parent.parent
REPOSITORY = "MaverickHQ/valvur"

#: What signs the image a user pulls: the release workflow, run by a version tag.
#: One workflow, one ref pattern — a rehearsal signs from `refs/heads/<branch>` and
#: this regex refuses it, which is the point: the README's command is the one a
#: user runs, and it must not verify a rehearsal, a probe, or a branch.
IMAGE_IDENTITY = r"^https://github.com/MaverickHQ/valvur/.github/workflows/release.yml@refs/tags/v"
#: What signs the daily index: the index workflow, on main. 27.0.1 made a branch
#: dispatch push nothing; this makes a branch's signature verify nothing.
INDEX_IDENTITY = r"^https://github.com/MaverickHQ/valvur/.github/workflows/index.yml@refs/heads/main$"
#: The identity that verified anything at all.
BROAD = "^https://github.com/MaverickHQ/valvur/'"

ALLOWED_SIGNERS = REPO / ".github" / "allowed_signers"


def _text(path: str) -> str:
    return (REPO / path).read_text()


def test_the_shim_verifies_the_index_against_the_index_workflow_on_main():
    """The shim's regex is the escaped form of the one the documents show; both
    must accept the daily index's identity and refuse every neighbour of it."""
    assert oci.SIGNING_IDENTITY.replace("\\.", ".") == INDEX_IDENTITY, oci.SIGNING_IDENTITY
    right = "https://github.com/MaverickHQ/valvur/.github/workflows/index.yml@refs/heads/main"
    assert re.match(oci.SIGNING_IDENTITY, right) and re.match(INDEX_IDENTITY, right)
    for wrong in (
        "https://github.com/MaverickHQ/valvur/.github/workflows/index.yml@refs/heads/feature",
        "https://github.com/MaverickHQ/valvur/.github/workflows/release.yml@refs/tags/v0.3.1",
        "https://github.com/MaverickHQ/valvur/.github/workflows/macos-probe.yml@refs/heads/main",
        "https://github.com/MaverickHQ/valvur-fork/.github/workflows/index.yml@refs/heads/main",
    ):
        assert not re.match(oci.SIGNING_IDENTITY, wrong), wrong


def test_every_command_a_user_is_given_names_the_release_workflow_and_a_version_tag():
    """The README, EVALUATING.md, RELEASING.md and the release notes the pipeline
    writes all show one verify command; it names the identity a real release
    signs under and nothing wider."""
    documents = {
        "README.md": _text("README.md"),
        "docs/EVALUATING.md": _text("docs/EVALUATING.md"),
        "docs/RELEASING.md": _text("docs/RELEASING.md"),
        ".github/workflows/release.yml": _text(".github/workflows/release.yml"),
    }
    for name, text in documents.items():
        assert BROAD not in text, f"{name} still shows the identity that verified anything"
    for name in ("docs/RELEASING.md", ".github/workflows/release.yml"):
        assert IMAGE_IDENTITY in documents[name], f"{name} does not show the image identity"
    # The README shows no command of its own; it sends the reader to EVALUATING.md,
    # and must keep doing so rather than growing a second, wider copy.
    readme = documents["README.md"]
    assert "cosign verify" not in readme or IMAGE_IDENTITY in readme
    # EVALUATING.md shows both: the image's, and the index's for the index.
    assert IMAGE_IDENTITY in documents["docs/EVALUATING.md"]
    assert INDEX_IDENTITY in documents["docs/EVALUATING.md"]
    assert INDEX_IDENTITY in _text(".github/workflows/index.yml")
    assert BROAD not in _text(".github/workflows/index.yml")


def test_the_pipeline_verifies_the_image_against_exactly_this_runs_identity():
    """`artifact` runs in a rehearsal (signed from `refs/heads/<branch>`) and in a
    release (`refs/tags/vX.Y.Z`); a regexp wide enough for both is the one just
    removed. So it verifies the EXACT identity of this run — `release.yml` at
    `github.ref` — which is stricter than any pattern and true in both."""
    release = _text(".github/workflows/release.yml")
    exact = ("--certificate-identity "
             '"https://github.com/${{ github.repository }}'
             '/.github/workflows/release.yml@${{ github.ref }}"')
    assert exact in release, "artifact does not pin the signature to this run's own identity"
    artifact = release.split("\n  artifact:", 1)[1].split("\n  promote:", 1)[0]
    assert "--certificate-identity-regexp" not in artifact, \
        "artifact still verifies against a pattern"


def test_a_real_tag_must_be_signed_by_a_known_key_and_sit_on_main():
    """`verify` checked only the version string. Now: `git tag -v` against the
    committed allowed-signers file, and `merge-base --is-ancestor` against main —
    both skipped in a rehearsal, which has no tag."""
    release = _text(".github/workflows/release.yml")
    verify = release.split("\n  verify:", 1)[1].split("\n  build:", 1)[0]
    assert " tag -v " in verify, "verify does not check the tag's signature"
    assert "allowed_signers" in verify, "verify does not say which key may sign a release"
    assert "merge-base --is-ancestor" in verify, "verify does not check the tag is on main"


def test_the_allowed_signers_file_verifies_the_tree_it_is_committed_to():
    """Not a literal: the same file, applied by the same git, must verify HEAD's own
    signature — every commit on main is signed with the release key, so a file
    that cannot verify HEAD could not verify a tag either."""
    assert ALLOWED_SIGNERS.is_file(), "no .github/allowed_signers"
    lines = [line for line in ALLOWED_SIGNERS.read_text().splitlines()
             if line.strip() and not line.startswith("#")]
    assert lines and all(len(line.split()) >= 3 and "ssh-" in line for line in lines), lines

    git = shutil.which("git")
    if git is None or not (REPO / ".git").exists():
        pytest.skip("not a git checkout")
    head = subprocess.run([git, "-C", str(REPO), "log", "-1", "--format=%G?"],
                          capture_output=True, text=True, check=False).stdout.strip()
    if head not in ("G", "U", "E", "N", "B", "X", "Y", "R", ""):
        pytest.skip(f"unexpected signature status {head!r}")
    if head == "N":
        pytest.skip("HEAD is unsigned — a local work-in-progress commit")
    done = subprocess.run(
        [git, "-C", str(REPO), "-c", f"gpg.ssh.allowedSignersFile={ALLOWED_SIGNERS}",
         "verify-commit", "HEAD"],
        capture_output=True, text=True, check=False, timeout=30)

    assert done.returncode == 0, f"HEAD does not verify with the committed signers: {done.stderr}"


def _gh(*args: str) -> str:
    gh = shutil.which("gh")
    if gh is None:
        pytest.skip("gh is not installed")
    done = subprocess.run([gh, *args], capture_output=True, text=True, check=False, timeout=60)
    if done.returncode != 0:
        pytest.skip(f"gh could not ask GitHub: {done.stderr.strip()[:120]}")
    return done.stdout


@pytest.mark.e2e
def test_a_release_tag_can_only_be_created_by_the_owner_and_must_be_signed():
    """The ruleset, read back from GitHub: active, targeting `refs/tags/v*`, with
    creation, update and deletion restricted and signatures required; bypass for
    the repository's admin role and nobody else."""
    rulesets = json.loads(_gh("api", f"repos/{REPOSITORY}/rulesets?targets=tag"))
    tags = [r for r in rulesets if r.get("target") == "tag" and r.get("enforcement") == "active"]
    assert tags, "no active tag ruleset: anyone with write can push a release tag"

    [rid] = [r["id"] for r in tags if r["name"] == "release tags"]
    ruleset = json.loads(_gh("api", f"repos/{REPOSITORY}/rulesets/{rid}"))
    assert ruleset["conditions"]["ref_name"]["include"] == ["refs/tags/v*"], ruleset["conditions"]
    rules = {rule["type"] for rule in ruleset["rules"]}
    assert {"creation", "update", "deletion", "required_signatures"} <= rules, sorted(rules)
    actors = ruleset.get("bypass_actors") or []
    assert all(a["actor_type"] == "RepositoryRole" and a["actor_id"] == 5 for a in actors), actors
