"""Write the local release commit to a new branch through GitHub's API (R28.4, D64c).

    python3 scripts/signed_push.py OWNER/REPO release/vX.Y.Z

`main` takes only signed commits, and a commit pushed from a workflow is unsigned. A
commit made with GitHub's `createCommitOnBranch` is signed by GitHub, so this restates
HEAD, the commit `prepare_release.py` just made, as one: a branch at HEAD's parent,
then the same changes on it. It writes a `release/vX.Y.Z` branch and nothing else:
never `main`, never a tag. `GH_TOKEN` is the workflow's. Standard library and `gh`.
"""

from __future__ import annotations

import argparse
import base64
import json
import re
import subprocess
from pathlib import Path

_BRANCH = re.compile(r"release/v\d+\.\d+\.\d+")

MUTATION = """mutation($input: CreateCommitOnBranchInput!) {
  createCommitOnBranch(input: $input) { commit { oid url } }
}"""


def _git(root: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(root), *args], capture_output=True,  # noqa: S603
                          text=True, check=True).stdout


def variables(root: Path, repository: str, branch: str) -> dict:
    """The mutation's input for HEAD, on `branch` at HEAD's parent."""
    if not _BRANCH.fullmatch(branch):
        raise ValueError(f"only a release/vX.Y.Z branch is written, not {branch!r}")
    parent = _git(root, "rev-parse", "HEAD~1").strip()
    additions, deletions = [], []
    for line in _git(root, "diff", "--name-status", "--no-renames", "HEAD~1", "HEAD").splitlines():
        status, path = line.split("\t", 1)
        if status == "D":
            deletions.append({"path": path})
        else:
            contents = (root / path).read_bytes()
            additions.append({"path": path, "contents": base64.b64encode(contents).decode()})
    headline = _git(root, "log", "-1", "--format=%s").strip()
    return {"input": {
        "branch": {"repositoryNameWithOwner": repository, "branchName": branch},
        "expectedHeadOid": parent,
        "message": {"headline": headline},
        "fileChanges": {"additions": additions, "deletions": deletions},
    }}


def push(root: Path, repository: str, branch: str) -> str:
    """Create the branch at HEAD's parent and the signed commit on it; its URL."""
    payload = variables(root, repository, branch)
    parent = payload["input"]["expectedHeadOid"]
    subprocess.run(["gh", "api", f"repos/{repository}/git/refs",  # noqa: S603
                    "-f", f"ref=refs/heads/{branch}", "-f", f"sha={parent}"],
                   check=True, capture_output=True)
    request = json.dumps({"query": MUTATION, "variables": payload})
    reply = subprocess.run(["gh", "api", "graphql", "--input", "-"],
                           input=request, capture_output=True, text=True, check=True)
    return json.loads(reply.stdout)["data"]["createCommitOnBranch"]["commit"]["url"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("repository", help="OWNER/REPO")
    parser.add_argument("branch", help="release/vX.Y.Z")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    print(push(args.root.resolve(), args.repository, args.branch))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
