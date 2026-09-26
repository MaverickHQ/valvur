"""Our own supply chain (12a.6/7 and after): every action pinned by commit, every
base image by digest, Checkov by hash, one bake file, the release promoted only
after validation, the index tagged only after verification, the SBOM by the pinned
syft. Split from `test_constraints.py` (28.4.3).
"""

from __future__ import annotations

import subprocess
from pathlib import Path

# ------------------------------------------------- our own supply chain (12a.6/7)

def test_every_action_in_every_workflow_is_pinned_to_a_sha():
    """A tag is a mutable pointer, and the release workflow holds signing
    credentials — `id-token: write`, `packages: write`, `contents: write`. A moved
    tag there does not just run bad code, it signs it with our identity.

    `valvur.pinning.mutable-action-ref` catches this in a scan, but rules ship inside
    the image, so that only helps after a rebuild. This is the commit-time guard.
    """
    import re

    workflows = sorted(Path(".github/workflows").glob("*.yml"))
    assert workflows, "no workflows found — this test is asserting nothing"

    unpinned = []
    for path in workflows:
        for number, line in enumerate(path.read_text().splitlines(), start=1):
            match = re.search(r"uses:\s*([\w.-]+/[\w./-]+)@(\S+)", line)
            if match and not re.fullmatch(r"[0-9a-f]{40}", match.group(2)):
                unpinned.append(f"{path.name}:{number} {match.group(1)}@{match.group(2)}")

    assert not unpinned, "actions pinned to a mutable tag: " + "; ".join(unpinned)


def test_every_runner_in_every_workflow_is_a_named_image():
    """The runner is the one input under the build that was still a floating
    pointer. Every action is a SHA and every base image a digest, and the release
    ran on whatever `ubuntu-latest` meant that week — which GitHub moves to a new
    LTS every two years over a rollout of a month (24.04 → 26.04 from 2026-10-19,
    actions/runner-images#14748), during which a rerun of one commit lands on
    either image. What it costs here is not breakage — a kernel and a Docker
    changing under N1.1's and N1.4's numbers, which name the runner as the
    machine class they were measured on. So the image is named, and moving it is
    a diff that re-measures them (2026-09-20)."""
    import re

    floating = []
    for path in sorted(Path(".github/workflows").glob("*.yml")):
        for number, line in enumerate(path.read_text().splitlines(), start=1):
            if re.search(r"\b(ubuntu|macos|windows)-latest\b", line):
                floating.append(f"{path.name}:{number} {line.strip()}")

    assert not floating, "runners on a floating label: " + "; ".join(floating)


def test_no_workflow_grants_write_permission_it_does_not_need():
    """Least privilege, asserted rather than reviewed. `ci.yml` runs on every pull
    request including from forks; a write token there is the difference between a
    malicious PR reading the repository and rewriting it."""
    import re

    text = Path(".github/workflows/ci.yml").read_text()
    top_level = re.search(r"^permissions:\n((?:\s+\w[\w-]*:.*\n)+)", text, re.M)

    assert top_level, "ci.yml declares no top-level permissions block"
    assert "write" not in top_level.group(1), (
        f"ci.yml grants write at the top level: {top_level.group(1).strip()}"
    )


def test_every_base_image_is_pinned_by_digest():  # F2.2, and 15.1's stronger form
    """Task 15.1, and the same rule we apply to actions.

    A tag is a mutable pointer. Every `FROM` here was pinned by tag while every
    action was pinned by SHA — the same defect, in the build that signs our releases,
    where a moved tag does not merely run different code but signs it with our
    identity and logs it as authentic.
    """
    import re

    dockerfile = Path("Dockerfile").read_text()
    unpinned = []
    for number, line in enumerate(dockerfile.splitlines(), start=1):
        match = re.match(r"^FROM\s+(\S+)", line)
        if not match:
            continue
        reference = match.group(1)
        # A stage built on an earlier stage carries no registry reference to pin.
        if "/" not in reference and ":" not in reference:
            continue
        if reference.startswith("opengrep-"):
            continue
        if "@sha256:" not in reference:
            unpinned.append(f"Dockerfile:{number} {reference}")

    assert not unpinned, "base images pinned by mutable tag: " + "; ".join(unpinned)


def test_checkov_is_hash_locked_into_its_own_environment():
    """Task 23.4.1. `pip install checkov==3.2.517` pinned one package and resolved
    the other ~95 afresh on every build — the one input of the image we sign with
    our identity that was not pinned by hash. Now every one is, and the lock is
    what the image installs from, into a venv that shares nothing with valvur's
    interpreter."""
    import re

    lock = Path("requirements-checkov.txt").read_text()
    pinned = re.findall(r"^([A-Za-z0-9_.\-]+)==([^ \\]+)", lock, re.M)
    assert len(pinned) >= 80, f"only {len(pinned)} packages in the lock; Checkov needs ~96"
    hashes = lock.count("--hash=sha256:")
    assert hashes >= len(pinned), "a package in the lock carries no hash"
    checkov = dict(pinned).get("checkov")
    assert checkov, "the lock does not pin checkov itself"

    wanted = re.search(r"^checkov==(\S+)", Path("requirements-checkov.in").read_text(), re.M)
    assert wanted and wanted.group(1) == checkov, "the lock and its input disagree"
    from valvur.adapters import CheckovAdapter

    assert CheckovAdapter.version == checkov, (
        "the adapter reports a Checkov version the lock does not install"
    )

    # An override is a transitive pin of Checkov's we refuse to ship — with the
    # reason beside it, and the lock must carry exactly that version.
    overrides = Path("requirements-checkov.overrides").read_text()
    forced = re.findall(r"^([A-Za-z0-9_.\-]+)==(\S+)", overrides, re.M)
    assert forced, "the overrides file is empty; asteval was overridden for a reason"
    for name, version in forced:
        assert dict(pinned).get(name) == version, (
            f"{name} is overridden to {version} but the lock says {dict(pinned).get(name)}")
        assert re.search(rf"^# {name}:", overrides, re.M), (
            f"the override of {name} carries no reason")

    dockerfile = "\n".join(line for line in Path("Dockerfile").read_text().splitlines()
                           if not line.lstrip().startswith("#"))
    assert "--require-hashes -r /opt/checkov-requirements.txt" in dockerfile
    assert "--no-deps" in dockerfile, "the lock is the resolution; pip must not resolve again"
    assert "python3 -m venv --without-pip /opt/checkov" in dockerfile
    assert not re.search(r"\bpip\b[^\n]*\binstall\b[^\n]*checkov==", dockerfile), (
        "Checkov is still installed by name, outside the lock"
    )


def test_no_run_chain_in_the_dockerfile_can_swallow_its_own_failure():
    """Found by 23.4.1's first build: `a && b && c || true` makes `|| true` cover
    the whole chain, so a failed `pip install` produced an image without Checkov
    and the build reported success. A tolerated step must be scoped in a subshell."""
    import re

    dockerfile = Path("Dockerfile").read_text()
    runs = re.findall(r"^RUN\b(.*?)(?=^\S|\Z)", dockerfile, re.M | re.S)
    assert runs, "no RUN instructions found — this test is asserting nothing"
    for run in runs:
        joined = " ".join(line.strip().rstrip("\\").strip() for line in run.splitlines())
        if "&&" in joined and re.search(r"&&[^()]*\|\|\s*true\s*$", joined):
            raise AssertionError(f"a RUN chain ends in a bare `|| true`: {joined[:120]}…")


def test_the_image_digest_covers_the_checkov_lock():
    """A changed hash is a changed image; the staleness guard (22.C.1) must see it."""
    from valvur import tree_hash

    assert "checkov-lock" in tree_hash.tree_parts(Path("."))
    assert tree_hash.image_parts()["checkov-lock"] == Path(tree_hash.IMAGE_CHECKOV_LOCK)
    assert "requirements-checkov.txt" in Path("Dockerfile").read_text()


def test_every_image_build_goes_through_the_bake_file():
    """Task 23.4.3. Four copies of the build command drifted the way 19.A.3's
    copies did; now `docker-bake.hcl` is the one place, and the release builds each
    architecture natively — no QEMU — merging with `imagetools create`."""
    import re

    bake = Path("docker-bake.hcl").read_text()
    assert re.search(r'^target "dev"', bake, re.M) and re.search(r'^target "release"', bake, re.M)
    assert "push-by-digest=true" in bake
    assert 'VALVUR_VERSION = VALVUR_VERSION' in bake, "the version must reach the Dockerfile"

    for name in ("ci.yml", "corpus.yml", "release.yml"):
        text = Path(".github/workflows", name).read_text()
        assert "docker buildx build" not in text, f"{name} still carries its own build command"
        assert "docker buildx bake" in text, f"{name} does not build through the bake file"
    contributing = Path("CONTRIBUTING.md").read_text()
    assert "docker buildx bake" in contributing and "docker buildx build" not in contributing

    release = Path(".github/workflows/release.yml").read_text()
    assert "ubuntu-24.04-arm" in release, "the arm64 half is not built natively"
    assert "setup-qemu-action" not in release, "QEMU is still installed for the release"
    assert "docker buildx imagetools create" in release
    assert 'needs: [verify, build]' in release


def _release_jobs() -> dict[str, str]:
    """release.yml's jobs, id → text, split at the two-space job headers."""
    import re

    text = Path(".github/workflows/release.yml").read_text()
    body = text.split("\njobs:\n", 1)[1]
    parts = re.split(r"^  ([a-z_-]+):\n", body, flags=re.M)
    return {parts[i]: parts[i + 1] for i in range(1, len(parts) - 1, 2)}


def test_the_release_promotes_only_after_the_artifact_is_validated():
    """26.1.1. Until this, `release` pushed `:VERSION` and `:latest`, signed,
    published to PyPI and created the GitHub release — and THEN the artifact job
    validated the wheel/image pair, with a comment admitting it could not stop a
    release that had left. Now `stage` pushes a candidate tag, signs, attests and
    builds `dist/`; `artifact` validates; and the three things that cannot be
    taken back — the PyPI upload, the `:VERSION` and `:latest` tags, the GitHub
    release — live only in `promote`, which needs `artifact`. The candidate is
    promoted by re-tagging the signed digest, so the signature and the
    attestation hold."""
    import re

    jobs = _release_jobs()
    assert {"verify", "build", "stage", "artifact", "promote"} <= set(jobs), sorted(jobs)

    for irreversible in ("pypa/gh-action-pypi-publish", '"$IMAGE:latest"', "gh release create"):
        owners = [job for job, text in jobs.items() if irreversible in text]
        assert owners == ["promote"], f"{irreversible!r} is in {owners}, not only promote"
    assert re.search(r"needs:\s*\[[^\]]*\bartifact\b", jobs["promote"]), \
        "promote does not wait for artifact"
    assert re.search(r"needs:\s*\[[^\]]*\bstage\b", jobs["artifact"]), \
        "artifact does not follow stage"
    assert "needs: [verify, build]" in jobs["stage"]
    # The manual brake — a required reviewer on the environment — sits before the
    # irreversible step, not before the candidate push.
    assert "environment: release" in jobs["promote"]
    assert "environment: release" not in jobs["stage"]
    # stage never writes the version tag: a red artifact job leaves only a
    # candidate, and the version number is not burned.
    assert '"$IMAGE:$VERSION-candidate"' in jobs["stage"]
    assert re.search(r'-t "\$IMAGE:\$VERSION"', jobs["stage"]) is None
    assert '"$IMAGE@$DIGEST"' in jobs["promote"], "promote does not re-tag the validated digest"


def test_the_published_artifact_runs_on_both_architectures():
    """26.1.2, F10.7. The arm64 image was built natively, listed in the index and
    never executed by the pipeline: `verify`, `published` and `artifact` all ran
    on amd64, and the only machine that had ever run the arm64 image was a
    laptop. Now `artifact` in release.yml and `published` in ci.yml are each a
    two-runner matrix, and `promote` waits for both legs."""
    import re

    jobs = _release_jobs()
    artifact = jobs["artifact"]
    runners = set(re.findall(r"runner:\s*(\S+)", artifact))
    assert runners == {"ubuntu-24.04", "ubuntu-24.04-arm"}, \
        f"artifact does not run on both architectures: {sorted(runners)}"
    assert "runs-on: ${{ matrix.runner }}" in artifact

    ci = Path(".github/workflows/ci.yml").read_text()
    published = ci.split("\n  published:\n", 1)[1].split("\n  selfscan:\n", 1)[0]
    assert re.search(r"runner:\s*ubuntu-24\.04-arm", published), \
        "ci.yml's published job does not run the published image on arm64"
    assert re.search(r"runner:\s*ubuntu-24\.04\n", published)
    # The amd64 leg keeps the name main's branch protection requires.
    assert "name: the published image, on ${{ matrix.arch }}" in published


def test_the_pipeline_verifies_the_provenance_it_publishes_and_has_no_private_repo_branch():
    """26.1.3, F10.3. The repository went public on 2026-09-13; both workflows
    still carried the private-repository branches — an attestation step skipped
    with a warning, a `published` job that skipped with a warning when the
    package could not be pulled anonymously — each a way for a real failure to
    read as an expected skip. And the SLSA provenance the release attested was
    verified by nothing in the pipeline: `artifact` ran `cosign verify` and
    stopped. Now `artifact` verifies the image's attestation and `promote`
    verifies the wheel's on the index it published to."""
    import re

    release = Path(".github/workflows/release.yml").read_text()
    ci = Path(".github/workflows/ci.yml").read_text()
    for dead in ("private repository", "not publicly pullable", "repository.visibility"):
        assert dead not in release, f"release.yml still has the private-repository case: {dead!r}"
        assert dead not in ci, f"ci.yml still has the private-repository case: {dead!r}"

    jobs = _release_jobs()
    assert re.search(r'gh attestation verify "?oci://', jobs["artifact"]), \
        "artifact does not verify the image's build provenance"
    assert "pypi-attestations verify pypi" in jobs["promote"], \
        "promote does not verify the wheel's attestation on the index"
    assert "gh attestation verify" not in jobs["stage"]


def _index_steps() -> list[tuple[str, str]]:
    """index.yml's `publish` steps in order, name → text, split at the step
    headers. A step with no name is keyed by its `uses:` or `run:` line."""
    import re

    text = Path(".github/workflows/index.yml").read_text()
    body = text.split("\n    steps:\n", 1)[1]
    parts = re.split(r"^      - (name: .+|uses: .+|run: .+)$", body, flags=re.M)
    return [(parts[i].partition(": ")[2].strip(), parts[i + 1])
            for i in range(1, len(parts) - 1, 2)]


def test_the_daily_index_is_tagged_only_after_it_is_verified():
    """27.0.1, ADR-0018 in ADR-0020's order. `index.yml` pushed the day's index
    under `:$DATE` and `:latest` FIRST, then signed it, then pulled it back through
    the shim's own client to verify — so a build that failed its own verification
    had already moved `latest`, which the step's comment admitted ("the tag has
    already moved"). Now the push is to a candidate tag; the signature, the round
    trip and the digest comparison come next; `oras tag` writes the date and
    `latest` last, and only from `main`. A red run leaves `latest` where it was."""
    import re

    text = Path(".github/workflows/index.yml").read_text()
    steps = _index_steps()
    names = [name for name, _ in steps]

    def index_of(fragment: str) -> int:
        owners = [i for i, (_, body) in enumerate(steps) if fragment in body]
        assert len(owners) == 1, f"{fragment!r} is in {len(owners)} steps: {owners}"
        return owners[0]

    push, sign = index_of("oras push"), index_of("cosign sign")
    verify, tag = index_of("valvur.name_index pull"), index_of("oras tag")
    assert push < sign < verify < tag, (
        f"the order is push={names[push]!r}, sign={names[sign]!r}, "
        f"verify={names[verify]!r}, tag={names[tag]!r}"
    )

    # The push names no tag a user resolves; the date and latest exist only from
    # `oras tag`, on the digest the round trip verified.
    assert re.search(r'oras push "\$REPOSITORY:candidate"', steps[push][1]), \
        "the push is not to the candidate tag"
    assert re.search(r'oras push "\$REPOSITORY:[^"]*(\$DATE|latest)', text) is None, \
        "the push still names the date or latest"
    assert re.search(r'oras tag "\$REPOSITORY@\$DIGEST" "\$DATE" latest', steps[tag][1]), \
        "the date and latest are not written by re-tagging the verified digest"
    # The round trip checks the digest the shim resolved is the one about to be
    # tagged — not merely that some artifact under the candidate tag verifies.
    assert 'os.environ["DIGEST"]' in steps[verify][1], \
        "the round trip does not compare the resolved digest with the pushed one"

    # Nothing is pushed, signed or tagged from a branch: a dispatch there proves
    # the build and stops. Scheduled runs are on main by construction.
    guard = "if: github.ref == 'refs/heads/main'"
    for step in (push, sign, verify, tag):
        assert guard in steps[step][1], f"{names[step]!r} runs off main"

    # The private-repository branch, dead since 2026-09-13 (26.1.3's class): a
    # failed anonymous pull is a failure, not an expected skip with a warning.
    for dead in ("pulls anonymously", "is private", "repository.visibility"):
        assert dead not in text, f"index.yml still has the private-repository case: {dead!r}"
    assert "the tag has already moved" not in text
def test_the_release_sbom_is_made_by_the_pinned_syft_for_both_architectures():
    """27.0.2, F10.4. The release SBOM was generated by `anchore/syft:v1.51.1` — a
    tag, the one floating pointer left in a pipeline where every action is a SHA
    and every base image a digest — and for `linux/amd64` only, of an image that
    ships for two architectures. The Dockerfile already pins the same syft by
    digest; now the workflow reads that pin from the Dockerfile at run time, so
    there is one pin and nothing to drift, and generates one SBOM per child."""
    import re

    jobs = _release_jobs()
    stage, promote = jobs["stage"], jobs["promote"]
    release = Path(".github/workflows/release.yml").read_text()

    assert re.search(r"anchore/syft:v?\d", release) is None, \
        "the release SBOM is generated by a syft pinned by tag"

    # The workflow's extraction, run here on the same Dockerfile, must yield the
    # Dockerfile's own pin — the mechanism is tested, not a copied literal.
    extraction = re.search(r"SYFT=\$\((.+?)\)\n", stage)
    assert extraction, "stage does not read the syft pin from the Dockerfile"
    found = subprocess.run(["sh", "-c", extraction.group(1)], capture_output=True,
                           text=True, check=True).stdout.strip()
    pinned = re.search(r"^FROM (anchore/syft@sha256:[0-9a-f]{64}) AS syft$",
                       Path("Dockerfile").read_text(), re.M)
    assert pinned and found == pinned.group(1), f"{found!r} != {pinned and pinned.group(1)!r}"
    assert '"$SYFT"' in stage, "the extracted pin is not the image syft runs as"

    sbom = stage.split("- name: SBOM of the image", 1)[1].split("\n      - ", 1)[0]
    for platform in ("linux/amd64", "linux/arm64"):
        assert platform in sbom, f"no SBOM for {platform}"
    # Four files on the release, each naming its architecture and format.
    for name in ("linux-amd64.cdx.json", "linux-arm64.cdx.json",
                 "linux-amd64.spdx.json", "linux-arm64.spdx.json"):
        assert f"valvur-$VERSION.{name}" in promote, f"the release does not attach {name}"


