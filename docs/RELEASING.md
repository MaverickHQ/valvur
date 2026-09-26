# Releasing valvur

The release is a consequence of a tag. Everything below the "cutting a release"
heading is automated by
[`.github/workflows/release.yml`](../.github/workflows/release.yml) — the manual
parts are the one-time setup and the decision to release.

## One-time setup — owner actions

These cannot be automated, and the workflow fails without them.

> **All done on 2026-09-13** (task 23.1.1), the morning the repository went public.
> Kept here because each is a thing that can be undone by accident and would need
> redoing the same way.

1. **PyPI trusted publishing.** On PyPI → `valvur` → Publishing → add a GitHub
   publisher: owner `MaverickHQ`, repository `valvur`, workflow `release.yml`,
   environment `release`. This replaces a stored API token with an OIDC exchange, so
   there is no long-lived secret to leak.
2. **A `release` GitHub environment**, under Settings → Environments. Required by
   trusted publishing above, and the place to add a manual approval gate if you want
   one: since 26.1.1 the environment is on the `promote` job, so a required reviewer
   is asked *after* the artifact has been validated and *before* anything a user can
   install exists — the version tag, `:latest`, PyPI, the GitHub release.
3. **The GHCR packages must be public** (task 12a.1) — `valvur`, the image, or every
   user's first pull fails (measured 2026-08-31, and the failure surfaces as a
   confusing mount error rather than an authentication one); and `valvur-index`, the
   published package-name index (23.2.1), or every `valvur update` says *"the
   registry demands credentials and valvur pulls anonymously"* and walks the five
   registries itself for eight minutes instead. The index package is created private
   by the first run of `index.yml`; make it public under the package's settings.
4. **TestPyPI trusted publishing, for rehearsals.** On test.pypi.org → the `valvur`
   project (or a pending publisher, before it exists) → Publishing → the same GitHub
   publisher as above: `MaverickHQ` / `valvur` / `release.yml` / environment
   `release`. Without it the rehearsal's TestPyPI step fails with a clear
   `invalid-publisher` error — which is a rehearsal doing its job, but not the one
   you wanted. **Not optional in practice**: the TestPyPI upload is the only step
   that runs twine's metadata check, and rehearsal #6 (2026-09-13) found there that
   the pinned publish action refused every wheel `uv build` produces — a failure the
   real release would otherwise have met at its last step, after the image was
   pushed and signed.

## Rehearse before you release

`release.yml` runs every step against throwaway targets when dispatched by hand
(22.B.1). Do this before every real tag; it is the only way to find out what broke
since the last one without finding out in public.

```bash
gh workflow run release.yml --ref main
gh run watch                       # or: gh run list --workflow release.yml
```

What a rehearsal does differently, and nothing else:

| step | real release | rehearsal |
|---|---|---|
| version check | tag must equal `pyproject.toml` | no tag; publishes `<version>.dev<run-number>` |
| image | `ghcr.io/maverickhq/valvur:<version>` and `:latest` | `ghcr.io/maverickhq/valvur-rehearsal:<version>.devN` and `:latest` |
| signature, attestation, SBOM | on the image | on the scratch image — real Rekor entries, real attestations |
| PyPI | `pypi.org` | `test.pypi.org` |
| GitHub release | on the tag | a **draft** pre-release on `rehearsal-N`, deleted by the last step |

Everything else — `verify.sh`, the image build, the whole test suite against it,
the licence check, the self-scan gate, the multi-architecture push, the platform
assertion — runs exactly as it will for the tag. The scratch image and the TestPyPI
upload are left in place on purpose: they are what you inspect afterwards.

**The artifact is tested before it is promoted** (12b.2, N2.5, 26.1.1). `verify`
runs the suite and the gate against `valvur:dev` before anything is pushed, which
proves the tree the tag points at. `artifact` runs after `stage`: it installs the
wheel from `dist/` into a clean environment with `src/` deliberately off the path
(and proves it — `valvur._build` exists only in a built wheel), pulls the image by
the digest `stage` signed, verifies the signature, checks the pair's version label
and build digest against each other, and then runs the Phase 11 constraint suite,
the whole e2e suite and the self-scan gate through that wheel and that image. Only
then does `promote` run. Until 2026-09-20 this job ran *after* PyPI and `:latest`
had moved, and its own comment said it could not stop a release that had left. In
a rehearsal it runs against the scratch image and the `.devN` wheel, so it is
proven before the tag.

> **Keyless signing is public.** Every `cosign sign` writes an entry to the Rekor
> transparency log naming this repository and workflow, rehearsal or not. While the
> repository is private that is the one thing a rehearsal makes visible outside it.

> **Attestation cannot be rehearsed on a private repository.** Found by the first
> rehearsal, 2026-09-12: GitHub refuses to persist artifact attestations for a
> user-owned private repository — *"make this repository public"*. The rehearsal
> skips the step with a warning and the report says so; a real release never skips
> it. Until the repository is public (task 12a.1), SLSA provenance is the one step
> of the pipeline that has not run.

What the first two rehearsals proved, and what they found, is recorded under 22.B.1
in [`tasks.md`](../.kiro/specs/valvur/tasks.md).

## Cutting a release

```bash
# 1. Bump the one place the version lives.
$EDITOR pyproject.toml            # version = "0.2.0"

# 2. Refresh the install, or the version tests fail and are right to.
uv sync --extra dev --locked

# 3. Move [Unreleased] to [0.2.0] with today's date.
$EDITOR CHANGELOG.md

# 4. The README states the version it ships; a test enforces it.
$EDITOR README.md                 # > **Status: `0.2.0`**

# 5. Everything must be green BEFORE the tag. The workflow checks again, but
#    finding out here is cheaper than finding out in a job that has already pushed.
#    This is the same script CI and release.yml both call (19.A.3) — the commands
#    used to be written out here as a third copy, and third copies drift.
./scripts/verify.sh

#    verify.sh skips the e2e suite because it must run without a container. You have
#    one, so run that half too, against the image built below.
VALVUR_IMAGE=valvur:dev uv run pytest -q -m e2e

# 6. main is protected (0.14): required checks, signed commits, linear history,
#    enforced for administrators. The prep lands by pull request, and a PR lands by
#    fast-forwarding main to its head once the six checks pass — GitHub's merge
#    button would create a merge commit, which linear history refuses.
git checkout -b release/0.2.0
git commit -am "chore: release 0.2.0"
git push -u origin release/0.2.0
gh pr create --fill                 # wait for the six checks
git push origin release/0.2.0:main  # fast-forward; GitHub records the PR as merged

# 7. Rehearse on that exact commit (above), then tag it. The tag is the publish.
git tag -s v0.2.0 <that commit>   # must match pyproject exactly; the workflow rejects a mismatch
git push origin v0.2.0
```

### The window between bumping and publishing

Step 1 breaks local scanning until the image exists. The shim derives its image tag
from its own version (task 12a.2), so a bumped-but-unpublished version asks for a tag
nothing has pushed yet.

That is deliberate — the alternative is a shim silently using an image built from
different code — but it means during a release you either work from a local build or
pin explicitly:

```bash
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct) VALVUR_VERSION=0.2.0 docker buildx bake  # valvur:dev, from docker-bake.hcl
VALVUR_IMAGE=valvur:dev valvur scan .
```

> **`buildx`, not plain `docker build` (19.B.3)** — the same command `ci.yml` and
> `release.yml` run.
>
> Plain `docker build` does work today: **measured 2026-09-10, it exits 0** and
> produces a working image, because modern Docker enables BuildKit by default and
> BuildKit supplies `TARGETARCH`. But the Dockerfile selects its Opengrep stage with
> `FROM opengrep-${TARGETARCH}`, so that success is a default, not a guarantee. With
> `DOCKER_BUILDKIT=0`, or on an older Docker, there is nothing to resolve and the
> build fails somewhere unhelpful. Naming `buildx` makes the dependency explicit
> rather than lucky.

Keep the window short: bump, verify, tag and push in one sitting.

## What the workflow does

**`verify` — refuses to release a tree that does not agree with itself.** The tag
must match `pyproject.toml`; lint, types and the *whole* test suite including
end-to-end must pass; valvur must add no GPL component (F10.4); and valvur must scan
itself clean, with no unsuppressed finding, no expired suppression and no scanner
that failed to complete (N2.5).

**`build` — each architecture, natively (23.4.3).** One job per architecture, on
its own runner — `ubuntu-24.04` and `ubuntu-24.04-arm` — each running `docker
buildx bake release`: the runner's own architecture, no QEMU (which cost the amd64
runner 4m50s for both on v0.2.0), pushed to the package by digest and untagged, the
digest handed on as an artifact. `docker-bake.hcl` is the one place the build
lives; `ci.yml`, `corpus.yml`, `CONTRIBUTING.md` and `verify` build through it too.

**`stage` — pushes a candidate, signs it, builds the wheel; nothing a user can
name yet (26.1.1).**

- Writes one index over the two digests with `docker buildx imagetools create`,
  tagged **`:$VERSION-candidate`** — never `:$VERSION`, which the shim of this
  version pulls and which must not exist until the pair is validated — and asserts
  the index carries both architectures. That index's digest is what everything
  below signs, attests, tests and promotes; the candidate tag is for a person to
  look at.
- **Signs by digest, not by tag.** A tag can be moved to point at other code, which
  is the entire reason we pin actions to SHAs; signing one would carry that defect
  into our own supply chain. Keyless, via the workflow's OIDC identity, recorded in
  the public Rekor transparency log — there is no key to store, rotate or leak.
- Attests SLSA build provenance, so the image can be traced to this workflow and
  this commit.
- Publishes an SBOM of the **image** in CycloneDX and SPDX — **one per
  architecture** (27.0.2), four files, each named for the child it describes and
  checked to describe it (every Debian package's purl carries `arch=`). Generated
  by the syft the image was built with: the Dockerfile's digest pin, read from the
  Dockerfile at run time rather than copied, so a pin bump is one edit and a test
  refuses a syft named by tag. Distinct from the `sbom.cdx.json` valvur writes for
  a scanned project. F10.4 requires it, because the base image carries GPL
  components as every Linux container does, and disclosure is the honest answer
  to a claim no container could satisfy.
- Builds `dist/` with `uv build`. The wheel carries `valvur/_build.py`, written by
  the build hook (`hatch_build.py`): the digest of the tree it was built beside,
  the same digest the image records — so a user's scan can tell the pair came from
  one tree, and says so when it did not (23.4.4). The SBOM and `dist/` are handed
  on as run artifacts: one build, tested by `artifact`, published by `promote`.

**`artifact` — the pair, tested** (above) — **on both architectures** (26.1.2):
one leg on `ubuntu-24.04`, one on `ubuntu-24.04-arm`, each pulling its own child
of the signed digest and verifying both claims on it, the signature and the SLSA
provenance (26.1.3). `promote` waits for both. Measured on the first rehearsal
with the arm64 leg: 6m06s against amd64's 7m02s, and a peak of 391–410 MiB
against 511–528 MiB.

**`promote` — the three things that cannot be taken back, after the evidence.**

- Re-tags the signed digest as `:$VERSION` and `:latest` — a manifest re-push, so
  the signature and the attestation on the digest hold — and asserts each tag
  resolves to the digest `artifact` tested. First because it is the cheapest to
  undo: a tag can be re-pointed.
- Publishes to PyPI by trusted publishing (TestPyPI in a rehearsal), then reads
  each distribution's attestation back from the index and verifies the local
  file against it (`pypi-attestations verify pypi --repository …`) — the
  pipeline verifies what it publishes (26.1.3).
- Creates the GitHub release with the SBOMs, `dist/` and the verification commands
  in the notes, so a sceptical reader does not have to find them.

The `release` environment sits on this job. **A red `artifact` job leaves a
candidate tag on GHCR and nothing else** — no version tag, no `:latest` move, no
wheel, no release page — and the version number is not burned: fix, move the tag
(nothing public referenced it), and the candidate tag is re-pushed. The candidate
tag stays after a successful promotion, pointing at the same digest as the
version tag; it cannot be deleted on its own (GHCR deletes by version, which is the
digest), and it is harmless.

## Verifying a release, as a user would

Worth running yourself after a release, because a verification command that does not
work is worse than none — the README shipped one for weeks that failed twice:

```bash
cosign verify ghcr.io/maverickhq/valvur:0.2.0 \
  --certificate-identity-regexp '^https://github.com/MaverickHQ/valvur/.github/workflows/release.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

gh attestation verify oci://ghcr.io/maverickhq/valvur:0.2.0 --repo MaverickHQ/valvur
```

## If it fails partway — the runbook

The steps are ordered so the cheap, reversible things happen first, and the rule
throughout is **fix forward, never reuse a version**. GHCR tags can be overwritten
and PyPI versions cannot; a version that means one thing on one index and another
on the other is worse than a skipped number.

Find where it stopped with `gh run view --log-failed`, then:

| it stopped in | what exists | what to do |
|---|---|---|
| `verify` (any step) | nothing published | Fix the tree, commit, **move the tag** (`git tag -f vX.Y.Z && git push -f origin vX.Y.Z`). Nothing has left the runner, so the tag is still yours to move. |
| `stage` or `artifact` (any step) | at most a signed `:X.Y.Z-candidate` tag on GHCR; no version tag, no `:latest` move, no wheel, no release page | The same as `verify`: fix, commit, **move the tag**. Nothing a user can install or pull by the version's name exists, so the number is not burned (26.1.1). The old candidate is overwritten by the re-run. |
| push (image) | possibly a partial push: one architecture, or a manifest without its layers | Re-run the job (`gh run rerun --failed`). A registry push is idempotent; a re-push of the same content produces the same digest. If the failure was the registry itself, wait and re-run. |
| the platform assertion | `:X.Y.Z-candidate` points at a single-architecture index; nothing else moved | Re-run. `latest` and the version tag never moved, so there is nothing to re-point. If the multi-platform build cannot be made to pass, fix and move the tag. |
| `cosign sign` | the candidate pushed and reachable, **unsigned** | Re-run the job — signing is idempotent and the digest is in the push step's output. The unsigned digest is under a candidate tag only; nothing a user resolves points at it. If it cannot be signed, delete the candidate version from the package's versions page. |
| attestation, SBOM | signed image, no provenance or no SBOM asset yet | Re-run the failed job. Nothing downstream depends on these being first-time-right; the attestation step is idempotent and the SBOMs are regenerated from the pushed image. An SBOM whose purls name the wrong architecture means syft matched the wrong child of the index — check `--platform` reached it. |
| `promote`: the re-tag | signed, attested, validated image under the candidate tag; possibly `:X.Y.Z` or `:latest` half-moved | Re-run the failed job: `imagetools create` is idempotent and the step asserts both tags resolve to the validated digest. |
| `promote`: PyPI | `:X.Y.Z` and `:latest` moved to the validated image; **no wheel** | Re-run the job: the upload is the one step that is *not* idempotent, so a partial upload (`400 File already exists`) means PyPI has it — check `pip index versions valvur`. If PyPI rejected the release itself, fix forward: bump to `X.Y.Z+1`, tag, release. The image for `X.Y.Z` stays; document in `CHANGELOG.md` that `X.Y.Z` has no wheel. |
| `promote`: GitHub release | image and wheel published; no release page | `gh release create vX.Y.Z --notes-file notes.md dist/* ...` by hand from the run's artifacts, or re-run the job — `gh release create` fails cleanly if the release already exists. The release page is documentation of the other two; it is never what a user installs. |

**When a tag has to be re-run.** `gh run rerun <id> --failed` re-runs only the
jobs that failed, with the same tag and the same `GITHUB_SHA`, so the artifacts are
built from the same tree. Re-running the whole workflow on a tag that already has a
wheel on PyPI fails at the PyPI step — correctly. Never `git tag -f` a version that
reached PyPI.

## The daily index (23.2.1)

`.github/workflows/index.yml` runs at 03:23 UTC every day and on dispatch. It walks
the five registries with `python -m valvur.name_index build` — the same code as
`valvur update --build-index` — pushes the result to `ghcr.io/maverickhq/valvur-index`
under the day's date and `latest`, signs it keylessly under this repository's
workflow identity, then **pulls it back with the shim's own client** (`… pull`),
cosign included, and compares every file byte for byte with what it built. A
failure there is loud and the tag has already moved: point `latest` at the previous
day (`oras tag ghcr.io/maverickhq/valvur-index:<yesterday> latest`) and read the run.
Nothing in a release depends on it; a user whose `valvur update` cannot reach it
walks the registries, as before 23.2.1.

The npm walk is incremental day to day because the workflow restores yesterday's
index from the Actions cache; a cache miss costs a full walk (five and a half
minutes) and nothing else.

## The air-gap recipe that was measured (22.B.3)

Reproducible on any machine with Docker, and the basis for the README's mirroring
section. The point of `--internal` is that the gap is structural: a container on
that network has no route out, so the database can only have come from the mirror.

```bash
docker network create --internal airgap
docker run -d --name mirror --network airgap registry:2
# populate it from a connected network first, then move it:
#   docker network connect bridge mirror
#   docker run --rm --network bridge ghcr.io/oras-project/oras:v1.2.3 \
#     cp --to-plain-http ghcr.io/aquasecurity/trivy-db:2 <mirror-ip>:5000/trivy-db:2
#   docker network disconnect bridge mirror
docker run -d --name names -p 127.0.0.1:8080:80 \
  -v /path/with/pypi.txt,npm.txt,metadata.json,kev.json:/usr/share/nginx/html:ro nginx:alpine

VALVUR_CACHE=$(mktemp -d) \
VALVUR_DB_REPOSITORY=mirror:5000/trivy-db VALVUR_DB_INSECURE=1 \
VALVUR_CONTAINER_NETWORK=airgap \
VALVUR_NAME_INDEX_URL=http://127.0.0.1:8080 VALVUR_KEV_URL=http://127.0.0.1:8080/kev.json \
python3 scripts/verify-mirror.py tests/fixtures/broken-repo
```

Result on 2026-09-12: update and offline scan complete from a fresh cache, 76
findings, `what_left_the_machine: nothing`, no connection attempted outside
loopback — and two settings that did not exist that morning, because the documented
one on its own did not work (`VALVUR_DB_INSECURE`, `VALVUR_CONTAINER_NETWORK`), plus
a third for the one fetch that had no mirror at all (`VALVUR_KEV_URL`).

**The `release` environment is the manual brake**, and it sits on `promote` on
purpose — [ADR-0020](adr/0020-promote-after-validation.md) records why, and moving
it to `verify` or `stage` would put the human before the evidence and leave the
irreversible steps ungated. Adding a required reviewer to it
(Settings → Environments → release) makes the `promote` job wait for approval after
`artifact` has validated the pair and before anything a user can install exists
(26.1.1; until then the brake was before the push, with the evidence still to come).
That is the right place for a human check if you want one; the tag push is the wrong
place, because by then the workflow is already running.

## The protocol

`docs/PROTOCOL.md` is what the shim assumes of the image, and the image carries its
major as `org.valvur.protocol` (26.3.1). **A release that breaks anything on that
page bumps `compat.PROTOCOL` and the Dockerfile's label together** — a test holds
them equal — and adds a line to the page's history. A release that only adds to it
does not. A shim and an image with the same major run together whatever their
versions say; the artifact job proves the pair it publishes.

## The action

[`MaverickHQ/valvur-action`](https://github.com/MaverickHQ/valvur-action) is
released separately and pinned to a valvur version: its `version` input defaults to
the newest valvur on PyPI that has `gate`, `--budget` and `--jobs` (0.3.0 and
later). When a valvur release changes the CLI the action uses, bump the default
there and tag the action (`v0.N`, and move `v0`) — on a commit whose self-test has
gone green, because that test installs the default from PyPI and is the README
example's path (`v0.1` = `v0` on 2026-09-20, the day `0.3.0` published; both
signed). `ci.yml`'s self-scan job uses the action with `version: ""` — the shim
from the tree under test — pinned by SHA to the tagged commit, so a change to the
CLI that breaks the action is found here first; `release.yml` runs the commands
directly, so a release never depends on the second repository.

## The Checkov lock

Checkov is the one Python Scanner, and the image installs it from
`requirements-checkov.txt` — every transitive package pinned by version and sha256 —
with `--require-hashes`, into `/opt/checkov` (task 23.4.1). To move Checkov, edit
`requirements-checkov.in` and run `scripts/lock-checkov.sh`; the runner's reported
version (`runner.run_checkov`) must match, and a test says so. The lock is part of
the image's build digest, so a changed hash is a changed image, and Dependabot opens
the update. A hash that no longer matches fails the build rather than installing
whatever was served, which is the point. `requirements-checkov.overrides` forces a
transitive pin we refuse to ship — today `asteval`, which Checkov pins to a release
with sandbox-escape advisories — each with its reason and the condition for
dropping it; the image installs the lock with `--no-deps` because the lock is the
resolution.

