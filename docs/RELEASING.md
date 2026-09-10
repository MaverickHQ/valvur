# Releasing valvur

The release is a consequence of a tag. Everything below the "cutting a release"
heading is automated by
[`.github/workflows/release.yml`](../.github/workflows/release.yml) — the manual
parts are the one-time setup and the decision to release.

## One-time setup — owner actions

These cannot be automated, and the workflow fails without them.

1. **PyPI trusted publishing.** On PyPI → `valvur` → Publishing → add a GitHub
   publisher: owner `MaverickHQ`, repository `valvur`, workflow `release.yml`,
   environment `release`. This replaces a stored API token with an OIDC exchange, so
   there is no long-lived secret to leak.
2. **A `release` GitHub environment**, under Settings → Environments. Required by
   trusted publishing above, and the place to add a manual approval gate if you want
   one before anything is published.
3. **The GHCR package must be public** (task 12a.1), or every user's first pull
   fails — measured 2026-08-31, and the failure surfaces as a confusing mount error
   rather than an authentication one.

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

git commit -am "chore: release 0.2.0"
git tag v0.2.0                    # must match pyproject exactly; the workflow rejects a mismatch
git push origin main --tags
```

### The window between bumping and publishing

Step 1 breaks local scanning until the image exists. The shim derives its image tag
from its own version (task 12a.2), so a bumped-but-unpublished version asks for a tag
nothing has pushed yet.

That is deliberate — the alternative is a shim silently using an image built from
different code — but it means during a release you either work from a local build or
pin explicitly:

```bash
docker buildx build --load --build-arg VALVUR_VERSION=0.2.0 -t valvur:dev .
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

**`release` — publishes, then proves what it published.**

- Pushes `:$VERSION` and `:latest` to GHCR.
- **Signs by digest, not by tag.** A tag can be moved to point at other code, which
  is the entire reason we pin actions to SHAs; signing one would carry that defect
  into our own supply chain. Keyless, via the workflow's OIDC identity, recorded in
  the public Rekor transparency log — there is no key to store, rotate or leak.
- Attests SLSA build provenance, so the image can be traced to this workflow and
  this commit.
- Publishes an SBOM of the **image** in CycloneDX and SPDX. Distinct from the
  `sbom.cdx.json` valvur writes for a scanned project. F10.4 requires it, because the
  base image carries GPL components as every Linux container does, and disclosure is
  the honest answer to a claim no container could satisfy.
- Publishes to PyPI by trusted publishing.
- Creates the GitHub release with the verification commands in the notes, so a
  sceptical reader does not have to find them.

## Verifying a release, as a user would

Worth running yourself after a release, because a verification command that does not
work is worse than none — the README shipped one for weeks that failed twice:

```bash
cosign verify ghcr.io/maverickhq/valvur:0.2.0 \
  --certificate-identity-regexp '^https://github.com/MaverickHQ/valvur/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

gh attestation verify oci://ghcr.io/maverickhq/valvur:0.2.0 --repo MaverickHQ/valvur
```

## If it fails partway

The steps are ordered so the cheap, reversible things happen first. A failure after
the image is pushed but before PyPI leaves a published image and no wheel: fix
forward with a new patch version rather than deleting the tag. GHCR tags and PyPI
versions are both effectively permanent, and a reused version number is worse than a
skipped one.
