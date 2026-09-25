# Maintainers

Who can change what ships, what you can rely on if they cannot be reached, and
what it takes to add a second person. Written for task 28.1.3, because the fourth
review measured the bus factor and it is one.

## Who

| | |
|---|---|
| Maintainer | **MaverickHQ** — `MaverickHQ@users.noreply.github.com` |
| Repository | user-owned (`MaverickHQ/valvur`), not an organisation; one collaborator, admin |
| Can sign a release tag | the one SSH key in [`.github/allowed_signers`](.github/allowed_signers); `release.yml` refuses a `v*` tag any other key signed (28.0.2) |
| Can approve the `release` environment | nobody is required to yet — the environment has no required reviewer, so the brake between validation and promotion (ADR-0020) is the maintainer's own tag |
| Commits | 288 of 291 by the maintainer, 3 by Dependabot (measured 2026-09-26) |

A test holds the first row to the signers file: every principal that may sign a
release is named here, so a key added to `allowed_signers` without a person added
to this table fails the build.

## What does not depend on the maintainer

Everything a user runs is reproducible from the tree, and everything they verify
is verifiable without anyone's cooperation:

- **The image.** `docker buildx bake` in this repository builds it from the
  `Dockerfile`; every base image and tool is pinned by digest, Checkov by hash
  (23.4.1). The published image records the tree it was built from (22.C.1).
- **The wheel.** `uv build`. Zero runtime dependencies (ADR-0015); it carries the
  tree hash it was built beside (23.4.4).
- **The name index.** `valvur update --build-index` walks the five registries
  itself — about seven minutes — when the published index cannot be reached, and
  a mirror can serve the files (`VALVUR_NAME_INDEX_URL`).
- **The signatures.** Keyless cosign signatures and SLSA provenance on every
  published image are verified against a public transparency log and this
  repository's workflow identity ([`docs/EVALUATING.md`](docs/EVALUATING.md)); no
  key the maintainer holds is needed to check them, and none expires.
- **The pipeline.** [`release.yml`](.github/workflows/release.yml) runs on any
  fork against that fork's registry and PyPI project, with that fork's identity.

## If the maintainer is unreachable

[`SECURITY.md`](SECURITY.md) commits to an acknowledgement within five working
days and an assessment within fifteen. If a report through GitHub's private
vulnerability reporting **and** the email there both go unanswered for **thirty
working days**, treat the project as unmaintained: the licence permits a fork, the
build is reproducible from any commit, and a fork that changes the name and the
signing identity is what this document asks for rather than what it fears. Do not
wait for a release that a single person's absence is holding.

## Adding a second maintainer

The steps, in order, so that the second person can do the one thing that matters
— approve a release the pipeline has already validated — before anything else:

1. Invite them as a collaborator with the **admin** role (a user-owned repository
   has no organisation teams to add them to).
2. Add them as a **required reviewer** on the `release` environment (Settings →
   Environments → release), so a promotion needs a second click.
3. Add their SSH signing key to [`.github/allowed_signers`](.github/allowed_signers)
   and their row to the table above, in one commit; the test that ties the two
   together will refuse either alone.
4. Give them the `release` role on the PyPI project and the TestPyPI project, and
   write access to the two GHCR packages.
5. Put the usability gate (task 10.1.1) on a calendar with both names on it.

Until step 2 is done, the `release` environment's reviewer list is empty and
this file says so; the pipeline's brake is the tag itself.
