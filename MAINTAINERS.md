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
| Can approve the `release` environment | the maintainer, as its one required reviewer (set 2026-09-26, after the last rehearsal); self-review is allowed, so the brake between validation and promotion (ADR-0020) is the maintainer's own click, after the evidence — until step 2 below puts a second name beside theirs |
| Commits | 818 of 980 by the maintainer, 155 by the Claude Code cloud sessions the maintainer ran, 7 by Dependabot (measured 2026-10-24, `git shortlog -sne main`) |

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

## If the maintainer cannot release

One person can release: the signed tag and the approval at the brake are both the
maintainer's. If that person cannot, as of 2026-11-23:

- **The data a scan reads keeps arriving.** The package-name index, the malicious-package
  list, CISA KEV and FIRST EPSS are fetched by the scan itself or published daily by a
  scheduled workflow on `main`, signed with the workflow's identity. No person is in that
  path.
- **The published images keep being checked.** The nightly scans the published image and
  the watchdog reads every scheduled workflow, and each files an issue when it fails.
  Nobody is there to act on the issue.
- **No release happens.** Not a feature, and not a security patch: a vulnerability found
  in the published image stays in it until a person tags a release. ADR-0032 proposes
  that a security-only patch promote itself after a delay the maintainer can cancel. It
  is proposed, its workflows are not on `main`, and until they are this line stands.
- **What you hold still works.** An installed version scans as it did, offline, and its
  signatures verify with no key of the maintainer's.

A second maintainer is the remedy, and the steps are next.

## Adding a second maintainer

The steps, in order, so that the second person can do the one thing that matters
— approve a release the pipeline has already validated — before anything else:

1. Invite them as a collaborator with the **admin** role (a user-owned repository
   has no organisation teams to add them to).
2. Add them as a **required reviewer** on the `release` environment (Settings →
   Environments → release), beside the maintainer, and turn on **prevent
   self-review**, so a promotion needs a click the person who pushed the tag
   cannot make.
3. Add their SSH signing key to [`.github/allowed_signers`](.github/allowed_signers)
   and their row to the table above, in one commit; the test that ties the two
   together will refuse either alone.
4. Give them the `release` role on the PyPI project and the TestPyPI project, and
   write access to the two GHCR packages.
5. Put the usability gate (task 10.1.1) on a calendar with both names on it.

Until step 2 is done, the `release` environment's only reviewer is the maintainer
and self-review is allowed, and this file says so; the brake between validation
and promotion is one person's click, after the evidence.
