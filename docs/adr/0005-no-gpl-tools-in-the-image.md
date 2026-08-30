# No GPL-licensed Scanners in the distributed image

Hadolint is excluded despite being the obvious choice for Dockerfile linting,
because it is GPL-3.0. Checkov and Trivy both lint Dockerfiles adequately.

## Consequences

Invoking a GPL binary as a subprocess from a container is mere aggregation and would
almost certainly be fine. We exclude it anyway for two practical reasons: enterprise
buyers run an OSS licence review on third-party images, and a tool that ships Licence
Hygiene checks should have an unimpeachable licence story of its own.

This generalises: any future Scanner under GPL or AGPL is out, regardless of quality.
The image's licence bill of materials is a feature.


## Correction, 2026-08-30

This ADR was implemented as requirement F10.4, *"the image SHALL contain no GPL- or
AGPL-licensed component"* — which is **unsatisfiable by any Linux container image**.
Measured on our own: 12 GPL components, all from the base OS (`busybox`, `apk-tools`,
`alpine-baselayout`, `musl-utils`, `xz-libs`, `gdbm`, `readline` and others). Debian
and Ubuntu bases carry considerably more.

The decision here is unchanged and remains correct: **do not deliberately add a
GPL-licensed tool** as a Scanner, Check or library. That was always the real concern —
a product shipping licence analysis should not need to explain why it bundles GPL
tooling of its own choosing.

What changed is the claim we make about it. F10.4 now constrains what we *add*, and
requires publishing an SBOM that discloses every component's licence including the
base image's. A requirement that can never pass either blocks every release or gets
quietly ignored, and the second is worse — it teaches people to skip the check.
