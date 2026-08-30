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
