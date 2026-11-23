# Security policy

valvur is a security tool, so a flaw in it costs more than a flaw in most software:
it can tell someone their code is safe when it is not. The scope below is written
around that.

## Reporting a vulnerability

**Use GitHub's private vulnerability reporting** — the *Report a vulnerability*
button under this repository's **Security** tab. It is private, it lets us fix before
disclosing, and it keeps the discussion attached to the code.

If that is unavailable to you, email **info@maverickstudios.net** with `valvur
security` in the subject.

Please **do not open a public issue** for a suspected vulnerability. Everything else
belongs in an issue, and is welcome there.

Include what you would want if you were fixing it: what you ran, what you expected,
what happened, and the smallest repository or file that reproduces it. `valvur
doctor --bundle` writes the facts of the machine and the run into one tarball —
never your source, raw output or findings — for the report. A scan's
`run.json` tells us the profile, scanner versions and database age, which is usually
the fastest way to the cause — check it for secrets first, as it may name paths.

### What to expect

valvur is maintained by one person ([MAINTAINERS.md](MAINTAINERS.md) says what that
means for you), so these are commitments we can actually keep rather than ones
that read well:

| | |
|---|---|
| Acknowledgement | within **5 working days** |
| Initial assessment | within **15 working days** |
| Fix or a stated plan | agreed with you, based on severity |
| Credit | offered by default; tell us if you would rather not be named |

We will tell you when it is fixed and when it is disclosed. If we conclude it is not
a vulnerability, we will say why rather than closing quietly.

## In scope

These are vulnerabilities in valvur, not merely bugs:

- **A false clean result.** A scan that reports no findings on a repository that has
  them is the worst failure this tool can have — it manufactures confidence, and the
  developer stops looking. If you can make valvur miss something it should catch,
  that is a security report.
- **A silent scanner failure.** A scanner that crashes, or scans nothing, without
  that appearing in `SUMMARY.md` and `run.json`. Same reason as above: the output is
  indistinguishable from a clean scan.
- **Evidence that is not neutralised.** valvur quotes untrusted repository content
  into files an agent is instructed to read. A payload that survives into
  `SUMMARY.md`, `REMEDIATION.md` or an MCP response and can act on the reader is a
  vulnerability — valvur must never become the delivery mechanism.
- **Anything leaving the machine on the `offline` profile.** Non-exfiltration is a
  testable property, not a policy. If you can make the `offline` profile open a
  socket, from the shim or from a container, we want to know today.
- **A write outside the results folder.** The source tree is mounted read-only and
  the mount is the jail. A path that escapes it is in scope.
- **A secret reaching disk unredacted.** Gitleaks emits live credential values;
  every written artifact, including `raw/`, must redact them.
- **Anything that lets a scanned repository execute code on the host**, or escape
  the container.

## Out of scope

- **Vulnerabilities in the code valvur scans.** Those are your findings, working as
  intended.
- **Findings from the underlying scanners** — Trivy, Gitleaks, Opengrep, zizmor,
  Checkov, OSV-Scanner, Syft. valvur orchestrates them; it does not write their detections.
  Report those upstream, and please tell us too if we are presenting them wrongly.
- **False positives**, unless the volume makes real findings unreadable. That is a
  bug and an important one — open an issue.
- **Vulnerabilities in the base image's OS packages** that valvur does not use.
  The published SBOM discloses everything the image contains; a reachable one is in
  scope, an unreachable one is not. A package that nothing in the image loads is taken out
  of it, and [`.github/image-packages.txt`](.github/image-packages.txt) names the ones that
  stay. A removed package's files are gone from the image's filesystem, which is what a scan
  of the image reads. Its bytes remain in the base image's layer, where a tool that reads
  layers one by one will still find them.

## Supported versions

The latest minor series is supported; this table is the record.

| Version | Supported |
|---|---|
| `1.6.x` | ✅ latest only |

Earlier releases are not supported: upgrade to the latest. From `1.0.0` a minor or
patch release keeps every contract the CHANGELOG's `1.0.0` entry names; a change that
breaks one is a major release.

<!-- A test keeps this table on the released series (27.2.4): it said `0.1.x`
     through 0.2.0 and 0.3.0, so a reporter checking whether their version was
     supported read a series superseded twice. -->

## How a release is built: SLSA Build L2

**valvur's releases reach SLSA Build L2, and no higher.** The level is the Build track's,
as SLSA 1.0 defined it and the current specification, 1.2, keeps it, read on 2026-11-23.
Each requirement of the level, and where to check it:

| requirement | the evidence |
|---|---|
| Choose an appropriate build platform | GitHub Actions, on runners GitHub hosts: [`release.yml`](.github/workflows/release.yml) |
| Follow a consistent build process | every release is that one workflow, which stages, validates and then promotes: [`docs/RELEASING.md`](docs/RELEASING.md) |
| Distribute provenance | in the registry beside the image; attached to the GitHub release as `valvur-<version>.image.intoto.jsonl` and `valvur-<version>.dist.intoto.jsonl`; and on PyPI for the wheel and the sdist |
| Provenance exists | `actions/attest-build-provenance` writes it in SLSA's own format, for the image's digest and for each distribution |
| Provenance is authentic | signed through Sigstore with the workflow's own identity, a key no person holds. The release verifies it before anything is promoted, and so can you, below |
| Hosted | every job of the release runs on a runner GitHub hosts, and none on a machine of the maintainer's |

```bash
gh attestation verify oci://ghcr.io/maverickhq/valvur:<version> --repo MaverickHQ/valvur
```

A test holds each row to the workflow, so the workflow cannot lose a row's evidence while
this table keeps it.

### What Build L3 needs, and the release does not have

- **Provenance is unforgeable.** L3 asks that the steps a project writes cannot reach the
  identity that signs the provenance. Here the job that builds the image is the job that
  signs for it.
- **Isolated.** L3 asks for a build that nothing outside it can influence. Here the build
  is steps of the release workflow, and it reads a build cache that earlier runs wrote.

Both need the build moved into a builder that runs apart from the workflow that calls it.
That is not planned before 2.0, and until it is done this section says L2.

## What valvur does with your code

Nothing leaves your machine on the default profile, and you can check that yourself
rather than take our word for it — see
[verifying non-exfiltration](docs/HOW-IT-WORKS.md#1-it-cannot-exfiltrate-your-code-and-you-can-verify-it)
and [`scripts/verify-offline.py`](scripts/verify-offline.py). The `full` profile
sends dependency **package names** — never source — to public advisory and registry
APIs, and `run.json` records exactly what left in every run.
