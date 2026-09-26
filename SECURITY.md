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
- **Findings from the underlying scanners** — Trivy, Gitleaks, Opengrep, Checkov,
  OSV-Scanner, Syft. valvur orchestrates them; it does not write their detections.
  Report those upstream, and please tell us too if we are presenting them wrongly.
- **False positives**, unless the volume makes real findings unreadable. That is a
  bug and an important one — open an issue.
- **Vulnerabilities in the base image's OS packages** that valvur does not use.
  The published SBOM discloses everything the image contains; a reachable one is in
  scope, an unreachable one is not.

## Supported versions

Pre-1.0, only the latest release is supported. Once 1.0 lands, this table becomes
the record.

| Version | Supported |
|---|---|
| `0.3.x` | ✅ latest only |

<!-- A test keeps this table on the released series (27.2.4): it said `0.1.x`
     through 0.2.0 and 0.3.0, so a reporter checking whether their version was
     supported read a series superseded twice. -->

## What valvur does with your code

Nothing leaves your machine on the default profile, and you can check that yourself
rather than take our word for it — see
[verifying non-exfiltration](README.md#1-it-cannot-exfiltrate-your-code--and-you-can-verify-it)
and [`scripts/verify-offline.py`](scripts/verify-offline.py). The `full` profile
sends dependency **package names** — never source — to public advisory and registry
APIs, and `run.json` records exactly what left in every run.
