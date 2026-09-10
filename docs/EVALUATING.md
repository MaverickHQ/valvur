# Evaluating valvur

For someone deciding whether this is worth their time. It answers the questions a
reviewer actually has, in the order they have them, and it is deliberately specific
about what valvur does **not** do — because a security tool that oversells is worse
than one that undersells.

The [README](../README.md) is the introduction. This is the audit.

---

## 1. Install it

```bash
pipx install valvur          # or: uv tool install valvur
valvur update                # fetches the vulnerability database, once
valvur scan .
```

Needs Docker or Podman. The shim is Python, stdlib only, no runtime dependencies —
the scanners live in one OCI image, so nothing is installed onto your machine beyond
a ~200-line launcher.

As an MCP tool, which is the primary path:

```json
{ "mcpServers": { "valvur": { "command": "valvur-mcp" } } }
```

`valvur-mcp --help` describes the four tools it exposes. All four are read-only with
respect to your source.

## 2. Verify the image before you trust it

The signature is keyless, so there is no key to trust — only a public transparency-log
entry naming the workflow that built it:

```bash
cosign verify ghcr.io/maverickhq/valvur@<digest> \
  --certificate-identity-regexp '^https://github.com/MaverickHQ/valvur/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Build provenance, and the SBOM attached to every release:

```bash
gh attestation verify oci://ghcr.io/maverickhq/valvur:<version> --repo MaverickHQ/valvur
```

Signed **by digest, not by tag** — a tag can be moved, and signing one certifies
whatever it points at today.

## 3. Prove it does not phone home

The claim is that source never leaves your machine, and it has two halves.

**The containers** run with `--network=none` on the default profile. No interface, not
a policy.

**The host shim** is the half a `--network=none` flag cannot cover. It has one reason
to reach out — fetching EPSS exploitation scores — and it is gated on the `full`
profile only.

```bash
scripts/verify-offline.py          # checks both halves
```

On Linux you can prove it at the OS level, without privileges, because the container
runtime is reached over a unix socket:

```bash
unshare -rn valvur scan --profile offline .
```

macOS has no equivalent. Saying otherwise would be exactly the overclaim this
document exists to avoid.

Every run records what left the machine, in `run.json`:

```json
"network": { "used": false, "what_left_the_machine": "nothing" }
```

On `full` that field enumerates each destination by name. **That sentence is the
claim**, not a description of it, so a registry added without amending it makes the
claim false — there is a test asserting every destination reached appears there.

## 4. Read the verdict correctly

Three statuses. The distinction between the last two is the point of the product.

| Status | What it licenses you to say |
|---|---|
| `findings` | Live problems were found in this repository. |
| `clean` | Nothing live was found, **by a scan that could support the claim**. |
| `inconclusive` | Nothing was found **and that is not evidence**. Either the vulnerability database was too old, or an ecosystem present in your repository was never inspected. |

Only **active** findings make a status `findings`. Two things deliberately do not:

- **Suppressed findings** are risks your project already recorded a decision about, in
  a committed `.security-scan.toml` with a mandatory expiry date. They are always
  listed, never hidden, and always counted separately.
- **Coverage notes** are valvur's own missing features, not defects in your code.
  Counting them would fail your CI for something you cannot fix.

```
clean: 0 active, 4 suppressed
findings: 70 active, 1 not covered
```

## 5. What it does not claim

Read this before the feature list, not after.

- **It is not a scanning engine.** Detection is Trivy, Gitleaks, Opengrep, Checkov,
  OSV-Scanner and Syft. valvur orchestrates, normalises, enriches and presents. Every
  finding names its source.
- **It is not a reachability analyser.** It does not prove a vulnerable function is
  ever called. That is a multi-year per-language effort and claiming it would be a lie.
- **It does not fix anything.** `REMEDIATION.md` is a proposal. There is no
  `scan_and_fix` tool and a test asserts none exists in the registry, so adding one
  fails the build rather than merely failing review. An agent told to drive findings
  to zero has a cheaper path via deleting code than via correct fixes.
- **Dependency-reality covers Python and npm only.** `requirements*.txt` and
  `pyproject.toml` against PyPI; `package.json` against the npm registry. Cargo, Go,
  Ruby, PHP and JVM have **no existence check** — and a repository using one gets a
  finding saying so on every profile, rather than a clean result it did not earn.
- **SELinux mount labelling is unimplemented** (F1.6). It could not be reproduced as a
  defect on the enforcing environment available here, and a native RHEL host is
  untested. Recorded rather than quietly assumed.
- **It is not a pen-test tool.** No DAST, no exploitation, no scanning of deployed
  systems.

## 6. Judge it by how it handles being wrong

The interesting question about a security tool is not what it finds — it is what it
does when it cannot find anything.

- A Scanner that crashed appears **at the top** of `SUMMARY.md`, and the run is marked
  incomplete. A silent failure manufactures false confidence and is worse than no scan.
- A Scanner that was **skipped** (Checkov, where there is no infrastructure to
  analyse) says so with its reason, in `run.json` and `SUMMARY.md`. A conditional
  Scanner is one that can silently stop running.
- A Scanner the **profile did not run** is named on every scan, whether or not
  anything was found.
- An **ecosystem nothing inspects** produces a finding saying so.
- **Excluded paths** are reported with the count they cost. An exclusion you cannot
  see is indistinguishable from a scan that found nothing.
- A **fingerprint algorithm change** is announced, because otherwise every finding
  silently reappears as new and every committed suppression stops matching.

## 7. Read the record

The repository keeps its own audit trail, and it is not flattering by design.

- [`.kiro/specs/valvur/requirements.md`](../.kiro/specs/valvur/requirements.md) — 136
  numbered requirements. Unmet ones are annotated as unmet, with the measurement.
- [`.kiro/specs/valvur/tasks.md`](../.kiro/specs/valvur/tasks.md) — every task, with
  what went wrong while doing it. Several entries record a premise I asserted and then
  measured to be false.
- [`docs/adr/`](adr/) — 16 decisions with their rejected alternatives.
- CI runs a **traceability ratchet** that fails when a requirement loses its last
  citation, and a **self-scan gate** that fails on any unsuppressed finding in
  valvur's own repository.

The clearest single illustration: a Check was added to report ecosystems valvur cannot
inspect, its tests passed, and it shipped. A scan of six real local projects then
showed it never ran on the default profile at all, because it had been placed inside a
network-gated Check. Unit tests could not have caught that, and no amount of reasoning
did. Running it against real repositories did.
