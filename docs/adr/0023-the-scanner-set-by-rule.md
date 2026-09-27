# ADR-0023 — The Scanner set, decided by rule

**Status:** accepted 2026-09-27 by the owner as rules, written by task R0.5; amended by
R4.1 with the measurements. Reopens ADR-0019 on its own stated condition.

## Context

Checkov is the slowest Scanner on every corpus repository (12 of 12 in
`tests/corpus/report.json`) and found 5 issues across the 11 application repositories,
all GitHub Actions checks (F2.1, N1.1). On this Mac it took 14.4 s of a 20 s scan for two
workflow files and found nothing, including write permissions the owner's manual audit
flagged (F3.11). Measured on `terraform-aws-vpc`, Trivy's misconfiguration scanner found
3 of Checkov's 9 distinct rules in 7 to 10 s against 77 to 83 s, and reads no workflows.
Syft costs a pass for an SBOM no Finding depends on (P3). OSV-Scanner runs only on `full`,
though it has an offline database mode that may also carry the known-malicious `MAL-`
entries from ossf/malicious-packages (F3.2).

## Decision

The changes are made only where R4.1's measurements meet these rules; otherwise the
current tool stays.

1. **zizmor** (MIT) is adopted for GitHub Actions if it reports every unpinned action
   and every write permission Checkov's GitHub Actions checks found on the corpus.
2. **Checkov runs only where there is infrastructure** other than workflows. **KICS**
   (Apache-2.0) replaces it only if it finds at least 90% of Checkov's distinct failed
   rules on the infrastructure repositories and runs at least twice as fast.
3. **The SBOM comes from Trivy's own pass**, through `trivy convert`, if its component
   count is within 5% of Syft's on the corpus; Syft is then removed (F2.2).
4. **OSV-Scanner's offline database joins `offline`** if it reports acceptance
   repository 8's planted `MAL-` package with no network.
5. **Every Trivy call passes `--disable-telemetry` and `--skip-version-check`**: with a
   network, Trivy logs *sending anonymous telemetry* (N2.1, ADR-0010).

## Rejected

- **Trivy for all infrastructure.** A third of Checkov's rules on the one measured
  repository.
- **actionlint.** zizmor covers its injection check, and its shellcheck integration is
  GPL-3.0 (ADR-0005).
- **GuardDog.** It downloads packages to analyse them, so it can never run on `offline`.
