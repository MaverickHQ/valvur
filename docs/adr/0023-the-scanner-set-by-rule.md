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

## Amendment, 2026-09-28: the measurements (R4.1)

On this Mac, the thirteen corpus checkouts and acceptance repositories 5 to 8, every tool
with no network; the scripts are in `scripts/spikes/`, the full record in
`docs/acceptance/r4.md`.

| rule | measured | verdict |
|---|---|---|
| 1. zizmor | 85 of 85 unpinned actions; 18 of 18 files with Checkov's write-permission finding, at `--persona pedantic --min-severity medium` (16 of 18 at the default persona); 1.1 s for sixteen repositories | **adopted** at that persona |
| 2. KICS | 14 of Checkov's 22 distinct failed rules on repositories 5 and 6 (64%); 10.0 s against Checkov's 63.3 s on the Terraform module, 9.6 s against 5.3 s on repository 6. Trivy: 12 of 22 (55%) | **Checkov stays**, only where there is infrastructure other than workflows: on the corpus, one repository of thirteen |
| 3. Trivy's SBOM | 205 components against Syft's 308 (66.6%); 205 against 209 without the 99 GitHub Actions Syft lists | **Syft stays**; by D9 the SBOM is written only with `--sbom` |
| 4. OSV offline | MAL-2023-1 on repository 8's `@hyperion-util/cookies`, with `--network=none`, in 10 s; npm's database is 207 MB | **joins `offline`** |

The corpus holds no infrastructure but the Terraform module: every other repository ran
Checkov for 4 to 6 s of startup to find nothing, now zizmor's work. KICS's misses are the
S3 hardening checks (public access block, lifecycle, events, replication, KMS) and the
module and availability-zone pins; licence, offline mode and pinning were checked for
zizmor (MIT, `--offline`, musl wheels by hash) before it enters the image.
