# Council brief — valvur codebase review

## Review goal

Perform a Level 400, codebase-wide assessment of valvur at `10ff462` through five
requested lenses: build, deploy, operations, architecture, and functionality. Produce
evidence-backed recommendations and an execution order that reduces risk early,
respects dependencies, and avoids parallel work that would create rework.

## Selected file set

The review set is recorded in `files.txt` (183 paths). It includes all production
Python under `src/`, all first-party rules and scripts, packaging and container build
inputs, all GitHub workflows, requirements/design/task records and ADRs, operational
documentation, and the complete non-fixture test suite. Generated outputs, vendored
dependencies, scanner golden payloads, and deliberately vulnerable fixture content
are excluded except for public schemas/snapshots that define a contract.

## Product and domain context

valvur 0.3.0 is a stdlib-only Python host shim plus a separately distributed OCI
scanner image. It orchestrates six third-party scanners and three in-container
first-party checks, normalises findings, ranks by exploit evidence, and writes a local
`.security-scan/` result set. The default `offline` profile promises that source and
dependency metadata do not leave the machine; the `full` profile explicitly permits
networked enrichment and lookups. CLI and a hand-rolled stdio MCP server share the
same operations layer. Users include regulated teams and coding agents, so false-clean
results, hidden data egress, supply-chain substitution, and ambiguous partial runs are
the primary hazards.

## Baseline evidence

- Worktree was clean before council artifacts were created.
- `./scripts/verify.sh` passed with network/socket access: Ruff, mypy over 57 source
  files, the traceability ratchet, 949 non-e2e tests (1 skipped, 29 deselected), and
  sdist/wheel builds.
- A local e2e/image-staleness run was not possible because `valvur:dev` is not present.
  The current GitHub `ci` run for `10ff462`, the v0.3.0 release run, and the latest
  scheduled index run are green.
- The review must therefore distinguish static/local evidence from CI-only container,
  dual-runtime, and published-artifact evidence.

## Load-bearing decisions

1. Source is mounted read-only; only the host shim writes result artifacts.
2. `offline` is the default and enforces `--network=none`; `full` is an opt-in trust
   boundary, not merely a larger ruleset.
3. Scanner/check failure yields an explicit incomplete result; findings do not fail a
   scan, while infrastructure failures do.
4. Findings, SARIF, summary, remediation, SBOM, raw outputs, and provenance are
   projections of one run model, with secret redaction and untrusted-text defanging.
5. The wheel and multi-architecture image are versioned together and compared by a
   source-tree digest; releases are signed and attested.
6. Vulnerability data and a daily package-name index live outside the image; staleness
   changes the meaning of a nil result.
7. MCP stays stdio-only and read-only with respect to source; remediation remains
   human-approved.

## Constraints and non-goals

- Preserve zero runtime Python dependencies unless evidence justifies changing the
  trust boundary.
- Preserve offline, no-account, no-telemetry, and non-autonomous-remediation promises.
- Native Windows, DAST, reachability analysis, hosted services, and an HTML UI are out
  of scope.
- Do not treat intentionally recorded product limitations as bugs unless the current
  implementation or documentation contradicts the chosen contract.
- This is a review only. Do not modify application code.

## Assumptions

- `main` at `10ff462` is the review target and represents the deployable source of
  truth.
- GitHub-hosted CI is the deployment control plane; GHCR, PyPI, TestPyPI, Rekor, and
  public registries are external dependencies that can fail independently.
- A successful current pipeline is evidence of present health, not proof that failure
  and race paths are sound.
- Documentation is part of functionality because agents and operators act on its
  claims.

## Open questions to carry into findings

- The v1 usability gate remains an owner/stranger exercise. Which production-readiness
  decisions should remain blocked on it?
- Is accepting an unverified package-name index when cosign is absent the intended
  long-term trust model, or only a 0.x availability tradeoff?
- Is post-publication artifact validation an accepted release risk, or should release
  promotion be made transactional before 1.0?
- What service-level expectation and alert/owner exists for the daily index and weekly
  corpus workflows beyond a red GitHub run?

## Review lanes to emphasize

- **Design:** central execution seams, duplicated container policy, host/image
  compatibility, and public contracts.
- **TDD:** race windows, platform-specific behavior, artifact promotion, trust fallback,
  and tests that can pass while a supported platform remains broken.
- **Engineering:** cancellation, partial failure, timeouts, filesystem/runtime
  portability, release atomicity, and false-clean risk.
- **Structural:** ownership among runner/orchestrator/pipeline/results, large parser and
  presentation modules, workflow topology, and documentation drift.
- **Ponytail:** remove duplicated launch/publish machinery and stale process narrative;
  do not recommend new platforms or services without a concrete failure mode.
