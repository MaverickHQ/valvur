<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/logo-dark.svg">
  <img src="docs/logo-light.svg" alt="valvur" width="280">
</picture>

**Offline security scanning for AI-generated code.**<br>
Your source never leaves your machine, and you can prove it.

[![PyPI](https://img.shields.io/pypi/v/valvur)](https://pypi.org/project/valvur/) [![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](https://pypi.org/project/valvur/) [![CI](https://github.com/MaverickHQ/valvur/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/MaverickHQ/valvur/actions/workflows/ci.yml) [![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/MaverickHQ/valvur/badge)](https://scorecard.dev/viewer/?uri=github.com/MaverickHQ/valvur) [![Licence: Apache-2.0](https://img.shields.io/badge/licence-Apache--2.0-blue)](LICENSE)
<br><sub>Scorecard's Code-Review, Branch-Protection and Contributors checks need a second maintainer; valvur has one ([MAINTAINERS.md](MAINTAINERS.md)).</sub>

</div>

> **Status: `1.5.0`**, the version this tree declares; the PyPI badge above shows what `pip install valvur` serves, and [the CHANGELOG](CHANGELOG.md) what each version changed.

**In Claude Code:** `/plugin marketplace add MaverickHQ/valvur`, then `/plugin install valvur@valvur`, and ask it to scan the project.
**From a terminal,** with Docker or Podman running: `uvx valvur scan`.

![valvur scans a project whose lockfile pins a package published as malicious, and lists the findings](docs/demo.svg)

## Why valvur

- **Nothing leaves your machine, provably.** No account, no API key, no telemetry. The
  Scanners run in one container with no network interface, and your source is copied in,
  never mounted. Every fetch of public data is recorded in `run.json`, beside what left
  the machine: nothing. [One command checks it.](docs/HOW-IT-WORKS.md#1-it-cannot-exfiltrate-your-code-and-you-can-verify-it)
- **Built for how AI-generated code breaks.** Models invent package names that attackers
  then register; agent instruction files carry injected directives and hidden Unicode;
  agent settings leak tokens. valvur checks for each, offline, beside the classic
  secrets, vulnerable dependencies and misconfigurations.
- **Ten findings that matter, not four hundred.** Findings are ranked by whether attackers
  are exploiting them, from CISA KEV and FIRST EPSS rather than CVSS alone, grouped by rule
  and directory, with development-only dependencies demoted.
- **You stay in charge.** valvur proposes fixes and never applies them. An agent told to
  reach zero findings can delete code or write suppressions instead, and *the finding
  disappeared* is not *the vulnerability is fixed*.

## What it finds

| | what valvur reports | found by |
|---|---|---|
| **Hallucinated packages** | dependencies that do not exist, or sit one edit from a popular name, checked offline against every name on PyPI, npm, RubyGems, Packagist and crates.io | valvur's `dependency-reality` Check |
| **Malicious packages** | dependencies published as malicious, from OpenSSF's malicious-packages | OSV-Scanner, and the same Check |
| **Agent configuration** | injected directives, hidden Unicode, unpinned MCP servers, blanket approval, hooks that run a command, settings that would leak | valvur's `ai-artifact` Check |
| **Vulnerable dependencies** | known CVEs from lockfiles, ranked by exploitation, with the direct package to bump | Trivy, OSV-Scanner |
| **Secrets** | credentials in the files and in git history | Gitleaks |
| **Code** | injection, path traversal, SSRF, open redirects, XXE and insecure cookies, and model output reaching `eval`, a shell, a query or the DOM | Opengrep, with valvur's rules |
| **Infrastructure** | Terraform, CloudFormation, Kubernetes and Dockerfile misconfiguration | Checkov |
| **CI workflows** | unpinned actions, write permissions, template injection | zizmor |
| **Licences and SBOM** | a missing or contradictory project licence; a CycloneDX SBOM when asked for | valvur's `licence-file` Check, Syft |

What it checks, rule by rule, and what it cannot see: [how valvur works](docs/HOW-IT-WORKS.md).

## How it works

1. **A small host shim** decides what a scan reads (the files git would publish, plus
   `.env*` files and agent configuration), fetches the public data it needs, and records
   each fetch.
2. **One Scan Container**, with no network interface, runs every Scanner over a copy of
   those files fed on stdin. Nothing in it can change your source.
3. **One findings model** normalises and ranks what they report, and the shim writes the
   Results Folder into your project:

```
.security-scan/          ← ignores itself in git, so it is never committed
├── SUMMARY.md           ← start here: the verdict, anything that failed, the top groups
├── REMEDIATION.md       ← a ranked proposal: you choose what to apply
├── findings.json        ← every finding, normalised, secrets redacted
├── results.sarif        ← SARIF 2.1.0, for code scanning and IDEs
└── run.json             ← what ran, what was fetched, and what left the machine: nothing
```

A scan ends `findings`, `clean` or `inconclusive`. It never says `clean` when stale data,
an uninspected ecosystem or a Scanner that did not finish cannot support it, and it says why.

## Measured, not claimed

How much of what valvur claims it finds is measured as **the Score**: eight tracks scored
by the OWASP Benchmark's formula, with a ratchet that no change may fall more than two
points under. It is **73.4** out of 100, the same on Linux and on macOS.

| track | what it holds | score |
|---|---|---|
| sast-python | the OWASP Benchmark for Python | 40.9 |
| sast-js | valvur's JavaScript twins: ten weaknesses, vulnerable and fixed | 55.0 |
| secrets | ten formats, in files and in history | 100.0 |
| dependencies | lockfiles pinned to vulnerable versions; known-malicious packages | 100.0 |
| package-reality | nonexistent, near-miss and malicious names | 100.0 |
| agent-configuration | planted directives and hidden Unicode, against real files | 94.3 |
| infrastructure | Terraform, Kubernetes, Dockerfile and Actions faults | 95.0 |
| real-code-precision | 48 maintained projects, every finding labelled by hand | 2.3 |

Track 8 is precision on maintained code, where almost nothing is a vulnerability: 3 of its
171 findings are real. Each rule's precision is in [`docs/RULES.md`](docs/RULES.md), and
the method, the gates and what valvur does **not** claim are in
[`docs/EVALUATING.md`](docs/EVALUATING.md). Read that one sceptically.

## Use it

### In an AI coding agent

The Claude Code plugin brings the MCP server, a skill that runs the workflow, and a hook
that asks you before the agent installs a package valvur flags. Kiro takes it as a power.
Any MCP client runs the server with `uvx --from valvur valvur-mcp`.
[The agents' guide](docs/AGENTS.md) has the configuration for eleven clients, the seven
tools, and the permissions a *don't ask* mode needs.

### From the command line

The Scanners run in a container, so the machine needs Docker or Podman; `valvur doctor`
says what is missing.

```bash
pip install valvur          # or: uv tool install valvur
valvur scan                 # offline by default; --profile full adds the registries' answers
valvur check npm left-pad   # before an install: real, a near-miss, or malicious?
valvur gate . --fail-on high --no-inconclusive
```

[The command-line guide](docs/CLI.md) has every command, what a first scan fetches, the
Results Folder, and the settings files.

### In CI

```yaml
- uses: MaverickHQ/valvur-action@16b19e275f843419887873ed536a71f872607e24 # v0.2
  with: { fail-on: high, no-inconclusive: "true" }
```

The action scans, uploads `results.sarif` to code scanning and gates the job.
[The CI guide](docs/CI.md) covers the gate, the image as a step of its own, and GitLab.

## Built on open-source scanners

valvur builds no detection engine. Seven open-source Scanners do that and deserve the
credit; valvur adds one File Set, one findings model, exploit-aware ranking, and three
Checks of its own. All of them run in one container, fed a copy of the files. `run.json`
records the version of each that ran, and `raw/` keeps what each said.

| Scanner | Licence | Reads | Runs |
|---|---|---|---|
| [Gitleaks](https://github.com/gitleaks/gitleaks) | MIT | Secrets in the files scanned and in git history, the newest 5,000 commits or 200 MB | always |
| [Trivy](https://github.com/aquasecurity/trivy) | Apache-2.0 | Known vulnerabilities in dependencies, from lockfiles, against its database in the host cache | always |
| [OSV-Scanner](https://github.com/google/osv-scanner) | Apache-2.0 | Lockfiles against OSV's data, which carries the known-malicious `MAL-` packages nothing else here reports. On `offline`, OSV's offline database for each ecosystem present, fetched into the host cache; on `full`, OSV.dev's API, which receives lockfile names and versions | always |
| [Opengrep](https://github.com/opengrep/opengrep) | LGPL-2.1 | Static analysis: pinning rules, a sink inventory at INFO, taint rules from a model call to a sink, and taint rules from request data | always |
| [Checkov](https://github.com/bridgecrewio/checkov) | Apache-2.0 | Infrastructure misconfiguration: Terraform, CloudFormation, Kubernetes, Dockerfiles, other CI systems | where there is infrastructure other than GitHub workflows |
| [zizmor](https://github.com/zizmorcore/zizmor) | MIT | GitHub Actions workflows: unpinned actions, write permissions, template injection | where there are workflows |
| [Syft](https://github.com/anchore/syft) | Apache-2.0 | The SBOM, and the dependency licences read from it | when asked for: `scan --sbom`, or `sbom = true` under `[scan]` |

| Check | Reads |
|---|---|
| `ai-artifact` | Agent configuration: injected directives, hidden Unicode, unpinned MCP servers, blanket approval, hooks that run a command, and local settings that would leak |
| `dependency-reality` | Every declared dependency against the Name Index: does it exist, and on `full`, how old and how adopted is it. Every declared or locked one against the known-malicious list, built daily from OpenSSF's malicious-packages |
| `licence-file` | The project's own licence: missing, or contradicting what the manifest declares |

Exploit intelligence comes from CISA KEV and FIRST EPSS: public primary sources,
auditable and mirrorable. No proprietary database, and nothing to lock you in.

## What it does not do

- **No reachability analysis.** We do not prove a vulnerable function is called.
- **No autonomous fixing.** You choose the fixes.
- **No penetration testing.** No DAST, no exploitation, no scanning of deployed systems.
- **No code-quality analysis.** Security only.
- **We will not out-detect commercial SAST.** We win on trust, breadth in one
  artifact, and prioritisation, not on engine depth.

## Platforms

| | |
|---|---|
| Linux, Docker **and** Podman | **Supported**. Every commit runs the e2e suite against Docker and Podman on `amd64`, and against Docker on `arm64`, and a scan with the published image on both; the acceptance set runs nightly on GitHub's Linux runner |
| macOS, Docker Desktop or Podman | **Supported**, and tested by hand on an Apple-silicon Mac through Docker Desktop at every phase's exit: the acceptance set and the e2e suite against the image built from that commit ([`docs/acceptance/`](docs/acceptance/)). Not on every commit: a container runtime needs nested virtualisation, which GitHub's macOS runners do not offer |
| `linux/amd64` and `linux/arm64` | Both, **from 0.2.0**. `0.1.0rc1` was published `arm64` only, a defect and not a policy |
| Windows via **WSL2** | Supported: inside WSL valvur is running on Linux |
| Native Windows | **Not claimed.** Untested, and valvur says so at startup |
| SELinux-enforcing hosts (RHEL, Fedora) | Supported. Your source is copied into the scan and never mounted, so its SELinux label does not matter; valvur labels its own cache mounts |

**Air-gapped?** The database, the Name Index and its malicious list, KEV, EPSS and
OSV's databases all live outside the image, and each has a mirror setting. See [`docs/AIR-GAPPED.md`](docs/AIR-GAPPED.md).

## Privacy

valvur collects nothing: no account, no API key, no telemetry, and no part of it reports on
you or your code. The results stay in `.security-scan/`, which ignores itself in git. What
the host fetches is public data, each fetch recorded in `run.json`.
`python3 scripts/verify-offline.py` checks it, and on Linux `unshare -rn valvur scan` proves
it ([how](docs/HOW-IT-WORKS.md#1-it-cannot-exfiltrate-your-code-and-you-can-verify-it)).

## Documentation

| guide | for |
|---|---|
| [How it works](docs/HOW-IT-WORKS.md) | the offline proof, every check, and the ranking |
| [AI coding agents](docs/AGENTS.md) | the plugin, the power, eleven MCP clients and the seven tools |
| [Command line](docs/CLI.md) | the commands, the Results Folder and the settings |
| [CI](docs/CI.md) | the gate, the GitHub Action and the image in a pipeline |
| [Evaluating valvur](docs/EVALUATING.md) | the audit: the Score, the gates and the limits |
| [Rules](docs/RULES.md) | each static-analysis rule's measured precision |
| [Air-gapped use](docs/AIR-GAPPED.md) | mirrors for every data source |
| [Every document](docs/README.md) | the protocol, the decisions, releasing and the records |

## Community and support

- **Questions and ideas:** [Discussions](https://github.com/MaverickHQ/valvur/discussions).
- **Bugs, and findings valvur missed:** https://github.com/MaverickHQ/valvur/issues, with
  the tarball `valvur doctor --bundle` writes: versions and the last `run.json`, never your
  source, raw output or findings.
- **Security:** a suspected vulnerability in valvur, a false `clean` included, goes
  privately by [SECURITY.md](SECURITY.md).
- **Contributing:** [CONTRIBUTING.md](CONTRIBUTING.md) has the setup and the short list of
  what is refused on principle. [MAINTAINERS.md](MAINTAINERS.md) says who maintains valvur,
  one person today, and what you can rely on. There is no paid tier and no support contract.

## Licence

Apache-2.0, see [LICENSE](LICENSE); chosen over MIT for the explicit patent grant.
Bundled Scanners keep their own licences, listed above and in [NOTICE](NOTICE). valvur
adds no GPL or AGPL component; the Alpine base carries GPL userland as every Linux
container does, and the published SBOM discloses all of it
([ADR-0005](docs/adr/0005-no-gpl-tools-in-the-image.md)).
