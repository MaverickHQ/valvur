# valvur

A fully offline security scanner for codebases, with particular attention to how
AI-generated code fails. It orchestrates third-party scanners, normalises their
output into a single model, ranks it by real-world exploitability, and writes it
where a developer or a coding agent can act on it.

## Language

### Scanning

**Scan Run**:
One complete invocation of valvur against one Workspace, producing one Results Folder.
_Avoid_: scan, job, execution, analysis

**Workspace**:
The developer's project being examined. Always mounted read-only; valvur never writes to it.
_Avoid_: project, repo, target, source directory, codebase

**Profile**:
The named breadth of a Scan Run — `quick`, `standard` or `deep` — determining which Scanners run and whether any network access is permitted.
_Avoid_: mode, level, preset, tier

**Scanner**:
A third-party tool that performs actual detection (Trivy, Gitleaks, Opengrep, Checkov, OSV-Scanner, Syft). valvur never detects anything itself.
_Avoid_: tool, engine, plugin, analyser

**Check**:
A detection valvur performs itself rather than delegating to a Scanner — the Dependency Reality Check, AI Artifact scan, pinning hygiene, and Licence Hygiene.
_Avoid_: rule, test, custom scanner

### Findings

**Finding**:
One problem identified in the Workspace, attributed to the Scanner or Check that produced it.
_Avoid_: issue, vulnerability, alert, violation, error, result

**Finding Class**:
The category a Finding belongs to — dependency vulnerability, secret, IaC misconfiguration, licence, dependency reality, or static analysis. Determines how its Fingerprint is derived.
_Avoid_: type, kind, category

**Fingerprint**:
A Finding's stable identity across Scan Runs, derived from its Finding Class's natural key. Never derived from line numbers. Byte-identical across machines.
_Avoid_: id, hash, key, signature

**Status**:
A Finding's relationship to the previous Scan Run — `new`, `persisting`, `fixed`, or `regressed`.
_Avoid_: state, disposition

**Redaction**:
The replacement of a secret's value with its Fingerprint before any Finding is written to disk. Applies to every written artifact without exception.
_Avoid_: masking, scrubbing, sanitising

### Prioritisation

**Enrichment**:
Exploitability information attached to a Finding to rank it — distinct from the severity a Scanner assigns.
_Avoid_: metadata, context, intel, annotation

**Exploit Signal**:
Evidence that a vulnerability is exploited in reality rather than in theory: presence in CISA KEV, the KEV ransomware flag, and the FIRST EPSS probability.
_Avoid_: threat intel, exploit data

**Enrichment Provider**:
A source of Enrichment behind a common interface. The only Provider is local — a bundled KEV snapshot plus on-demand EPSS lookups.
_Avoid_: intel source, feed, backend

**Dependency Path**:
The chain from a direct dependency of the Workspace to a vulnerable transitive one, naming the direct package that must change.
_Avoid_: dependency chain, transitive path

**Slopsquat**:
A package registered by an attacker under a name that language models hallucinate. Detected by the Dependency Reality Check, not by any advisory database.
_Avoid_: typosquat, malicious package

### Output and disposition

**Results Folder**:
The `.security-scan/` directory written into the Workspace by the host, ignoring itself via its own `.gitignore`. Never committed.
_Avoid_: output directory, report directory, artifacts

**Provenance**:
The record of what a Scan Run actually did — Scanner versions, Enrichment age, what was skipped and why, what failed. Makes a clean result falsifiable.
_Avoid_: metadata, manifest, audit log

**Clean Scan**:
A Scan Run that completed with no Findings. Still writes a full Results Folder, so it is distinguishable from a Scan Run that never happened.
_Avoid_: pass, green, empty result

**Remediation Item**:
A proposed change addressing one or more Findings, ranked by Exploit Signal and independently applicable. A proposal for a human, never an instruction executed automatically.
_Avoid_: fix, recommendation, action, task

**Suppression**:
A recorded decision to accept a Finding, keyed by Fingerprint, carrying a mandatory expiry date. Lives in the Workspace and is committed — unlike the Results Folder.
_Avoid_: ignore, exception, waiver, mute, allowlist entry
