# What a finding is mapped to: CWE and OWASP's lists

Every finding names the weakness its rule or advisory names, as `cwe`, and the OWASP
categories its rule is mapped to, as `owasp`. They are in `findings.json`, in
`results.sarif` as taxonomies, relationships and tags, and in the `findings` reply.
`valvur findings --owasp A05:2025` lists one category's findings, and `SUMMARY.md` counts
by category once a scan has more than one.

**The word is *mapped to*, and it is the whole claim.** A mapping says where a finding
sorts in a taxonomy your other tools and your auditors already use. It says nothing about
how much of a category valvur detects: one rule mapped to a category is one rule. Nothing
valvur writes says *covers*, *complies* or *certified* of a list, and a test holds every
document and every output to that. What valvur measures about its own detection is
[the Score](EVALUATING.md), by rule in [`RULES.md`](RULES.md).

The mapping is one file, `src/valvur/data/identifiers.toml`, and this page is generated
from it. Neither field is part of a finding's identity: no fingerprint changed when they
were added.

## The lists and their editions

Each list was read from OWASP's own pages on the day shown. A new edition changes the IDs
(injection was A03 in 2021 and is A05 in 2025), so the file names the edition and
`findings --owasp` refuses a category that is in none of them.

<!-- generated: identifier-lists -->

| list | edition | read from OWASP's pages on | mapped to |
|---|---|---|---|
| OWASP Top 10 | 2025 | 2026-11-23 | yes, 10 categories |
| OWASP Top 10 for LLM Applications | 2025 | 2026-11-23 | yes, 10 categories |
| OWASP Top 10 for Agentic Applications | 2026 | 2026-11-23 | yes, 10 categories |
| Agentic AI: Threats and Mitigations | 1.1 | 2026-11-23 | no. Read and not mapped to: the Top 10 for Agentic Applications is the list OWASP publishes to be cited, and of its threats T1 to T17 the name of T14 could not be read from the document. |

<!-- /generated -->

## How a finding gets its entry

A rule is looked up by its ID, then by the longest prefix of it, then by its Scanner, then
by its Finding Class. An entry may say `none`, and then says why.

- **A rule with a CWE** sits in the OWASP Top 10 category whose own list of mapped CWEs
  holds that CWE. A test holds every entry to OWASP's lists.
- **The categories of the LLM and agentic lists** are valvur's reading of each list's
  text: neither publishes a CWE mapping to look them up in.
- **A dependency vulnerability** keeps the CWE its advisory gives, where Trivy or
  OSV-Scanner reports one, and takes its Scanner's category: the fix is an upgrade,
  whatever the weakness inside the package.
- **Gitleaks', Checkov's and zizmor's rules** cannot be listed from valvur's repository,
  so each Scanner has one entry.

<!-- generated: identifier-rules -->

### By rule

Every rule valvur writes or vendors, and every Check and note of its own.

| rule or Check | CWE | mapped to |
|---|---|---|
| `javascript_eval_rule-eval-with-expression` | CWE-95 | A05:2025 Injection |
| `python_deserialization_rule-yaml-load` | CWE-502 | A08:2025 Software or Data Integrity Failures |
| `python_random_rule-random` | CWE-338 | A04:2025 Cryptographic Failures |
| `python_sql_rule-hardcoded-sql-expression` | CWE-89 | A05:2025 Injection |
| `valvur.ai-artifact.blanket-auto-approve` | none | LLM06:2025 Excessive Agency; ASI02 Tool Misuse and Exploitation |
| `valvur.ai-artifact.coercive-directive` | none | LLM01:2025 Prompt Injection; ASI01 Agent Goal Hijack |
| `valvur.ai-artifact.credential-harvesting` | none | LLM01:2025 Prompt Injection; LLM02:2025 Sensitive Information Disclosure; ASI03 Identity and Privilege Abuse |
| `valvur.ai-artifact.exfiltration-directive` | none | LLM01:2025 Prompt Injection; LLM02:2025 Sensitive Information Disclosure; ASI01 Agent Goal Hijack |
| `valvur.ai-artifact.hidden-unicode` | none | LLM01:2025 Prompt Injection; ASI01 Agent Goal Hijack |
| `valvur.ai-artifact.hook-runs-command` | none | LLM06:2025 Excessive Agency; ASI05 Unexpected Code Execution |
| `valvur.ai-artifact.local-config-exposed` | none | A02:2025 Security Misconfiguration; LLM02:2025 Sensitive Information Disclosure |
| `valvur.ai-artifact.mcp-mutable-ref` | CWE-829 | A08:2025 Software or Data Integrity Failures; LLM03:2025 Supply Chain; ASI04 Agentic Supply Chain Vulnerabilities |
| `valvur.ai-artifact.permission-bypass` | none | LLM06:2025 Excessive Agency; ASI02 Tool Misuse and Exploitation |
| `valvur.ai-artifact.prompt-injection` | none | LLM01:2025 Prompt Injection; ASI01 Agent Goal Hijack |
| `valvur.dependency.confusion` | CWE-1357 | A03:2025 Software Supply Chain Failures; LLM03:2025 Supply Chain |
| `valvur.dependency.ecosystem-not-covered` | none | none: A statement about what valvur read, not a weakness in the code. |
| `valvur.dependency.malicious` | CWE-506 | A03:2025 Software Supply Chain Failures; A08:2025 Software or Data Integrity Failures; LLM03:2025 Supply Chain; ASI04 Agentic Supply Chain Vulnerabilities |
| `valvur.dependency.near-miss` | CWE-1357 | A03:2025 Software Supply Chain Failures; LLM03:2025 Supply Chain |
| `valvur.dependency.newly-registered` | CWE-1357 | A03:2025 Software Supply Chain Failures; LLM03:2025 Supply Chain |
| `valvur.dependency.nonexistent` | CWE-1357 | A03:2025 Software Supply Chain Failures; LLM03:2025 Supply Chain; LLM09:2025 Misinformation |
| `valvur.dependency.not-public` | none | none: A statement about what valvur read, not a weakness in the code. |
| `valvur.dependency.private-registry` | none | none: A statement about what valvur read, not a weakness in the code. |
| `valvur.dependency.vulnerabilities-unchecked` | none | none: A statement about what valvur read, not a weakness in the code. |
| `valvur.javascript.command-injection` | CWE-78 | A05:2025 Injection |
| `valvur.javascript.insecure-cookie` | CWE-614 | A02:2025 Security Misconfiguration |
| `valvur.javascript.path-traversal` | CWE-22 | A01:2025 Broken Access Control |
| `valvur.javascript.sql-injection` | CWE-89 | A05:2025 Injection |
| `valvur.javascript.ssrf` | CWE-918 | A01:2025 Broken Access Control |
| `valvur.js.output-to-innerhtml` | CWE-79 | A05:2025 Injection; LLM05:2025 Improper Output Handling |
| `valvur.licence.copyleft-in-permissive` | none | none: A licence is a legal matter, and none of these lists has a category for one. |
| `valvur.licence.dependencies-unreadable` | none | none: A licence is a legal matter, and none of these lists has a category for one. |
| `valvur.licence.dependency-unknown` | none | none: A licence is a legal matter, and none of these lists has a category for one. |
| `valvur.licence.mismatch` | none | none: A licence is a legal matter, and none of these lists has a category for one. |
| `valvur.licence.missing` | none | none: A licence is a legal matter, and none of these lists has a category for one. |
| `valvur.licence.unidentified` | none | none: A licence is a legal matter, and none of these lists has a category for one. |
| `valvur.llm.model-call` | none | none: A mark valvur reads to write one note. It reports nothing by itself. |
| `valvur.llm.output-not-followed` | none | none: A statement about what valvur read, not a weakness in the code. |
| `valvur.llm.output-to-code-execution` | CWE-94 | A05:2025 Injection; LLM05:2025 Improper Output Handling; ASI05 Unexpected Code Execution |
| `valvur.llm.output-to-shell` | CWE-78 | A05:2025 Injection; LLM05:2025 Improper Output Handling; ASI05 Unexpected Code Execution |
| `valvur.llm.output-to-sql` | CWE-89 | A05:2025 Injection; LLM05:2025 Improper Output Handling |
| `valvur.pinning.mutable-git-ref` | CWE-829 | A08:2025 Software or Data Integrity Failures |
| `valvur.python.code-injection` | CWE-95 | A05:2025 Injection |
| `valvur.python.command-injection` | CWE-78 | A05:2025 Injection |
| `valvur.python.dangerous-eval` | CWE-95 | A05:2025 Injection |
| `valvur.python.dangerous-exec` | CWE-95 | A05:2025 Injection |
| `valvur.python.insecure-cookie` | CWE-614 | A02:2025 Security Misconfiguration |
| `valvur.python.insecure-yaml-load` | CWE-502 | A08:2025 Software or Data Integrity Failures |
| `valvur.python.open-redirect` | CWE-601 | A01:2025 Broken Access Control |
| `valvur.python.path-traversal` | CWE-22 | A01:2025 Broken Access Control |
| `valvur.python.string-built-sql` | CWE-89 | A05:2025 Injection |
| `valvur.python.subprocess-shell-true` | CWE-78 | A05:2025 Injection |
| `valvur.python.tls-verification-off` | CWE-295 | A07:2025 Authentication Failures |
| `valvur.python.weak-hash` | CWE-328 | A04:2025 Cryptographic Failures |
| `valvur.python.xml-external-entities` | CWE-611 | A02:2025 Security Misconfiguration |
| `valvur.suppression.expired` | none | none: About the project's own record of accepted risks, not a weakness in the code. |
| `valvur.suppression.invalid` | none | none: About the project's own record of accepted risks, not a weakness in the code. |
| `valvur.suppression.stale` | none | none: About the project's own record of accepted risks, not a weakness in the code. |
| `valvur.vex.not-honoured` | none | none: About the project's own record of accepted risks, not a weakness in the code. |
| `valvur.vex.unused` | none | none: About the project's own record of accepted risks, not a weakness in the code. |

### By prefix

For a rule or Check with no entry of its own.

| a rule that starts with | CWE | mapped to |
|---|---|---|
| `valvur.ai-artifact.` | none | LLM01:2025 Prompt Injection |
| `valvur.dependency.` | none | A03:2025 Software Supply Chain Failures |
| `valvur.licence.` | none | none: A licence is a legal matter, and none of these lists has a category for one. |

### By Scanner

For the rules that cannot be listed from valvur's repository. A dependency vulnerability keeps the CWE its advisory gives.

| Scanner | CWE | mapped to |
|---|---|---|
| `checkov` | none | A02:2025 Security Misconfiguration |
| `gitleaks` | CWE-798 | A07:2025 Authentication Failures |
| `osv-scanner` | none | A03:2025 Software Supply Chain Failures |
| `syft` | none | none: An SBOM is an inventory, and a component in it is not a finding. |
| `trivy` | none | A03:2025 Software Supply Chain Failures |
| `zizmor` | none | A03:2025 Software Supply Chain Failures |

### By Finding Class

When nothing above names the rule or its Scanner.

| class | CWE | mapped to |
|---|---|---|
| `IaC misconfiguration` | none | A02:2025 Security Misconfiguration |
| `dependency reality` | none | A03:2025 Software Supply Chain Failures |
| `dependency vulnerability` | none | A03:2025 Software Supply Chain Failures |
| `licence` | none | none: A licence is a legal matter, and none of these lists has a category for one. |
| `secret` | CWE-798 | A07:2025 Authentication Failures |
| `static analysis` | none | none: A static-analysis rule is mapped by its own entry, and this one has none. |

<!-- /generated -->

## The categories nothing is mapped to

No rule or Check is mapped to these, at any level. Most are properties of a design or of a
running system, which a scan of a repository does not see.

<!-- generated: identifier-unmapped -->

- **OWASP Top 10 2025:** A06:2025 Insecure Design; A09:2025 Security Logging and Alerting Failures; A10:2025 Mishandling of Exceptional Conditions
- **OWASP Top 10 for LLM Applications 2025:** LLM04:2025 Data and Model Poisoning; LLM07:2025 System Prompt Leakage; LLM08:2025 Vector and Embedding Weaknesses; LLM10:2025 Unbounded Consumption
- **OWASP Top 10 for Agentic Applications 2026:** ASI06 Memory & Context Poisoning; ASI07 Insecure Inter-Agent Communication; ASI08 Cascading Failures; ASI09 Human-Agent Trust Exploitation; ASI10 Rogue Agents

<!-- /generated -->
