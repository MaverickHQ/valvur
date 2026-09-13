# Positioning & market thesis

> Source of truth for all marketing copy, README claims and pitch material.
> Any public claim must be traceable to this document. Written 2026-08-29.
> **Working name:** `valvur` (Estonian: *guard, watchman*). Provisional until first publish.

---

## 1. The one-sentence thesis

> Every serious code-security scanner sends your code, or metadata about it, to
> someone else's servers. For a large and growing population of developers that
> is not a preference problem — it is a compliance wall. We are the tool on the
> other side of that wall.

## 2. Why now

Two trends collide:

1. **AI writes a rapidly growing share of production code**, and it fails in
   ways classic scanners were never built to catch — hallucinated dependencies
   that attackers pre-register, poisoned agent instruction files, hidden Unicode
   directives, model output flowing into shells and interpreters.
2. **Data-residency and code-confidentiality rules are tightening**, while the
   entire security-scanning market has consolidated onto SaaS delivery.

The intersection — *security scanning for AI-generated code that never leaves
the machine* — is currently unserved.

## 3. Target segments

### Primary — regulated industries that cannot send code to a vendor
Finance, defence, healthcare, government, critical infrastructure.
For these buyers "your manifest is analysed on our servers" is not a privacy
concern to be negotiated; it ends the evaluation. They currently choose between
weak local tooling and a lengthy vendor-risk process. **This is the beachhead.**

### Primary — data-residency-constrained jurisdictions
Cloud code-analysis services ship in a small number of regions. Anything
outside them is non-compliant by construction, regardless of encryption or
private networking. A fully offline tool has **no residency question to
answer** — the strongest possible compliance posture, because the control is
architectural rather than contractual.

### Secondary — teams shipping AI-generated code
Need checks nobody else runs: slopsquat/dependency-reality, agent-config
auditing, hidden Unicode, LLM-output-to-sink taint.

### Secondary — individual developers and OSS maintainers
One command, no account, useful output in under 60 seconds, free at any scale.

## 4. Competitive landscape — verified, fair

| | Where code is processed | Account required | Fully offline | Regions / residency | AI-code checks | Cost |
|---|---|---|---|---|---|---|
| **This tool** | **Your machine** | **No** | **Yes** | **N/A — never leaves** | **Yes** | Free |
| Snyk CLI | Snyk servers | Yes (`snyk auth`) | No | Vendor-controlled | Partial, SaaS-coupled | Free tier, then paid |
| AWS Transform custom | AWS Batch / Fargate | Yes (AWS account) | No | **us-east-1, eu-central-1 only** | No | Paid |
| SonarQube (self-hosted CE) | Your infrastructure | No | Largely yes | Yours | No | Free CE, paid tiers |
| SonarCloud | Sonar servers | Yes | No | Vendor-controlled | No | Free OSS, paid private |
| GitHub Advanced Security | GitHub | Yes | No | GitHub-controlled | No | Paid |

**Being fair about AWS Transform custom** — accuracy here protects our
credibility, and the true picture is favourable to us anyway. AWS Transform
custom performs static analysis and does not modify your code. Your repository
is *ephemerally cloned into AWS*, processed on AWS Batch and Fargate, and
purged when the job completes. It supports customer-managed KMS keys and
AWS PrivateLink, so traffic need not cross the public internet.

**PrivateLink keeps your code off the internet; it does not keep it on your
hardware.** And it is available in two regions — US East (N. Virginia) and
Europe (Frankfurt). An organisation under UK-, Swiss-, Canadian-, Australian-,
Indian- or Gulf-only residency requirements cannot use it compliantly at all.

> Do **not** claim AWS "says it doesn't send your code." That is false and
> trivially disproved. The accurate, stronger claim is: *your code goes to AWS
> ephemerally, in one of two regions; ours never leaves your machine.*

**Being fair about SonarQube** — self-hosted Community Edition keeps code on
your infrastructure, so residency is not our differentiator against it. Our
differentiators there are scope (SCA, secrets, IaC, containers, SBOM, licence,
AI-specific checks vs quality-first), exploit-aware prioritisation, agent-native
output, and no server to run.

## 5. The three claims

Everything in the README and any pitch reduces to these:

### Claim 1 — "It cannot exfiltrate your code, and you can prove it."
Not a privacy policy: a demonstrable property. Read-only source mount,
`--network=none` on the default `offline` profile, published SBOM, signed image,
reproducible build, and a documented command a security reviewer runs to verify
it themselves. **SaaS competitors structurally cannot make this claim.**

### Claim 2 — "Security for AI-generated code."
Slopsquatting, agent-config auditing, hidden Unicode, LLM-output-to-sink taint.
A new, unclaimed category. Competitors' entries into it inherit their trust
model — the SaaS answer to an AI-code problem still ships your code offsite.

### A measured limit on Claim 2, recorded 2026-09-13

**"LLM-output-to-sink taint" is a rule set, not a demonstrated capability.** Four
Opengrep rules ship for it. Measured on twelve real repositories, one of them an LLM
tool (task 22.E.2; twelve since the corpus run of 2026-09-13), they fired zero times — because no repository in the corpus
executes model output, which makes the result *unmeasured* rather than a pass or a
fail. The rules' sources are three SDK call shapes; anything reaching a sink through
LangChain, litellm, ollama, or a helper that unwraps `.choices[0].message.content` is
outside them today (task 23.5.3).

Consequences for what we say:
- Claim 2 rests on **slopsquatting, agent-config auditing and hidden Unicode** —
  each measured on real code and each carried by a Check that reports its own
  coverage. Lead with those.
- The rules may be **listed**, with what they match and that they have not fired on
  real code (the README does this since 24.2). They may not be listed as a feature
  a buyer is getting, until a corpus measurement shows them catching something.
- §10 of CLAUDE.md applies: a coverage claim we do not hold is prohibited, and the
  one in the README until 2026-09-13 was that.

### A measured limit on Claim 3, recorded 2026-08-30

**CISA KEV barely covers application dependencies.** Measured directly: across
PyYAML, urllib3, Django, Jinja2 and Pillow there are **269 CVEs and exactly one in
KEV**. The catalogue is overwhelmingly vendor appliances and enterprise software —
Microsoft 386 entries, Cisco 96, Apple 94, of 1,685 total.

Consequences for what we say:
- For a pure-Python or pure-JavaScript project, **EPSS does most of the ranking
  work**, not KEV. The inversion example in the README is real but will fire rarely
  on application dependencies alone.
- KEV earns its place mainly on **container and OS packages**, which is the `full`
  Profile's image scanning.
- Do **not** imply that KEV routinely reorders a typical application scan. It does
  not, and a knowledgeable reviewer will know it does not.

### Claim 3 — "Ten things that matter, not four hundred findings."
Dev-dependencies demoted, KEV/EPSS-ranked, dependency paths with exact upgrade
targets. Every scanner brags about finding more; we brag about finding **less,
better**. Signal quality is the most common complaint in this category and it
is winnable by a small team, because it is a design problem, not a data
problem.

## 6. Requirements derived from positioning

These are commitments, tracked as non-functional requirements in the spec.

| ID | Requirement |
|---|---|
| P1 | **Zero-config first run.** One command, no account, useful output in under 60 seconds. First-run friction is the biggest determinant of OSS adoption. |
| P2 | **Every finding traceable.** `raw/` plus `run.json` let a reviewer verify any finding against the tool and version that produced it. "Show me why you flagged this" is a procurement question in regulated industries. |
| P3 | **No lock-in, stated loudly.** SARIF and CycloneDX out, primary-source intel in. Users can leave whenever they like, and we say so. |
| P4 | **Credit the scanners prominently.** Trivy, Gitleaks, Opengrep, Checkov, OSV-Scanner and Syft do the detection. Being upfront builds more trust than implying proprietary magic — and it is simply what is true. |
| P5 | **Verifiable non-exfiltration.** Documented commands a reviewer can execute unaided, covering both halves of the claim: `--network=none` on every Scanner container, and no connection opened by the host shim. On Linux `unshare -rn` proves both at once at the OS level; macOS has no equivalent and the honest substitute is to disconnect the machine. Stating the platform limit is part of the requirement — a proof that only works where we say it does is still a proof; one we imply works everywhere is not. |
| P6 | **Dual-audience documentation.** README addresses developers and AI coding agents separately; results are self-describing for agents that never read the README. |

## 7. Defensibility

Snyk, GitHub and Semgrep will all enter AI-code security — the category is too
obvious to stay unclaimed. **The feature list is not defensible.**

What is defensible is being the **trusted local-first option**, because copying
it means breaking their own business model. Every time a feature would improve
results by sending data somewhere, that is the moat being traded away.

Risks to manage honestly:
- **A credible OSS competitor adopts the same posture.** Mitigation: be first,
  be genuinely good at signal quality, build the agent-native contract others
  must retrofit.
- **Detection quality gap vs commercial tools.** Mitigation: never claim
  parity. We win on trust, breadth-in-one-artifact and prioritisation, not on
  SAST depth. Say so plainly.
- **Maintenance burden of six upstream scanners.** Mitigation: pinned versions,
  a thin adapter per tool, and normalisation tested against captured `raw/`
  fixtures.

## 8. Messaging

**One-liner:**
> A fully offline security scanner for AI-generated code — your source never
> leaves your machine, and you can prove it.

**30 seconds:**
> Every serious code scanner ships your code, or metadata about it, to someone
> else's servers. If you work in finance, defence, healthcare or government —
> or under data-residency rules — that ends the conversation. This runs
> entirely on your machine, with networking switched off and your source
> mounted read-only, so exfiltration isn't a promise in a privacy policy, it's
> a property you can verify in one command. It orchestrates six best-of-breed
> open source scanners, ranks findings by whether attackers are actually
> exploiting them rather than by CVSS theatre, and adds checks nobody else runs
> for AI-generated code — hallucinated dependencies attackers pre-register,
> poisoned agent instruction files, hidden Unicode. Results land in your repo
> in a format your coding agent can act on, and they're never committed.

**What not to say:** never claim reachability analysis, proprietary detection,
parity with commercial SAST, or that competitors do not send code when they do.
