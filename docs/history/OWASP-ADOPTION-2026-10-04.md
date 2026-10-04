# valvur as an OWASP project: the requirements, the gap, and the plan (2026-10-04)

Written at the owner's request after `1.4.0`, when the owner asked how to maximise the
chance of valvur being adopted under OWASP, trading speed to submission against the
features that raise the odds. The phases are R30 to R37 in
[`tasks.md`](../../.kiro/specs/valvur/tasks.md) (D67 to D74), with a backlog in its §9.
Every OWASP rule below was read from its primary source on 2026-10-04; copies of each are in
the build's scratchpad, and each is cited by URL.

## 1. What OWASP requires

**Creating a project.** "New projects must be approved by the foundation", through the New
Project Request form ([Project Policy](https://owasp.org/www-policy/operational/projects),
adopted 2021-09-28, edited 2025-08-20). The Project Handbook's
[Creating a Project](https://github.com/OWASP/www-committee-project/blob/main/_includes/create_a_project.md)
asks for a name, the leaders' names, emails and GitHub usernames, "a short summary, a longer
description, and a roadmap", an OSI licence, and a review of the
[Good Practices](https://github.com/OWASP/www-committee-project/blob/main/_includes/good_practices.md).
Requests "can take some time to resolve". Every new project starts at **Incubator**; leaders
must create the `www-project-<name>` pages within 30 days of GitHub access.

**Hard rules.**
- "Each project must have a minimum of 2 and a maximum of 5 foundation-recognized, official
  leaders", and "project leaders are required to be members" ($50 a year). Leadership is
  personal, not tied to an employer.
- "Projects must use OWASP's recommended contributor agreement, DCO."
- OSI-approved licence for code; Creative Commons for documentation.
- New projects are required to use OWASP's source platform (an exception can be asked for);
  good projects live in the OWASP GitHub organisation, or a dedicated one when they span
  several repositories, with every leader an admin.
- "Projects must identify as an OWASP project in their branding."
- The leader agreement hands "all past, present and future contributions" to the Foundation,
  and a project "may not withdraw" once donated. The name stays with OWASP.
- The brand "must not be used in a manner that suggests that a product or technology is
  compliant with any OWASP Materials" ([branding](https://owasp.org/www-policy/operational/branding)).
- At least one release a year, or the project is reactivated or dissolved.

**Levels** ([Project Committee, promotions](https://owasp.org/www-committee-project/#div-promotions)).
Lab needs a major release, install and usage docs, a support queue, contribution guidelines,
3 to 6 months of age, and an OpenSSF Best Practices registration. Production adds yearly major
releases, "fully scoped usage documentation", managed onboarding, a GSoC, Summit or similar
event, "evidence of significant use", more than a year of age, and the **passing** badge.
Promotion reviews take 4 to 8 weeks. Flagship is a Board decision, not a level.

**Good practices** that are not rules: no paywalled features; the project's own social
presence; "multiple Project Leaders who are not all employed by the same company"; a name not
confused with a company's; a check for "a possibly existing similar OWASP project", and a
stated unique selling point.

## 2. The GenAI Security Project

It is governed by a Board, a Core Project Management Team (CPMT) and Initiative Leads, by lazy
consensus ([governance](https://genai.owasp.org/project-governance/)). A new **initiative** is
a 1 to 2 page proposal, reviewed by the core team within 4 weeks, posted to `#team-llm-core`
with "a minimally viable # of contributors", and voted by the CPMT and Board. **There is no
documented door for an outside tool:** every tool its GitHub organisation hosts came from one
of its own initiatives (DSGAI from Data Security, the Red Team Lab, the AIBOM generator, FinBot
CTF, the Agent Control Standard). Two close neighbours, the Agentic Skills Top 10 and the MCP
Top 10, are standalone Foundation **Incubator** projects; the first published its
[proposal](https://github.com/OWASP/www-project-agentic-skills-top-10) with sections for
overview, deliverables, scope, relationship to existing OWASP projects, timeline, leadership
and risks.

**The overlap to answer.** [DSGAI](https://github.com/GenAI-Security-Project/dsgai) audits a
GenAI codebase against the 21 controls of OWASP's GenAI Data Security Risks and Mitigations
2026, with a deterministic CLI (standard library and ripgrep), SARIF and a Claude Code skill.
It sends package names and versions to OSV and NVD. valvur is fully offline, orchestrates seven
open-source Scanners, and centres on AI-generated code and the agent's workflow: hallucinated
and malicious packages, injection in agent configuration, an install hook, a measured Score.
They complement each other, and the proposal says so before a reviewer does.

**The lists to map to.** The current LLM Top 10 is the **2026** edition (published 4 August
2026, [repository](https://github.com/GenAI-Security-Project/GenAI-LLM-Top10)), which
renumbers 2025's: LLM01 Prompt Injection, LLM02 Sensitive Information Disclosure, LLM03
Excessive Agency, LLM04 Supply Chain, LLM05 Data and Model Poisoning, LLM06 Unbounded
Consumption, LLM07 Misinformation, LLM08 Hidden Context Exposure, LLM09 Vector and Embedding
Weaknesses, LLM10 Improper Output Handling. It ships machine-readable mappings to ASI, CWE and
others. The Top 10 for Agentic Applications 2026 runs ASI01 to ASI10; the Agentic Skills Top
10 runs AST01 to AST10. OWASP publishes no SARIF tagging convention; the
[crosswalk](https://github.com/GenAI-Security-Project/crosswalk) is the closest machine-readable
reference.

## 3. What adopted OWASP tool projects have in common

| project | level | leaders | stars | contributors | releases, 12 months |
|---|---|---|---|---|---|
| Dependency-Check | Flagship | 1 | 7,716 | 384 | 7 |
| Dependency-Track | Flagship | 2 | 4,258 | 135 | 20 |
| Juice Shop | Flagship | 2 | 14,022 | 167 | 8 |
| DefectDojo | Flagship | 3 | 4,978 | 601 | 61 |
| Threat Dragon | Production | 4 | 1,618 | 111 | 5 |
| Nettacker | Lab | 4 | 5,638 | 91 | 1 |

From the GitHub API and each project's pages, 2026-10-04. What they share: a documentation
site; a place in workflows people already have (build plugins, Helm charts, 369 DefectDojo
parsers, an Ecma standard for CycloneDX); an OpenSSF Best Practices badge; a Slack channel or
community meeting; GSoC as a contributor pipeline; and, for Juice Shop, a teaching role that
put it in every training course.

## 4. Where valvur stands

| requirement or trait | valvur on 2026-10-04 | gap |
|---|---|---|
| 2 to 5 leaders, OWASP members, different employers | one maintainer | **blocking** |
| the owner's decision to donate | not taken | **blocking** |
| DCO | not used | yes |
| OSI licence | Apache-2.0 | none |
| roadmap, governance | `tasks.md` only; no `GOVERNANCE.md`, `ROADMAP.md` or `CODEOWNERS` | yes |
| similar OWASP project, USP | DSGAI not addressed | yes |
| OWASP's own taxonomies | LLM05 named in two rule comments; 2026 not mapped | yes |
| works with OWASP's flagships | SARIF and CycloneDX written; DefectDojo and Dependency-Track untested, undocumented | yes |
| documentation site | about 2,000 lines of Markdown | yes |
| support queue, contribution path | issues; no Discussions, no good-first issues, no dev container | yes |
| evidence of use | 0 stars, 0 forks, 0 outside issues or PRs; ~1,170 PyPI downloads a month | yes |
| OpenSSF Best Practices | answers prepared (R22.2); not submitted | owner |
| Scorecard | 5.7 published; R27 lifts what one maintainer can | in hand |
| releases, supply chain | signed, attested, provenance on every release | none |
| measured quality | the Score, 73.9, three lanes | a strength |

## 5. The plan, and the trade-off

**Speed first.** OWASP admits at Incubator, which asks only that the website state the
project's intent. So the shortest path to a submission is the owner's two blocking items, in
parallel with three phases: an OWASP-ready repository (R30), OWASP's taxonomies in every
finding (R31), and the application itself (R32). That is about two to three weeks of build
after R29, if a second leader is found.

**Depth while the request is reviewed.** Four phases build what Lab and Production measure and
what adopted projects share: working with DefectDojo and Dependency-Track (R33), a
documentation site and a practice repository for teaching (R34), a contributor on-ramp (R35),
and public evidence: the Score as a citable evaluation, `ADOPTERS.md`, usage figures without
telemetry (R36). R37, moving the repository to OWASP, waits for acceptance; R32 makes the
move cheap beforehand by having a release accept both the old and the new signing identities.

**The backlog** holds what is large or uncertain: DSGAI's controls as an offline Check (needs
its lead's agreement), the Agent Control Standard in the hook, AIBOM, more languages, image
scanning, scoped scans, translation, an IDE extension, native Windows, and a GenAI initiative
of its own (needs contributors first).
