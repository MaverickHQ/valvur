# How valvur works, and what it checks

[README](../README.md) · [Documentation](README.md)

The README's three claims, in full: why nothing leaves your machine and how to check it,
what valvur reads in AI-generated code, and how it ranks what it finds.

[`docs/EVALUATING.md`](EVALUATING.md) is the audit: the
verification commands, the three Statuses, and a plain list of what valvur does **not**
claim. Read that one sceptically. How much of what valvur claims it actually finds is
measured as **the Score**: eight tracks scored by the OWASP Benchmark's formula, from
static analysis to agent configuration, with a ratchet in `tests/eval/` that no change
may fall under. It is **73.4** out of 100 on both lanes, from 59.3 when first measured;
`EVALUATING.md` gives each track, and one command reproduces it.

## 1. It cannot exfiltrate your code, and you can verify it

No account, no API key, no telemetry: nothing to opt out of. On the default `offline`
Profile the Scan Container has no network interface. The host process that launches it
fetches only public data, each by a fixed public name: the image, the vulnerability
database, the Name Index and its list of known-malicious names, CISA KEV, FIRST's EPSS
scores, and OSV's offline database for each ecosystem your lockfiles use, so which of
those it asks for says which ecosystems are present, and nothing more. It fetches what
is absent and refreshes what is stale (the index, the malicious list, KEV and EPSS past
two days, the database and OSV's past seven), says so as it does, and records
each fetch in `run.json`, beside `what_left_the_machine`: on `offline`, `nothing`. Both halves are checked by one command:

```bash
python3 scripts/verify-offline.py /path/to/your/repo
```

On Linux the kernel can deny the whole process tree the network, no privileges needed:
`unshare -rn valvur scan`, once `valvur update` has filled the cache. For a machine that
must never fetch, `fetch = "never"` turns every fetch off, and
[`docs/AIR-GAPPED.md`](AIR-GAPPED.md) mirrors each source.

## 2. Security checks built for AI-generated code

- **Hallucinated dependencies (slopsquatting).** Language models invent package names;
  attackers register them. No advisory database can catch it, because the package is
  *new*, not known-bad. valvur checks that every declared dependency exists,
  **offline**, against a local index of every name on PyPI, npm, RubyGems, Packagist
  and crates.io: 6,334,163 names, exact, published daily and signed. A PyPI name one
  edit from a popular package is flagged offline too. On `full` it asks each registry how
  old the package is and, for npm, whose download counts are public, whether a package
  under 90 days old has under 1,000 downloads a month: *new and unadopted*, the
  slopsquat signal itself, reported at high. PyPI publishes no counts, so there it is
  age alone.
- **Known-malicious packages.** OSV's data carries the `MAL-` entries from
  ossf/malicious-packages, and valvur reads it offline: acceptance repository 8's
  planted `MAL-2023-1` is reported with no network.
- **Agent configuration.** `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `.mcp.json`,
  skills and prompt files, and the clients' own folders (`.kiro/` steering, settings
  and hooks, `.claude/`, `.cursor/`, `.roo/`, `.continue/`, `.clinerules`,
  `.aider.conf.yml`) are read for injected directives, hidden Unicode (zero-width,
  bidi, tag characters), unpinned `@main` MCP servers, blanket `autoApprove` and
  permission-bypass flags, and **hooks that run a shell command on an event**: a
  committed Kiro hook, Claude Code hook or aider `lint-cmd` makes every agent that
  opens the repository run it, reported at high with the command as evidence. A local
  settings file such as `.claude/settings.local.json` that git would publish, holding
  a home directory or a credential, is reported too. Forty-one patterns among these
  are translated from Cisco's mcp-scanner, and each Finding they produce names its
  pattern.
- **Static analysis, measured, and modest.** Opengrep runs valvur's own rules and four
  of GitLab's.
  - valvur's own are pinning rules, a **sink inventory** at INFO (`eval`, `exec`,
    `shell=True`, unsafe `yaml.load`, string-built SQL), and **taint rules** from a
    model call to those sinks and to `innerHTML`. They have sources for the Anthropic,
    OpenAI, Gemini, LangChain, litellm and ollama SDKs. The taint rules fire on every
    planted flow in the fixture and have not fired on real code in the 48-project
    corpus.
  - Since R25, **taint rules from request data**: for Python, command and code
    injection, path traversal and open redirects, with insecure cookies and XXE by
    pattern; for JavaScript, SQL and command injection, path traversal and SSRF. On
    the 48-project corpus they fire 23 times, and each was judged a false alarm.
  - Every rule's true and false positives, on the Benchmark, the twins and the corpus,
    are in [`docs/RULES.md`](RULES.md), and none is under the bar it shipped by.
  - GitLab's four were each shipped because they met a measured bar (D29), out of 106
    whose licences allowed it: Python's weak `random`, string-built SQL and unsafe
    `yaml.load`, and JavaScript's `eval` of an expression.
  - On the Score's track 1, the OWASP Benchmark for Python, this is **40.9** out of
    100: the true-positive rate minus the false-positive rate, averaged over its 14
    categories, of which 10 find something. On track 2, valvur's JavaScript twins, it
    is **55.0**. That is the claim; the checks above carry this section.

What is covered, and what is not, is stated on every scan rather than left to infer:

| ecosystem | exists? | known CVEs? |
|---|---|---|
| Python, npm, Ruby, PHP, Rust | offline, from the index | from a lockfile: `requirements*.txt` pinned, `uv.lock`, `poetry.lock`, `package-lock.json` and the rest |
| JVM, Go | `full` only: neither registry publishes a name list | `pom.xml`, `go.mod` on their own |

A manifest with no lockfile beside it, or one nothing here reads (a lone `setup.py`,
say), is a **coverage note**: the run reads `inconclusive` rather than `clean`, and
names why. A licence valvur *could not read* is a note too, listed and counted, but it
casts no doubt: a security verdict of `clean` stays `clean` over it.

## 3. Ten things that matter, not four hundred findings

Findings are ranked by **whether attackers are actually exploiting them**: CISA KEV
(with its ransomware-campaign flag) and FIRST EPSS, not CVSS alone. KEV rarely lists
an application dependency, so on application code EPSS does most of that work. Development-only
dependencies are demoted; a transitive vulnerability comes with its path and the
direct package to bump. Findings of one rule in one directory are one **group**, so
`SUMMARY.md` shows one line where a generated file would have filled a page, and a
flood of machine-written findings in data files ranks last, with the exclude line
that drops it in `REMEDIATION.md`. An illustration of the ranking:

| Finding | CVSS | EPSS | KEV | Severity-sorted | Ranked here |
|---|---|---|---|---|---|
| CVE in a dev-only test library | 9.8 CRITICAL | 0.04% | No | **#1** | #40 |
| CVE in your production web framework | 6.5 MEDIUM | 92% | **Yes** | #40 | **#1** |

`SUMMARY.md` leads with anything that failed or was cut, then the Status and its
reason, then the top groups. Facts about the repository that no Finding carries (no
`SECURITY.md`, no Dependabot or Renovate, a workflow left to the default token) are
listed and never ranked.
