# ADR-0027 — Every dataset's age is its data's, and the fast-moving ones are fresh

**Status:** accepted 2026-09-29 by the owner, with the review of that day, and approved
under `CLAUDE.md` §10 as recorded fetches of public data; written by task R9.2 from
`tasks.md` D23 to D26. Requirements F6.12, F6.13, F10.9 and F3.14. Amends ADR-0025's
thresholds, ADR-0007's EPSS on demand, and ADR-0018's thirty days.

## Context

The review of 2026-09-29 measured four gaps in how data reaches a scan.

1. **KEV's age was its file's time.** A package installed on 2026-09-26 called the
   2026-08-27 catalog three days old, so its staleness could never fire. F6.11 forbade
   exactly this for the vulnerability database.
2. **The Name Index could be thirty days old**, and a name missing from it is reported
   as hallucinated at high. A package published after the index was built told an
   agent to delete a real dependency. The index is published daily.
3. **Malicious-package data could be seven days old**, and the attack runs at install.
4. **`offline`, the default, ranked without EPSS**, and KEV matched 1 of 269
   application CVEs. On `full`, EPSS came from an API that received the project's CVE
   identifiers (F6.10).

## Decision

1. **Every dataset's age is its data's** (F6.12). KEV from `dateReleased`; EPSS from its
   file's `score_date`; each OSV database from the `Last-Modified` its fetch recorded;
   the index and the database as now. A source with no date reads *fetched*, never
   *built*.
2. **Refresh thresholds** (F10.9). A scan refreshes, announces and records:
   - the vulnerability database and OSV's databases past 7 days, as ADR-0025 set;
   - the Name Index and the malicious list past **2** days;
   - KEV and EPSS past **2** days, which no scan refreshed before.

   The thresholds that make a verdict `inconclusive` are unchanged. `fetch = "never"`
   fetches none. A failed refresh keeps the old data and says so.
3. **EPSS from FIRST's daily file** (F6.13): `epss_scores-current.csv.gz`, fetched into
   the host cache by `valvur update` and by a stale scan, mirrorable as `epss_url`, read
   on every Profile. `full` no longer sends CVE identifiers anywhere.
4. **Known-malicious names, published daily** (F3.14). `index.yml` also publishes a
   sorted list per ecosystem of `MAL-` package names and affected versions from
   ossf/malicious-packages (Apache-2.0). It is published as the tags `malicious` and
   `malicious-<date>` of the existing public `valvur-index` package, signed and pulled
   back like the index. `1.1.0`'s client pulls `latest` and is untouched.
   `dependency-reality` reports a declared or locked package in the list as critical,
   and a version-scoped entry matches only the locked version it names. OSV-Scanner's
   finding for the same package merges into it.

## Fallbacks

- If EPSS's file is over 20 MB compressed, or unreachable from GitHub's runners, F6.3's
  API stays on `full` and `offline` ranks as before.
- If the malicious list exceeds 10 MB compressed, it carries names only.

## Rejected

- **Raising the thresholds instead.** It hides the risk the thresholds state (ADR-0025).
- **Refreshing in the background.** A watcher, which F9.4 forbids.
- **Asking a registry about a name missing from the index.** The registry, and anyone
  watching it, learns which hallucinated name to register.
