# Signal and adoption: design

**Status:** proposed 2026-11-21; its decisions accepted by the owner on 2026-11-22
(checkpoint B), as proposed · answers
[requirements.md](requirements.md) · built by [tasks.md](tasks.md)

## Overview

Five phases, in the order a user would feel them.

- **R48, the measurement.** Every rule of every Scanner gets its own true and false counts on
  maintained code, and the three measurements that judge the build stop moving by
  themselves. Nothing a user sees changes.
- **R49, the bar.** One table says, per rule, where its Findings are active and where they
  are inventory. It is filled from R48's counts. Secrets in test material, the two noisy
  static-analysis rules and every other rule under the bar leave the verdict. The rules that
  can be narrowed are narrowed first. The baseline is raised once.
- **R50, an existing codebase.** The gate can fail on what a change adds. A project's own
  VEX statements and its declarations about its paths are read.
- **R51, the tools around it.** Every Finding carries the identifiers its rule maps to.
  DefectDojo and Dependency-Track are measured. Each agent client is run or said not to be.
- **R52, the evidence.** A VEX document per release, the SLSA level stated, a Health record,
  a first use watched.

```
the corpus, 48 projects ──► per-rule counts, every Scanner (R48) ──► tiers.toml (R49)
                                                                        │
a Finding ─► path class ─► tier: active │ inventory ─► verdict, gate, SUMMARY.md, the Score
                                                                        │
                       ┌────────────────────────────────────────────────┘
                       ▼
valvur gate --new-since <ref>     the base ref's tree, scanned beside the working tree (R50)
identifiers.toml ─► findings.json, SARIF taxa, the reply, docs/OWASP-MAPPING.md        (R51)
image-gate.json ─► valvur-X.Y.Z.openvex.json, attested on the image's digest           (R52)
```

### What the measurements already say

Read on 2026-11-21 from `tests/eval/labels/corpus.toml` (169 false, 3 true; 171 of them were
judged in the last run) and the last Score report on this Mac.

| rule | true | false | where the false ones are |
|---|---|---|---|
| `private-key` (Gitleaks) | 0 | 35 | 34 under `tests/`, `test/` or `fixtures/`, 1 under `examples/` |
| `jwt` (Gitleaks) | 0 | 29 | 15 under tests, 13 under `docs/`, 1 in a guide |
| `generic-api-key` (Gitleaks) | 0 | 26 | 14 under tests, 2 examples, 4 `docs/`, 4 `docs_src/`, 2 other documents |
| `python_random_rule-random` (vendored) | 0 | 23 | jitter, ports, temporary names, sample text |
| `valvur.python.weak-hash` | 0 | 21 | cache keys and ETags 11, a protocol's own SHA-1 5, HMAC 2, content keys 3 |
| `valvur.python.insecure-cookie` | 0 | 8 | R49.1 records |
| `valvur.python.open-redirect` | 0 | 7 | R49.1 records |
| `valvur.python.path-traversal` | 0 | 6 | R49.1 records |
| `curl-auth-header` (Gitleaks) | 0 | 6 | one project's `guide/` |
| `javascript_eval_rule-eval-with-expression` (vendored) | 2 | 1 | |
| `valvur.pinning.mutable-git-ref` | 1 | 1 | |
| `valvur.javascript.ssrf` | 0 | 2 | |
| `slack-webhook-url`, `pkcs12-file` (Gitleaks) | 0 | 1 each | |
| `valvur.licence.mismatch`, `valvur.dependency.near-miss` | 0 | 1 each | |

By path class (`src/valvur/pathclass.py`), the 98 false secrets are: test 57, docs 17,
fixture 8, example 3, source 13. All 13 in `source` are documentation in practice: `guide/`,
`docs_src/` and two `README`-like files, which the class does not name today.

**Three things follow, and each is a decision below.**

1. **The inventory must reach every Scanner's rules.** Today only Opengrep's adapter can mark
   a Finding `inventory`, from the rule's own YAML. A vendored rule may not be edited
   (Requirement 4.4) and Gitleaks' rules are not valvur's files. So the tier moves to one
   table that names a rule by its Scanner and its ID (D82c).
2. **Demoting a rule costs its planted credit.** The Score counts active Findings only. On
   the Python track, `weak-hash` is the whole `hash` category (37 of 71 caught, none safe
   flagged) and the vendored `random` rule the whole `weakrand` category (35 of 99). Moving
   both to the inventory takes about 6.2 points from that track (40.9 to about 34.7), which
   is past the ratchet (D82g).
3. **The target of 50 is out of reach on this corpus.** The track's formula is
   `100 × (true + 1) / (true + false + 1)`. With 3 true Findings, 50 needs at most 4 false
   ones left active. Seven false Findings would remain, each from a rule with one to three
   Findings there. A bar that demotes a rule on one label is not a measurement (D82h).

---

## What changes, file by file

| file | change | task |
|---|---|---|
| `scripts/eval/precision.py`, `scripts/eval/rule_precision.py`, `scripts/eval.py` | per-rule and per-Scanner counts for every Scanner; Checkov and zizmor judged in their own table | R48.2 |
| `tests/eval/labels/corpus.toml`, `tests/eval/labels/hygiene.toml` (new) | labels keep a `changed` reason when a verdict moves; Checkov's and zizmor's labels | R48.2, R48.3 |
| `tests/eval/rules-measured.json`, `scripts/rules_doc.py`, `docs/RULES.md` | every Scanner's rules, corpus counts apart from planted counts | R48.4 |
| `scripts/mutation_check.py` | a hunk that changes only annotations is *no code change* | R48.5 |
| `tests/test_no_moving_target.py` (new), `tests/test_licences.py`, `scripts/check_image_licences.py` | the base is read from the Dockerfile, digest included | R48.6 |
| `tests/fixtures/broken-repo/`, `scripts/fixtures.py`, `tests/fixture_copy.py`, `scripts/scanner_upgrade.py` | four agent files stored as `*.fixture`; every reader takes the copy | R48.7 |
| `src/valvur/data/tiers.toml` (new), `src/valvur/tiers.py` (new), `src/valvur/classtable.py` | the tier table and its third action, `inventory` | R49.2, R49.3 |
| `src/valvur/pathclass.py` | the docs class gains the names R49.1 measures | R49.4 |
| `rules/python-security.yaml`, `rules/javascript-security.yaml` | three rules narrowed, two rules added | R49.5, R49.6 |
| `scripts/eval/twins.py` | secrets under test and documentation paths; certificate and cookie cases | R49.4, R49.6 |
| `rules/llm-output-sinks.yaml` or `src/valvur/checks/` | the flag, or the coverage note | R49.7 |
| `tests/eval/baseline.json`, `README.md`, `docs/EVALUATING.md` | the baseline raised once, and re-based where D82g says | R49.8 |
| `docs/adr/0033-…md` to `0037-…md` (new) | the five decisions the owner accepted at checkpoint B, 2026-11-22 | wave 1, item 1.3 |
| `src/valvur/fileset.py`, `engine_host.py`, `history.py`, `api.py`, `cli.py` | `scan --ref`: a commit's tree, read with git's plumbing | R50.2 |
| `src/valvur/gate.py`, `cli.py`, `docs/CI.md`, `docs/examples/github-actions.yml` | `gate --new-since` | R50.3, R50.4 |
| `src/valvur/vex.py` (new), `suppressions.py`, `exclusions.py`, `data/security-scan.schema.json` | `[[vex]]` and `[[context]]` in `.security-scan.toml` | R50.5, R50.6 |
| `src/valvur/ranking.py`, `findings.py`, `artifacts.py` | the declared raise; `Dependency.paths` | R50.6, R50.7 |
| `src/valvur/data/identifiers.toml` (new), `src/valvur/identifiers.py` (new) | one mapping, looked up by rule, prefix, Scanner, then class | R51.2 |
| `src/valvur/artifacts.py`, `reply.py`, `summary.py`, `mcp/tools.py` | `owasp` beside `cwe`; SARIF taxonomies; the grouping | R51.3 |
| `scripts/generate_docs.py`, `docs/OWASP-MAPPING.md` (new) | generated from the mapping | R51.4 |
| `.github/workflows/imports.yml` (new), `docs/DEFECTDOJO.md`, `docs/DEPENDENCY-TRACK.md` (new) | both imports measured on dispatch; the guides | R51.5 to R51.8 |
| `tests/fixtures/schema/` | the CycloneDX schema of the version Syft writes | R51.6 |
| `docs/AGENTS.md`, `src/valvur/mcp/clients.py` | each client's record | R51.9 |
| `scripts/image_vex.py` (new), `.github/workflows/release.yml` | the release's OpenVEX document, attested; the SBOMs attested | R52.2, R52.3 👤 |
| `SECURITY.md`, `MAINTAINERS.md`, `docs/BEST-PRACTICES.md` | the SLSA level with its evidence; who can release | R52.4 |
| `scripts/health.py` (new), `.github/workflows/health.yml` (new) | the Health record, from recorded runs | R52.5 |
| `docs/history/usability-gate.md`, `docs/CLI.md` | Gate 2's record; first-run numbers measured again | R52.6 👤 |

---

## Components

### 1. Precision for every rule and every Scanner (Requirement 1)

`scripts/eval/precision.py` judges a Finding when `owned()` says so: a `valvur.*` rule, a
vendored rule, or a Gitleaks secret. Checkov's, zizmor's, Trivy's and OSV-Scanner's are
counted by Scanner (78, 700, 1,010 and 53 in the last run) and the counts are not written to
the baseline.

- **The track's population stays** (D82a). Adding 778 Findings of two Scanners to the pool
  would move the number without valvur changing, and most of them are statements of fact
  about a file (*this action is not pinned*), which are true by reading and say nothing
  about whether valvur's own claims can be believed.
- **Checkov and zizmor are judged in a second table,** `hygiene`, by rule, with labels in
  `tests/eval/labels/hygiene.toml` in the same shape. A label's verdict is `tp` when the
  property the rule names holds in that file and a maintainer of the project would not call
  the report wrong, and `fp` otherwise. The reason is mandatory, as today.
- **A rule with more than 25 Findings on the corpus is judged on 25,** the ones with the
  lowest Fingerprints, and the report says *sampled* beside it (D82b). 700 hand labels for
  one Scanner would be a week of work that R48.1 may show is five rules.
- **The report** (`score.json`) gains `tracks.real-code-precision.by_rule`, for every judged
  rule of every Scanner: `{scanner, rule, tp, fp, sampled}`, and `by_scanner`:
  `{findings, judged, tp, fp}`. `rules-measured.json` and `docs/RULES.md` take them, so the
  page lists Gitleaks', Checkov's and zizmor's rules that fired, each with its corpus counts
  in one column and its planted counts in another.
- **An unlabelled judged Finding fails `--compare`,** as today, in both tables.
- **Labels cannot be bent.** `--update-baseline` records each label's verdict in
  `baseline.json`. A label whose `verdict` differs from the one recorded there must carry
  `changed = "<date>: <reason>"`, and a test compares the two committed files. (*Changed by
  the test-driven pass, 2026-11-22:* this read the labels at the baseline's commit. The
  baseline names no commit, and most CI jobs check out one commit.)

### 2. The tier table (Requirements 2 and 3)

`src/valvur/data/tiers.toml`, read by `src/valvur/tiers.py` and applied where the class
table is applied today (`pipeline.py`'s `classes` stage):

```toml
[[rule]]
scanner = "opengrep"
id = "python_random_rule-random"
tier = "inventory"
where = "everywhere"
corpus = { tp = 0, fp = 23 }
reason = "On maintained code every use measured was jitter, a port or a temporary name."

[[rule]]
scanner = "gitleaks"
id = "private-key"
tier = "inventory"
where = "test material"          # path classes test, fixture, docs and example
corpus = { tp = 0, fp = 35 }
reason = "A key under a test path is a fixture in every case measured."
```

- **`where`** is `everywhere` or `test material`. The second is the repair Requirement 2.5
  asks for when a full demotion would cost a planted track: a private key in `config/` stays
  active and critical, and the same rule under `tests/` is inventory.
- **`classtable.ROWS` gains the action `inventory`.** The two actions it has stay: Gitleaks'
  other Findings in test material are still lowered to `low`, and are still active.
- **The four sink rules keep `metadata.inventory`** in their YAML (D47a). A test holds that
  no rule is named in both places.
- **A Finding made inventory by the table says why** (Requirement 3.4). Its `title` gains
  the clause the row's `where` gives, for example *"…, under a test path (`tests/keys/`):
  listed for review"*, and `SUMMARY.md`'s line for the inventory names the count by reason.
  The existing field `inventory: true` is the machine's signal. Nothing is added to the
  schema.
- **The bar** (D82d): a rule is *measured on the corpus* with 5 or more judged Findings
  there, and *under the bar* when fewer than half of them are true. A test reads
  `rules-measured.json` and refuses a rule that is under the bar and has no row, and a row
  whose `corpus` counts differ from the measurement.
- **Which of Gitleaks' rules can take `test material`.** Only a rule that matches a *shape*
  (a PEM block, three base64 segments, a high-entropy string beside a keyword). A rule that
  matches a provider's own format (`AKIA…`, `ghp_…`, `sk_live_…`, a Slack webhook's host)
  gets no row however it measures: a live-format secret under a test path is the case
  Requirement 3.2 plants. The shape rules measured today are `private-key`, `jwt`,
  `generic-api-key` and `curl-auth-header`.

**What this does on the corpus,** by arithmetic on the labels, before any rule is narrowed:

| step | false labels left active | true | track score |
|---|---|---|---|
| today | 169 | 3 | 2.3 |
| three shape rules, in test material: 83 | 86 | 3 | 4.4 |
| `weak-hash` and `random`, everywhere: 44 | 42 | 3 | 8.7 |
| the docs class widened (D82f): 12 of the 13 in guides and tutorials | 30 | 3 | 11.8 |
| three Python rules, narrowed or demoted (D82e): 21 | 9 | 3 | 30.8 |
| `valvur.javascript.ssrf`, narrowed: 2 | 7 | 3 | 36.4 |

The file holds 169 false labels, of which the last run judged 168, so each score is a
fraction of a point low. The seven left are one Finding each of
`javascript_eval_rule-eval-with-expression`, `valvur.pinning.mutable-git-ref`,
`slack-webhook-url`, `pkcs12-file`, `valvur.licence.mismatch`, `valvur.dependency.near-miss`,
and a `generic-api-key` in a `README`. None of those rules has 5 Findings on the corpus, so
none is measured there, and they stay active. The fourth shape rule, `curl-auth-header`, has
all 6 of its Findings in one project's `guide/`, which the third step covers.

### 3. Secrets in test material (Requirement 3)

- **The corpus:** 83 of the 98 leave the verdict by the tier table and 12 by D82f. Three
  stay active: `slack-webhook-url`, which is a provider's format; `pkcs12-file`, which fired
  once; and a `generic-api-key` in a `README`.
- **The planted cases:** `scripts/eval/twins.py` gains, for each of the nine provider formats
  the secrets track has (every format but `private-key`), a live-format secret at
  `tests/<format>_test.env` and at `docs/<format>.md`. Both are vulnerable cases. They are
  caught today, at `low`, and must still be caught. The track has 40 cases and will have 58.
- **A private key under a test path is not planted as vulnerable.** valvur cannot tell a
  fixture key from a real one in the same place, and says so: `docs/RULES.md` and the README
  state that a key, a JWT or a generic high-entropy string under a test, fixture, example or
  documentation path is listed for review and does not make the verdict `findings`.
- **Criterion 3.5 does not arise** if the table above holds when R49.4 measures it: both
  constraints are met by the rule's kind and the path together. If a provider-format rule
  turns out under the bar, it goes to the owner as 3.5 says.

### 4. Rules narrowed, and two added (Requirement 4)

- **`valvur.python.insecure-cookie` (0 true, 8 false), `open-redirect` (0 and 7),
  `path-traversal` (0 and 6), `valvur.javascript.ssrf` (0 and 2).** The corpus is mostly
  frameworks, and the likely pattern is a framework's own implementation of the function
  the rule guards (`set_cookie(..., secure=secure)`, `redirect(location)`, `send_file`).
  R49.1 reads the 23 labels and records the pattern for each rule. R49.5 narrows each rule to
  what an application writes: a literal `secure=False` or no `secure` at all on a call, a
  redirect or a path whose value comes from a request object the rule names.
- **A narrowed rule is measured on both sides** before it replaces the old one: its corpus
  counts, and its category on the Python track (`securecookie` 24 of 24, `redirect` 9 of 13,
  `pathtraver` 27 of 65). It replaces the old rule only if it is over the bar on the corpus
  or silent there, and its category does not fall more than the ratchet allows. Otherwise
  the old rule takes a row in the tier table, `everywhere`, and D82g's cost applies to it.
- **`weak-hash` is not narrowed.** A cache key and a password hash are the same expression,
  `hashlib.md5(x).hexdigest()`. It takes a row, `everywhere`.
- **`python_random_rule-random` is vendored** and takes a row, `everywhere`. Its manifest
  entry keeps the numbers it was admitted on, and gains the corpus counts.
- **Two rules are added,** each in valvur's own files:
  - `valvur.python.tls-verification-off` and `valvur.javascript.tls-verification-off`:
    `verify=False` on `requests` and `httpx` calls, `ssl._create_unverified_context`,
    `ssl.CERT_NONE`; `rejectUnauthorized: false` and `NODE_TLS_REJECT_UNAUTHORIZED = "0"`.
    CWE-295.
  - `valvur.javascript.insecure-cookie`: `res.cookie(..., { secure: false })` and a session
    cookie configured so. CWE-614.
- **Their cases.** The JavaScript track is generated (`twins.py`) and gains two categories,
  CWE-295 and CWE-614, two vulnerable and two safe cases each. The Python track is the OWASP
  Benchmark, which valvur does not write, so the Python rule's cases are generated twins
  reported as a category of their own, `tls-verification (generated)`, beside the
  Benchmark's fourteen, as the ninth track reports `generated` and `real` apart. Both tracks
  are re-based for the added cases (D65a), in R49.8's one new baseline.

### 5. Model output crossing a function (Requirement 6)

R13.5 measured Opengrep's `--taint-intrafile` on 1.29.0: it raised neither static-analysis
track, and it was not adopted. The ninth track did not exist then.

- **R49.7 measures it again** on the version the image ships (1.31.0, or 1.33.x if wave 3's
  upgrade has landed), with `scripts/eval/taint.py`, on the five advisories and on the corpus.
- **It is adopted for the four `valvur.llm.*` rules alone** if it catches at least one of
  the five, adds no false Finding on the corpus, and loses no generated case. The flag is
  per run, so R49.7 also measures the scan's time on the acceptance set with it.
- **Otherwise a coverage note.** One new Opengrep rule, `valvur.llm.model-call`, matches the
  sources the four rules already name and reports nothing by itself. When a Scan Run has a
  model call, has a Finding of a sink-inventory rule, and has no `valvur.llm.*` Finding in
  the same function, `SUMMARY.md` says under *What valvur could not read*: *"this project
  calls a model in N files. valvur follows a model's output to a sink inside one function,
  and not through a call to another."* It is a note (`NOTE_RULES`), not a doubt: it does not
  make a `clean` verdict `inconclusive`, because every project that calls a model would then
  never be clean (D82j).

### 6. The gate on new Findings (Requirement 7)

Today `valvur gate` reads a Results Folder and scans nothing. valvur scans the working tree
only. So this needs two things.

**`valvur scan --ref <ref> --out <dir>`: a commit's tree.**

- The host reads the commit with git's plumbing, which writes nothing to the repository:
  `git rev-parse --verify <ref>^{commit}`, `git ls-tree -r -z <commit>`, and
  `git cat-file --batch` for the blobs. Not `git worktree add`, which writes under `.git`,
  and not `git archive`, which drops what `export-ignore` names.
- The File Set of a ref is the commit's tree, less `[scan] exclude` as that commit's
  `.security-scan.toml` gives it. It has no untracked and no ignored files, and the Snapshot
  is built from the blobs instead of from disk. Submodules are named and not entered, as in
  the working tree.
- The history pass reads `git log <commit>` instead of `--all`.
- `--ref` requires `--out`, and refuses an `--out` inside the Workspace's own Results Folder.
  `run.json` records `tree: {ref, commit}`.
- Suppressions are read from that commit's `.security-scan.toml`.

**`valvur gate --new-since <ref>`.**

- It runs that scan itself, into `<cache>/base/<repository's root commit>/<commit>/`, with
  the image, the Profile and the data the working tree's Scan Run recorded in its `run.json`.
  A base result already there is reused when the commit, the image digest, the Profile and
  every dataset's identity are equal (ADR-0030's rule).
- A Finding is *already there* when its Fingerprint is in the base's `findings.json`, in any
  state. The gate fails on active Findings at or above `--fail-on` that are not.
- Everything else about the gate stands. An incomplete Scan Run of either tree fails it. A
  lapsed Suppression in the working tree fails it. `--no-inconclusive` reads the working
  tree's verdict.
- When the ref does not resolve, the base scan cannot complete, or the two Scan Runs differ
  in image, Profile or data, the gate fails with exit 1 and one line that says which. In CI
  the usual cause is a shallow checkout, and the line says `fetch-depth: 0`.
- Output, after the failures: *"gate: 2 new finding(s) at or above high since origin/main
  (4f2c1ab); 37 were already there and were not gated on"*.

**What it does not do,** stated in `docs/CI.md`: a Finding in a file that was renamed, or a
static-analysis Finding whose matched text changed, has a new Fingerprint (`CLAUDE.md` §8) and
counts as new. That errs toward failing, which is the safe side for a gate.

**The action** is in its own repository, `MaverickHQ/valvur-action`. It gains the input
`new-since`, passed through. R50.4 prepares that as a pull request there, for the owner.

### 7. A project's own VEX (Requirement 10)

```toml
[[vex]]
path = "security/valvur.openvex.json"
expires = 2027-05-21
```

- **Declared, with an expiry, in the file where Suppressions live.** OpenVEX has no expiry
  field. The entry is the project's acceptance of that document until a date, which keeps the
  rule that nothing is accepted for ever, and keeps the decision in the file a reviewer
  already reads. valvur does not search the tree for VEX documents.
- **What is honoured:** a statement with status `not_affected` or `fixed`, whose
  vulnerability is the Finding's ID or one of its aliases, and whose product is the
  Finding's package at its version, compared as package URLs. `not_affected` must carry a
  `justification` or an `impact_statement`, as the OpenVEX specification requires. A
  statement naming a product with no version is not honoured, and is reported.
- **How it shows:** the Finding is suppressed, with `suppressed` reading
  *"VEX not_affected: vulnerable_code_not_in_execute_path (author, timestamp), accepted
  until 2027-05-21"*. It is listed under *Suppressed* and is not active.
- **When it lapses:** a `[[vex]]` entry past its date gives `valvur.suppression.expired`,
  which fails the gate at every threshold, as a Suppression's does.
- **A statement that matches nothing** is listed in `SUMMARY.md` under *Suppressed* as
  *"N statements in `<path>` match nothing here"*, with rule `valvur.vex.unused` at `low`. It
  does not fail the gate at every threshold as a stale Suppression does: a VEX document is
  written for a product's consumers and names versions this tree no longer holds (D82m).
- **Only dependency vulnerability Findings.** No other class has a product and a
  vulnerability ID.
- **valvur writes none.** `valvur suppress` does not print a VEX statement. The skill's rule
  *never add a suppression without asking the human* names `[[vex]]` too.

### 8. Declared context and lockfiles (Requirement 11)

```toml
[[context]]
path = "services/api/"
exposure = "internet"      # or: data = "sensitive"
```

- `ranking.sort_key` gains one key after the tier: a Finding whose path is under a declared
  path sorts before one that is not, within the same tier. A KEV-listed advisory in an
  undeclared path still outranks a medium Finding in a declared one.
- A raised Finding's `REMEDIATION.md` item ends *"raised by this project's declaration:
  `services/api/` is internet-facing (`.security-scan.toml`)"*. The word is *declaration*
  wherever it appears.
- A project with no `[[context]]` gets the same order as today, held by the ranking's
  existing tests unchanged.
- **Lockfiles:** `Dependency.paths`, a tuple, additive. `findings.merge` already folds
  same-Fingerprint Findings and keeps the first path; it now keeps every path, sorted.
  `path` stays the first, so nothing that reads it changes. SARIF gets one location per
  path. The Fingerprint has never held the path.

### 9. Standard identifiers (Requirement 8)

This is the parked D69, brought back, with what was learnt since.

- **`src/valvur/data/identifiers.toml`** is looked up in this order: the rule's ID, a rule
  prefix, the Scanner, the Finding Class. valvur's own 21 rules and about 30 Checks, and the
  4 vendored rules, each need an entry by ID, which a test holds against the rule files and
  `verdict.py`. Gitleaks', Checkov's and zizmor's rules cannot be listed from this
  repository, so each Scanner has one entry, and a rule of theirs may have its own.
  Dependency advisories take the CWE the advisory gives, where Trivy reports one, and the
  class's OWASP category.
- **The lists and their editions** are read again by R51.1 from OWASP's own pages, and the
  file names each edition and the date it was read. An entry is `none` with a reason where
  no honest mapping exists.
- **On a Finding:** `owasp`, a tuple of IDs, beside the existing `cwe`. Additive in
  `findings.json` (schema 1's rule for additions) and in the reply (schema 2, with the
  snapshot updated). `fp_version` does not move: neither field is identity.
- **SARIF:** `run.taxonomies` for CWE and for each OWASP list, each rule's `relationships`
  to its taxa, and `properties.tags`, which is what DefectDojo and GitHub read.
- **`SUMMARY.md`** gains one bounded table, *By OWASP category*, counts only, when the Scan
  Run has active Findings. `valvur findings --owasp <id>` and the MCP tool's filter list them.
- **`docs/OWASP-MAPPING.md`** is generated: every rule beside its identifiers, then each
  list's categories that nothing maps to. A test holds every document to *mapped to*.

### 10. DefectDojo and Dependency-Track (Requirement 9)

The parked D71. `imports.yml`, on dispatch only, starts each tool from its published
container images at a version the workflow pins by digest, imports the Results Folder of a
scan of `tests/fixtures/broken-repo`, and reads back through the tool's own API what
arrived: Findings by severity, CWE, tags, the file and line, and whether a second import of
the same file deduplicates. The record goes to `docs/acceptance/r51.md`. The corrections are
whatever the first measurement shows, inside SARIF 2.1.0 and CycloneDX. A test validates
`sbom.cdx.json` against the schema of the `specVersion` it declares (1.7 from Syft 1.57.1),
vendored under `tests/fixtures/schema/`. Each guide shows the user's own pipeline step and
the user's own token. `src/valvur/egress.py` is untouched, and a test holds that.

### 11. The agent clients (Requirement 12)

Each of the nine is installed on this Mac, pointed at valvur as `docs/AGENTS.md` says, and
asked to scan `tests/fixtures/broken-repo`. The record per client is its version, the date,
the first tool call it made and what it reported. Three of them need the owner's account
(tasks.md §3). A client that cannot be run gets *not run: <reason>*, dated. `valvur doctor
--client` only prints what a client reads, so its record is that the printed snippet is what
worked.

### 12. The release's evidence (Requirement 14)

- **`scripts/image_vex.py`** reads the two `image-gate.json` verdicts of a release and
  `.github/image-accepted.yaml`, and writes one OpenVEX document whose product is the image
  by digest. A vulnerability with no fixed version is `under_investigation`. One the owner
  accepted is `affected`, with the acceptance's reason and expiry as its action statement,
  or `not_affected` when the entry gives one of OpenVEX's justifications. valvur claims
  `not_affected` for nothing by itself.
- **In `release.yml`,** the `notes` job, which already reads both verdicts, writes the
  document, and `promote` attaches it as `valvur-<version>.openvex.json`. It is attested
  with `cosign attest --type openvex` on the image's digest, and the four SBOMs with
  `--type cyclonedx` and `--type spdxjson`, in `stage`'s grant. This is an edit to
  `release.yml`, so R52.3 is the owner's, with the diff shown first.
- **SLSA.** R52.4 reads the Build track's requirements at v1.0 and records the evidence for
  each. The likely statement is Build L2: the provenance is generated and signed by the
  hosted platform. L3 needs the build isolated from the workflow that calls it, which D66
  left for 2.0. `SECURITY.md` states the level reached and no higher.
- **The Health record** (D82r): `health.yml`, daily, reads recorded runs through GitHub's
  API: the Score by track from `eval-report`, the published image's verdict from
  `image-gate-published`, the mutation score, and time to heal from `heal_report.py` once
  R46.1 exists. It writes one issue, *valvur health*, through `file-issue`'s shape, and the
  README links to it. It commits nothing, so it needs no identity that can push.
- **`MAINTAINERS.md`** says who can release, and that if that person cannot: the daily
  index and the heal keep running from `main`; a security patch still releases itself after
  the delay (ADR-0032); every other release waits; and how a second maintainer would be
  added, which the file already describes.

### 13. Measurement hygiene (Requirement 15)

- **Mutation:** `mutation_check.code_changed` compares the two syntax trees with every
  annotation removed: argument and return annotations, and the annotation of an annotated
  assignment. A hunk that changes nothing else is *no code change*. The baseline is recorded
  again if the score moves.
- **Moving targets:** a test reads every image reference in `tests/`, `scripts/` and
  `.github/` and refuses a `name:tag` that the Dockerfile pins as `name:tag@sha256:…`,
  unless the line reads the Dockerfile. `tests/test_licences.py` and
  `scripts/check_image_licences.py` take the base from the Dockerfile. `:latest` of valvur's
  own image, which the nightly and the watchdog read on purpose, is on the test's short list
  of exceptions, each with its reason.
- **Hostile fixtures:** `AGENTS.md`, `CLAUDE.md`, `.mcp.json` and `.claude/settings.json`
  under `tests/fixtures/broken-repo/` become `*.fixture`. `scripts/fixtures.py` already
  restores that suffix in a copy. Every reader takes a copy: conftest's `workspace` does
  today, and `scanner_upgrade.RECIPES`, `ci.yml`'s `published` job and the acceptance
  generator are held to it by a test that finds no reader of the stored tree. The goldens do
  not move, because they were captured from the names a copy has.

---

## Decisions: D82

Proposed 2026-11-21, and **accepted by the owner on 2026-11-22 (checkpoint B), every row as
proposed.** Those marked **ADR** are written as ADRs. Requirements 1.2, 5.1 and 10.4 were
amended that day to say what D82b, D82h and D82m decide.

| # | decision | fallback when a measurement disagrees |
|---|---|---|
| D82a | **The eighth track keeps its population:** valvur's rules and Checks, the vendored rules, and Gitleaks. Checkov's and zizmor's Findings are judged in a second table, by rule, and are not pooled into the track. | none needed |
| D82b | **A rule with more than 25 Findings on the corpus is judged on 25,** those with the lowest Fingerprints, marked *sampled*. Requirement 1.2 was amended to say so. | if R48.1 counts under 300 Findings for Checkov and zizmor together, all are labelled |
| D82c | **One tier table for every Scanner's rules** (`tiers.toml`), applied with the class table. `where` is `everywhere` or `test material`. **ADR-0033.** | none |
| D82d | **The bar on maintained code:** measured with 5 or more judged Findings on the corpus; under the bar when fewer than half are true. ADR-0029's bar still decides whether a rule ships at all. **ADR-0033.** | if R48 shows a rule with 3 or 4 judged Findings and none true, it is listed for the owner and stays active |
| D82e | **A rule of valvur's own under the bar is narrowed first,** and takes a row only if the narrower rule fails either measurement. `weak-hash` takes its row at once. | the row, and D82g's cost |
| D82f | **The docs path class gains** `docs_src`, `doc`, `guide` and `guides` as directory names. R49.1 measures each name on the corpus and on every track before it is added. | a name that moves a planted case is left out, and the Findings it would have covered stay active |
| D82g | **A demoted rule takes its planted credit with it.** The Score counts active Findings only, so the Python track is re-based once, with both numbers and the reason, as R29.6 re-based the eighth: about 40.9 to 34.7 for `weak-hash` and `random`. The Score as a whole still rises. This is the conflict Requirement 2.5 puts to the owner, who accepted the re-base. **ADR-0033.** | if R49.1 measures a fall of more than 8 points on the Python track, the phase stops before the re-base and the owner is asked again |
| D82h | **The eighth track's target is 33, with a second measure: at most 8 false active Findings on the corpus, from 168.** Requirement 5.1 said 50, which needs at most 4, and the arithmetic above leaves 7 while the corpus holds 3 true Findings; it was amended to this target. **ADR-0033.** | if the phase ends under 33 or with more than 8, it reports what it reached, with the rule of each false Finding left, and the owner decides at its exit |
| D82i | **Two rules added,** with generated cases on both static-analysis tracks, the Python ones as a category of their own. | a rule under ADR-0029's bar on its cases is not shipped, and the requirement's criterion stays open, recorded |
| D82j | **The limit on model output is a note, not a doubt,** when the flag is not adopted. | none |
| D82k | **The gate's base is a git ref, read with plumbing and scanned by the gate itself** into the cache. No baseline file. **ADR-0034,** amending ADR-0021. | if `git cat-file --batch` is too slow on the acceptance set's largest repository, the tree is read with one `git archive` and `export-ignore` is reported as a limit |
| D82l | **A Finding is *already there* by its Fingerprint alone,** in any state in the base. Renames and edited matches count as new. | none |
| D82m | **VEX is honoured only through a `[[vex]]` entry with an expiry.** An unmatched statement is reported at `low` and does not fail the gate at every threshold. Requirement 10.4 was amended to say so. **ADR-0035.** | none |
| D82n | **Declared context raises within a tier, never across one.** `Dependency.paths` lists every lockfile. **ADR-0036.** | none |
| D82o | **Identifiers: one file, four levels of lookup, *mapped to*.** D69 stands, with the editions read again. **ADR-0037.** | where two of OWASP's publications disagree, the newer wins, recorded |
| D82p | **Imports are measured against the real tools on dispatch,** and held by schema tests between measurements. D71 stands. | if a tool's container cannot start on a hosted runner, it is measured on the dev machine and recorded so |
| D82q | **The release's VEX says only what valvur knows:** `under_investigation` for no fix, the owner's acceptance for the rest. It and the SBOMs are attested with cosign on the image's digest. | if the owner declines the `release.yml` edit, the document is attached and not attested, and `SECURITY.md` says so |
| D82r | **The Health record is an issue a daily workflow rewrites,** not a committed page. | if the owner prefers a page, the same script's output is published with GitHub Pages, an owner setting |
| D82s | **The measurements are fixed before the bar is set:** R48 precedes R49. | none |
| D82t | **The executor runs on the owner's Mac, and containers on the dev machine,** which holds no credential (*How the build runs*; wave 1, item 1.7; proposed 2026-11-22 for checkpoint D). Each phase has a budget in hours and stops when it passes it. | when the machine cannot start, GitHub's lanes; when the Mac is not available, a cloud session under D61 |

---

## Error handling

| what fails | what happens |
|---|---|
| a judged Finding has no label, in either table | the track fails `--compare`, naming it |
| a row in `tiers.toml` names a rule the measurement does not have, or with other counts | a unit test fails; a scan is unaffected |
| `--new-since`'s ref does not resolve | the gate fails: *"cannot read `<ref>`: fetch it, or check out with `fetch-depth: 0`"* |
| the base scan is incomplete, or its image, Profile or data differ from the working tree's | the gate fails and names which |
| the Workspace is not a git repository | `--ref` and `--new-since` refuse, and say so |
| a `[[vex]]` path is missing or not OpenVEX | `valvur.suppression.invalid`, as a malformed Suppression gives |
| a `[[vex]]` entry is past its date | `valvur.suppression.expired`; its statements are no longer honoured |
| a `[[context]]` path matches no file | `valvur doctor` reports it; a scan ignores it |
| `imports.yml` cannot start a tool | the run fails; nothing in the product depends on it |
| `health.yml` cannot read a run | the record keeps the last value with its date, and says *not read today* |

---

## Security of what is added

| threat | what stops it |
|---|---|
| an agent demotes a rule to make Findings go away | `tiers.toml` is package data in the image, not a project file. A project cannot change a tier |
| an agent writes a VEX document to silence an advisory | it is honoured only through `[[vex]]` in `.security-scan.toml`, with an expiry, shown under *Suppressed* with its author; the skill's rule on Suppressions names it; valvur writes none |
| an agent declares every path internet-facing, or none | a declaration only reorders within a tier. It removes nothing and changes no verdict |
| a hostile base ref | the ref's tree is data in a Snapshot, as the working tree is (ADR-0022). Its `.security-scan.toml` is read with the same parser and limits |
| a pull request that lowers the base to hide a Finding | the base is a ref the workflow names, usually the target branch, which the pull request cannot move |
| a Finding hidden by renaming a file | a rename gives a new Fingerprint, so it is gated on as new |
| the new-only gate used as a way never to fix the backlog | the output names the count not gated on, every run |
| a mapping read as a compliance claim | *mapped to* in every output, held by a test |
| the base scan's result reused when it should not be | reuse needs the commit, the image digest, the Profile and every dataset's identity equal |
| a secret in a test path that is real | a provider-format rule stays active there; a shape rule's Finding is still listed, with its path |

---

## Testing strategy

- **Through public interfaces,** as the main `tasks.md` §3 requires: `valvur gate` and
  `valvur scan` through `cli.main`, the eval scripts through their `main()`.
- **Only two boundaries are faked:** the container runtime and the network. git is real, in
  repositories made in `tmp_path`.
- **The tier table is tested against the measurement,** not against a copy of itself: the
  test reads `rules-measured.json`.
- **Planted credentials are assembled at runtime,** as §3 requires, in the new secrets cases.
- **The Score is the judge of R49.** Every task there ends with `scripts/eval.py --tracks`
  for the tracks it touches, and the phase with the whole Score on both lanes.
- **New tests go in new files.** The constraint suite stays at 54.
- **Live proofs:** R50.4 runs `--new-since` in a pull request of valvur's own repository.
  R51.5 and R51.8 are the dispatched imports. R52.6 is a person.

---

## Alternatives considered

- **Path alone decides a secret's tier.** It is simpler, and it would hide a live AWS key
  committed under `tests/`, which is where they are often committed.
- **Delete the two noisy rules.** A user who wants every `md5` call can no longer ask for
  it. The inventory keeps them one flag away.
- **Count inventory Findings as detections on the planted tracks.** The Python track would
  keep its number, and the Score would then credit a Finding valvur does not assert.
- **Pool Checkov and zizmor into the eighth track.** The number would pass 50 on the day
  the labels land, because most of their Findings are true by reading the file. It would
  measure nothing valvur changed.
- **A committed baseline file for the gate.** It is what most tools do. ADR-0011 forbids
  scan output in git, and a file an agent can edit is a way to make a Finding old.
- **`state.json`'s `new` Status as the gate's base.** It is free, and it compares with the
  last Scan Run on that machine, which in CI is nothing: every Finding is new.
- **Reading VEX from any `*.vex.json` in the tree.** No decision is recorded, and nothing
  expires.
- **A Health page committed by a workflow.** It needs an identity that can push to `main`
  for a page of numbers.

---

## How the build runs

Wave 1's item 1.7, for both this spec and the self-healing spec's open phases (D82t). The
main list's §1 to §4 stand. This says where each step runs, what it costs and how it resumes.

**Measured on 2026-11-22,** on `main` at `60bc7fd`:

| step | this Mac (M1, 8 GB) | the dev machine (m7g.xlarge, 16 GB, arm64) | GitHub Actions |
|---|---|---|---|
| the unit suite | 150 s | 137 s | 126 s, with lint and types |
| the image, built cold | not built here since 1.6.1 | not measured: its cache was warm | 417 s arm64, 517 s amd64 |
| the image, cache warm | | 1 s | |
| the acceptance set | | 147 s with its repositories generated, 135 s after | |
| the end-to-end suite | 12 min (2026-09-29) | 391 s | 602 s amd64, 510 s arm64 |
| the Score, nine tracks | 663 s, 574 s of it the eighth track | 671 s, 579 s of it the eighth track | |

- **The Mac's gate failed twice on 2026-11-21** when the unit suite ran beside an image
  build, under swap. Alone it takes 150 s.
- **The dev machine is not faster at the Score,** and is twice as fast at the end-to-end
  suite. What it buys is that neither runs on an 8 GB Mac beside the session.
- **A command sent to the machine may carry about 70 KB:** 60 KB was accepted and 90 KB
  refused. That is enough for one slice's diff.
- **The pace of R9 to R47,** from the author dates of their 611 build commits: 83 hours of
  work, counting no gap over an hour. 8 minutes a commit on average, and 21 in the slowest
  phase.
- **Prices,** Ireland, read 2026-11-21: the machine $0.187 an hour while it runs, with its
  address; its 60 GB of disk $5.28 a month whether it runs or not.

**Where the executor could run.**

| option | verdict |
|---|---|
| this Mac for everything, as R9 to R47 | rejected: the image is now built from four Scanners' source, and the gate fails under that load |
| **the executor on this Mac, containers on the dev machine** | **chosen** |
| the executor on the dev machine | rejected: it puts three secrets on a cloud machine (a token that can push, the signing key, the model's credential), and the gain is that the Mac may sleep |
| a Claude Code cloud session (D61) | the fallback when the Mac is not available: it already signs and pushes, on x86_64 alone, with D61's workarounds |
| CodeBuild, or the build lab's runner | not needed: GitHub Actions is free for this repository and is already the Linux lane; the runner stays deferred (the owner, 2026-11-21) |

**The plan.**

| step | where |
|---|---|
| edits, the unit gate (`check.sh`), signing, pushes | this Mac |
| the image, `-m e2e`, the acceptance set, the Score | the dev machine, through `~/dev-machine/bin/dev run` |
| Linux on amd64, the arm64 image, the mutation job, a release's rehearsal | GitHub Actions, on the phase's pull request |

- **The machine holds no credential,** and nothing is pushed from it. It clones the public
  repository, fetches the build branch by commit, and its answer is the command's output
  and exit status. Its cache and its `valvur:dev` are the build's own.
- **A slice whose failing test needs a container** (a rule run by Opengrep, the image's
  package list) is seen red before its commit: the working tree's diff goes to the machine
  inside the command, and is applied to the branch's head there. A diff over 70 KB is split
  into smaller slices.
- **The machine is stopped after a container step,** unless the next one follows in the
  same task. Left alone it stops itself after 30 idle minutes.
- **A phase's exit** is measured on the dev machine and on GitHub's Linux lane. The Mac lane
  is run once before each release, as D61(a) had it: the acceptance set and the Score on
  this Mac, with nothing else running.
- **When the machine cannot start** (the nightly stop at 03:00 London cut a job, or the $40
  ceiling refused the start): the command is run again once. If it is refused again, the
  step goes to GitHub's lanes (the pull request's checks, and `eval.yml` on dispatch), the
  phase goes on, and §3 gains a row.
- **No agent run and no API key.** The model's usage is the session's own.
- **A budget for each phase,** in hours of the executor's work. The lower figure is the
  measured average pace, and the upper the slowest phase's. **A phase that passes its upper
  figure stops and reports,** as the main list's §1 does on a stop: that is what protects
  the week's usage limit from a loop.

| phase | behaviours | hours of work | hours of the dev machine |
|---|---|---|---|
| R44, the lock and the image heal themselves | 91 | 12 to 32 | 4 |
| R45, security patches release themselves | 42 | 6 to 15 | 1 |
| R46 and what is left of R47 | 20 | 3 to 7 | 1 |
| R48, the measurement | 34 | 5 to 12, and R48.3's labels at about a minute each | 2 |
| R49, the bar | 46 | 6 to 16 | 8 |
| R50, an existing codebase | 54 | 7 to 19 | 2 |
| R51, the tools around it | 31 | 4 to 11 | 2 |
| R52, the evidence | 31 | 4 to 11 | 1 |
| all nine phases | 349 | 47 to 123 | 21 |

The machine's hours are twice what the listed container steps take, for reruns. They come
to about $4 at $0.187 an hour, beside the $5.28 a month its disk costs.

- **Resuming** is the main list's §2, unchanged: the hourly in-session schedule, and the
  desktop task `valvur-build-resume`. Each phase's first task arms them again. The resume
  prompt needs no change, since `build_status.py` reads every spec. A resuming session runs
  `dev status` before its first container step.
- **The owner's part** is the landing sitting at each wave's end, and §3's rows.

---

## What it costs

- **R48's labels:** at most 25 per rule for Checkov and zizmor. R48.1 gives the count.
- **The eighth track:** 574 s of the Score's 663 s on this Mac. R49 runs it once per task
  that changes a rule, on the dev machine (*How the build runs*, above).
- **`--new-since`:** a second scan per pull request, less ADR-0030's reuse and the base
  result's own reuse while the base branch has not moved.
- **`imports.yml`:** on dispatch only. Two tools, about ten minutes of runner time each.
- **`health.yml`:** API reads once a day.
