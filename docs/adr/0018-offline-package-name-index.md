# ADR-0018 — An exact index of package names, from primary sources, in the host cache

**Status:** accepted · **Date:** 2026-09-12 · **Amends:**
[ADR-0016](0016-two-profiles-split-on-the-network-boundary.md) · **Follows:**
[ADR-0012](0012-vulnerability-db-lives-outside-the-image.md)

## Context

The dependency-reality Check — *does this package exist at all?* — is the finding this
product is most distinctive for, and it ran only on `full`, because it asked a
registry. `full` sends package names out, and target market #1 (§5) cannot do that.
So "fully offline" and "detects hallucinated packages" were both true and never at
the same time. The 2026-09-12 review named this the one product move before `0.2.0`.

Existence and its refinements are different questions. *Does `reqeusts` exist?* can be
answered from a list of names. *When was it first published?* needs the registry.
Split them: existence moves to the default Profile, against a local index; age stays
`full`-only. Two decisions were needed, each measured before it was made.

## Decision 1: an exact sorted list, not a bloom filter

Measured 2026-09-12 against the real registries:

| | names | plain | gzip -9 | xz -6 | bloom 1% | bloom 0.1% |
|---|---|---|---|---|---|---|
| PyPI | 890,006 | 12.8MB | 4.0MB | 3.4MB | 1.1MB | 1.6MB |
| npm | 4,382,736 | 90.5MB | 25.4MB | 21.3MB | 5.3MB | 8.0MB |

The exact form is **29MB on the wire** against the vulnerability database's 116MB,
and 103MB on disk against Trivy's 1.35GB. A bloom filter at 0.1% would save 20MB per
refresh and cost one missed hallucination in a thousand, silently, on the headline
finding — and could not be audited with `grep`. xz saves 5MB over gzip and takes
55 seconds to compress npm; gzip it is.

**Lookup is a binary search over the memory-mapped plain file.** Measured: 8µs per
name, 11–15ms for a scan's worth including opening the file. The alternatives are
worse in the dimension that matters — streaming the gzip costs 0.3s (PyPI) and 1.6s
(npm) *per scan*, and a 4.4M-entry Python set costs a second to build and ~270MB of
memory for a Check that asks about ten names. So the index is stored **uncompressed on
disk**, one canonical name per line, sorted bytewise: PyPI names in PEP 503 form
(`re.sub(r"[-_.]+", "-", name).lower()`), npm names lowercased. Plain text, because a
reviewer can verify the whole thing with `grep -x`.

## Decision 2: primary sources, refreshed by `valvur update`

**PyPI** is one request: the simple index in its JSON form
(`Accept: application/vnd.pypi.simple.v1+json`), 9.7MB compressed on the wire, under
a second. PyPI adds ~530 projects a day (RSS, 39 items over 1h47m).

**npm has no all-names endpoint.** What exists, measured:

- `replicate.npmjs.com/_all_docs` — the registry's own CouchDB view, npm-operated.
  `limit` is capped at 10,000 and `skip` is refused, so it pages by `start_key`:
  **439 requests, 145.6MB on the wire, 330s** for the full set.
- `replicate.npmjs.com/_changes` — the same database's change feed, also capped at
  10,000 per request. ~24,000 results a day (rev bumps included; ~1,600 are new
  packages). **A day's drift is 2–3 requests; a week's is ~17 and ~6MB.** So the
  first pull is expensive and every later one is cheap, provided the `update_seq`
  taken *before* the first pull is stored beside it.
- `all-the-package-names` on npm — a daily 27MB tarball, one request, MIT. Rejected,
  and not only on the "primary sources" rule (§3, moat item 3). Diffed against the
  registry the same morning it was published: **140,823 names it lists do not exist**
  (spam the registry deleted and the list never dropped — the exact direction that
  turns a hallucinated name into a false *exists*), and 81,134 registry names it
  lacks. A third party's cron is not a source; it is a second thing that can be wrong.
- An index valvur publishes itself, the `trivy-db` pattern — the right answer to the
  first-run cost, and deferred: it would stack on a release pipeline that has never
  run (Phase 22 Block B). Revisit once 22.B.4 has measured the true first run.
  *Done, 23.2.1 — see the amendment below.*

So: full pull from `_all_docs` when there is no index, incremental from `_changes`
after that, both from `valvur update`, both into the host cache beside the
vulnerability database (ADR-0012: names change daily and image releases do not, and
the answer is the same). The cache directory is mounted **read-only** into every
container; the Check never writes it.

**Staleness is reported and, past 30 days, makes a clean verdict `inconclusive`** —
the rule the database already follows (§7). Thirty days is ~16,000 PyPI and ~48,000
npm names of drift, and matches the KEV threshold already in `run.json`. The failure
direction is worth being precise about: an old index is *missing* names, so its
errors are packages newer than itself reported as nonexistent — an overstatement
that `full` would have flagged as newly-registered anyway — not hallucinations
reported as real. Names leave the registry at ~7 a day. The threshold is about
keeping the answer's age visible, not about a cliff.

## JVM and Go: no index exists, so `full` only

Measured the same day, for task 22.A.4. **Maven Central** holds 661,801 coordinates;
its only complete name list is the Lucene index at `repo1.maven.org/maven2/.index/`
— **3.24GB** — and its search API pages 200 at a time. **Go** has no registry of
modules at all: `index.golang.org` is a feed of *versions* (2,000 entries did not
cover seventeen minutes of one day) with no distinct-module list, and a module path
is a VCS location the proxy fetches on demand. Neither can be turned into a 30MB
file a user downloads.

So both are checked on `full` only, one request per name: Maven Central's
`maven-metadata.xml` for the coordinate (200/404, 70–350ms) and the proxy's
`@v/list` for the module (200/404, and 410 for a module it will not serve). On
`offline` they are a **Profile omission, stated** — in the Coverage contract and the
Summary's caveat — and neither a failure nor a gap Finding, by F7.16's rule: valvur
*can* do the job on `full`, which is different from being unable to do it at all.
Neither registry states first publication, so there is no age for either. The
eventual answer for both is the same as npm's first-run cost: an index valvur builds
and publishes itself, once the release pipeline exists.

## Amendment (2026-09-12, tasks 23.2.1–23.2.3): published, and five ecosystems

**The index is now built once a day by a workflow in this repository and published
as a signed OCI artifact**, `ghcr.io/maverickhq/valvur-index:latest` plus a dated
tag — the `trivy-db` pattern the section above deferred. `valvur update` pulls it
first: the artifact's config blob *is* the index's `metadata.json`, so two small
requests establish what is there and how old it is, and when every file on disk
already carries the published `built_at` nothing else moves. Otherwise each layer —
one gzip file per ecosystem — streams through the shim's own registry client
(`valvur/oci.py`, zero dependencies: resolve, manifest, blob, the anonymous bearer
challenge GHCR issues and the CDN redirect it answers blobs with, both measured) and
is checked as it lands: sha256 against the manifest, then the invariants the reader
bisects on — sorted, no blank line — then renamed into place. **34MB on the wire,
1.7 seconds from a local registry**, against thirty seconds to eight minutes for the
walk. The walk stays: it is what the workflow itself runs, the fallback when the
registry is unreachable, and `valvur update --build-index` on demand. As the
fallback it is 400MB, so a registry walked within the last twenty hours is not
walked again unless forced — a CI job restoring yesterday's cache, or a user running
`update` twice while GHCR is down, pays it once a day at most.

**Signature.** The artifact is signed keylessly, under the same workflow identity as
the image. The shim verifies it with `cosign` when cosign is installed and says so
on one line when it is not (`signature: not verified: cosign is not installed`,
recorded in the metadata and so in `run.json`); a cosign that runs and *refuses* is
`SignatureInvalid`, which stops the update outright — never a fallback, never
"unverified". Three alternatives were rejected: reimplementing keyless verification
(a Fulcio chain, a Rekor inclusion proof and an OIDC SAN) in a shim with no
dependencies is the wrong trade for a security tool; a pinned-key signature
verified by a home-made ECDSA would put crypto we wrote in the product and a key on
the owner's desk; bundling cosign in the image adds ~90MB to make the verification
depend on the runtime, and 23.4.6 is trying to make the image smaller. The
vulnerability database this sits beside is pulled by Trivy with no signature at all
(`trivy-db:2` has no `.sig` tag — checked), so this posture is the stronger of the
two. `valvur doctor` (23.3.1) will name a missing cosign.

**Mirrors.** `VALVUR_INDEX_REPOSITORY` names a copy in any registry, the way
`VALVUR_DB_REPOSITORY` does for the database; `VALVUR_INDEX_INSECURE=1` is
`--insecure` for it. Set explicitly, it is the only source tried — an operator who
named a mirror wants to hear that the mirror failed, not watch the internet being
tried from inside their air gap. `cosign copy` or `oras cp --recursive` carries the
signature across; a copy made without it is refused by a cosign-equipped shim,
which is the point. The static-file mirror (`VALVUR_NAME_INDEX_URL`) remains and
wins over both.

**Three more ecosystems, from the same measurement discipline.** RubyGems publishes
`rubygems.org/names` (196,829 names, 2.8MB, one request; case-sensitive — `rails`
answers 200 and `Rails` 404 — so names are stored as spelled). Packagist publishes
`packages/list.json` (461,638 names, 3.6MB gzip-encoded; case-insensitive, stored
lowercase). crates.io publishes nothing but a 1.86GB database dump — and the phase
note that called that "impossible per user" was written before measuring it:
`data/crates.csv` is the archive's third member, so a streaming read reaches it
after 2MB and can stop when it ends. **381MB read, 17.5 seconds, 91MB of memory**,
332,494 names; the CSV carries every crate's README, so the reader keeps the `name`
column and nothing else. crates.io folds case and `-`/`_` (`Serde` and `serde-json`
answer `serde` and `serde_json`), and no two names in the dump collide under that
fold, so that is the stored form. All three are in `FILES`, all three are walked by
`--build-index`, and all three are answered offline. The full walk of five
registries measured **31.6 seconds** with npm incremental. What remains `full`-only
is JVM and Go, for the reasons above.

## Consequences

- The dependency-reality Check runs on **both** Profiles. On `offline` it answers
  existence from the index and the near-miss comparison from the bundled popular
  list — the latter never needed a registry, and withholding it was an oversight —
  under `--network=none`, with `what_left_the_machine` still `nothing`. On `full` it
  adds first-publish age, which is the one question that still needs a socket.
- ADR-0016's "the two that genuinely need a socket" becomes one: `osv-scanner`. The
  Profile gap prose changes from "hallucinated and typosquatted packages" to
  "package age (newly-registered names)".
- No index on `offline` is a **failed Scanner with a hint**, never clean — F3.5's
  rule, and the same first-run experience Trivy already gives without its database:
  `valvur update` fetches both.
- `valvur update` gains ~30MB and, the first time only, ~5.5 minutes for npm. Both
  numbers belong in `EVALUATING.md` (22.B.4). Air-gapped mirroring of the index is
  22.B.3's job, alongside the database's. *Since 23.2.1 the first run pulls 34MB
  and the walk is the fallback.*
- On the `full` Profile the registry is now asked only about names the index says
  exist, for their age — a nonexistent name is settled locally and never sent.
