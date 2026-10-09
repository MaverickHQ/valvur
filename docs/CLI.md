# valvur from the command line

[README](../README.md) · [Documentation](README.md)

valvur runs its Scanners in a container, so a machine needs Docker or Podman; `valvur
doctor` says whether it has one, and what to install if not.

```bash
pip install valvur          # or: uv tool install valvur
valvur scan                 # offline by default; --profile full adds the network's answers
valvur doctor               # if that did not work: what this machine is missing, and the fix
valvur check npm left-pad   # before an install: real, a near-miss, or malicious? Offline
```

<!-- generated: cli-commands -->

Nine commands in all: `scan`, `update`, `findings`, `status`, `doctor`, `gate`, `suppress`, `init` and `check`. `--help` on each says what it takes.

<!-- /generated -->

A first scan fetches what it lacks and says so as it goes. Measured from an empty cache
with the image already local, on this Mac: 59 s in all, of which 21.5 s fetched the
vulnerability database (123 MB to fetch, 1.4 GB on disk), 8.3 s the signed Name Index
(36 MB to fetch, 118 MB on disk), and 2.5 and 6.0 s OSV's databases for PyPI and npm
(35 and 217 MB). FIRST's daily EPSS file adds 2.5 s (3 MB to fetch). The image adds a
pull the first time: `0.5.0`'s was 256 MB on amd64 and 246 MB on arm64. `valvur update`
fetches the image, the database, KEV, EPSS and the index ahead of time; OSV's databases come with the
first scan of a project whose lockfiles need them. A scan refreshes what is stale by
itself, and `valvur update --if-stale` costs one file read when everything is current.

A scan after that, measured on the acceptance set at R15: 4.9 to 9.5 s on the seven
application repositories on this Mac through Docker Desktop, and 56.3 s on the
Terraform module, where Checkov runs; on GitHub's Linux runner, 2.5 to 12.8 s and
60.9 s. A rescan reuses Trivy's and OSV-Scanner's last answer when no dependency file
and none of their data has changed, since those two read nothing else: a warm rescan
of acceptance repository 8 fell from 14.0 s to 5.2 s on this Mac and from 12.4 s to
3.8 s on Linux, with the same findings. `run.json` names each reused answer, and
`--fresh` runs every Scanner. Each run is in [`docs/acceptance/`](acceptance/).

Results land in `.security-scan/`:

```
.security-scan/
├── .gitignore          ← "*": the folder ignores itself from creation
├── SUMMARY.md          ← start here. Bounded, leads with anything that failed
├── REMEDIATION.md      ← ranked proposal, per group, with dependency paths and upgrade targets
├── findings.json       ← complete, normalised, schema-versioned, secrets redacted
├── results.sarif       ← SARIF 2.1.0 for your IDE and code scanning
├── sbom.cdx.json       ← CycloneDX SBOM, when asked for: `scan --sbom`, or `sbom = true`
├── run.json            ← what ran, which versions, how long each took, what was fetched, what left (nothing)
├── state.json          ← the previous run's fingerprints, for new, persisting and fixed
└── raw/                ← each Scanner's own output, secrets redacted, so you can verify us
```

The folder ignores itself, so results are never committed, and your own `.gitignore` is
never touched. **You decide which fixes to apply and when to rescan**: there is no
autonomous loop. `valvur findings` lists the last scan's findings by group, rule, path
or status, and `valvur findings --fingerprint` shows one in full.

What a scan reads is decided once, before any Scanner starts. In a repository, it is
the files git would publish (tracked, and untracked but not ignored), plus ignored
`.env*` files and agent configuration, which are exactly where secrets and instructions
hide; in a plain folder, everything but dependency caches. Git history is read for
secrets, the newest 5,000 commits or 200 MB, and the Summary says when that bound
stopped the read. An excluded path never reaches a Scanner, and the Summary names
everything left out and why.

**Two settings files.** Project policy is `.security-scan.toml`, committed with the
project: what to exclude, whether to read history, and Suppressions, each with a
mandatory expiry date. `valvur init` prints a starter (`--write` writes it when there is
none), `valvur suppress` prints a
Suppression block for a finding, and `valvur doctor` checks the file against its JSON
Schema, [`src/valvur/data/security-scan.schema.json`](../src/valvur/data/security-scan.schema.json):

```toml
[scan]
exclude = ["tests/fixtures"]   # root-relative prefixes; only what is not source
history = true                 # read git history for secrets (the default)
scope = "git"                  # the git view (the default); "tree" walks the folder

[[suppress]]
fingerprint = "3f9c2a7d41b08e65c1d9e0a2b7f4c813"   # from `valvur findings`
rule = "CKV_DOCKER_2"
path = "Dockerfile"
expires = 2027-03-01
reason = "The image runs under an orchestrator that health-checks it."
```

Machine settings are `~/.config/valvur/config.toml` (under `$XDG_CONFIG_HOME` when it
is set): the runtime, the image, the cache, `jobs`, `fetch = "never"` for a machine
that must not fetch, and the mirrors. An environment variable overrides each for a CI
job or a one-off command, `VALVUR_CACHE` or `VALVUR_FETCH` say, and `valvur doctor`
says which value came from where.

`valvur doctor` says what is cached, how old and how large; `valvur update --prune`
removes only what is superseded, listing each first, and `valvur update --clear`
removes the data. The eight commands are `scan`, `update`, `findings`, `status`,
`doctor`, `gate`, `suppress` and `init`; `explain` and `cache`, their old names, still
work through 1.x and say what replaced them.
