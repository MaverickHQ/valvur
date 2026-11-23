# valvur in CI

[README](../README.md) · [Documentation](README.md)

In CI, `valvur scan` exits zero whenever the scan itself worked (findings are the job,
not a failure), and `valvur gate` turns the result into one exit code:

```bash
valvur scan . && valvur gate . --fail-on high --no-inconclusive
```

The gate fails on an incomplete run, on a lapsed Suppression, on an active finding at
or above `--fail-on` (`any` is every one; valvur's own release gate uses it), and with
`--no-inconclusive` on a scan whose data was too old to be evidence or that never
inspected part of the tree. Under GitHub Actions each reason is an annotation. In
GitHub Actions it is one step: [`MaverickHQ/valvur-action`](https://github.com/MaverickHQ/valvur-action)
installs the shim, fetches and caches what a scan needs, scans, uploads
`results.sarif` to code scanning and runs the gate; this repository's own release gate
uses it on every commit:

```yaml
- uses: MaverickHQ/valvur-action@16b19e275f843419887873ed536a71f872607e24 # v0.2
  with: { fail-on: high, no-inconclusive: "true" }
```

Pinned by commit, because a tag can move and a scan of your own tree would say so:
zizmor, which valvur runs, flags `@v0` as an unpinned action.

**Or the image as a step of its own**, where a job has no shim to install: `docker run`
of the image fetches what a scan reads (`valvur update /src`, OSV's databases for the
checkout's lockfiles included), then scans the checkout mounted read-only with
`--network=none`, writing `.security-scan/` to a directory you mount (`scan --out`).
[`docs/examples/github-actions.yml`](examples/github-actions.yml) is those steps;
this repository's CI runs them against the image built from each commit.
[`docs/examples/gitlab-ci.yml`](examples/gitlab-ci.yml) is the same as a GitLab
job, a documented shape not run here. The image has no `git`, so there the checkout is
walked and its history is not read, and the report says both; `run.json` names the
job's container and whether it had a network.

## A gate on what a pull request adds

A codebase with findings already cannot adopt a gate that fails on all of them on its
first day. `valvur gate --new-since origin/main` fails only on findings the base does not
have: valvur scans the base's tree itself, read with git's plumbing and never checked
out, keeps that result in its cache, and compares by fingerprint. There is no baseline
file to commit. An incomplete scan and a lapsed suppression still fail, and two scans
that did not use the same image, Profile and data are not compared: the gate says which
differs. The second job of [`docs/examples/github-actions.yml`](examples/github-actions.yml)
is this, for a pull request.

Two limits, each on the side of failing:

- A finding in a file that was renamed, or a static-analysis finding whose matched text
  changed, has a new fingerprint and counts as new.
- It needs git and the base's commits: `fetch-depth: 0` on the checkout, and valvur on
  the runner, not the image as a step of its own, which carries no git. Without them the
  gate fails and says which is missing.
