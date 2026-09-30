# valvur in CI

`valvur scan` exits zero whenever the scan itself worked: findings are its answer,
not a failure. `valvur gate` turns the result into one exit code:

```bash
valvur scan . && valvur gate . --fail-on high --no-inconclusive
```

The gate fails the job on:

- an incomplete run: a Scanner failed, timed out, or was cut by the budget;
- a suppression whose expiry date has passed;
- an active finding at or above `--fail-on`: `critical`, `high` (the default),
  `medium`, `low`, or `any` for every active finding;
- with `--no-inconclusive`, a scan whose data was too old to be evidence, or that
  never inspected part of the tree.

Under GitHub Actions each reason is an annotation. The action
`MaverickHQ/valvur-action`, pinned by commit, runs the whole step: it installs the
shim, fetches and caches what a scan reads, scans, uploads `results.sarif` to code
scanning, and runs the gate.

When a gate fails, read `.security-scan/SUMMARY.md` from the job's workspace and
report the verdict and each failing reason before proposing anything. Never loosen
`--fail-on`, drop `--no-inconclusive`, or add a suppression to make a job pass: those
are the human's decisions about risk.

`.security-scan/` is written into the checkout and ignores itself. Never commit it or
upload it anywhere but the job's own artifacts.
