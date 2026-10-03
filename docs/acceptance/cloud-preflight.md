# The cloud pre-flight, measured (D61)

Run on 2026-10-03 in a Claude Code cloud session, on `build/r23-the-host-side-in-layers`
at `6381320`, before any R23 work. Each step is the one `tasks.md` D61 asked to check.

**Verdict.** The VM is not ready for the build. **Docker runs, but `valvur:dev` cannot be
built:** the session's egress policy refuses `dl-cdn.alpinelinux.org`, which the image's
Checkov layer needs for `apk add`. With no image, neither `update` nor `scan` reaches a
data fetch. GitHub works through REST. The gate fails one test, because of the session's
commit-signing program, not because of the code. D61's fallback applies: the build
continues on the Mac until the host is allowed.

## 1. The machine

| | |
|---|---|
| `whoami` | `root` |
| `$HOME` | `/root` |
| OS | Ubuntu 24.04.4 LTS, x86_64 |
| `nproc` | 4 |
| `free -g` | 15 GB total, 15 GB free, no swap |
| `df -h /` | 252 G size, 8.4 G used, **30 G available** (22 %) |
| `VALVUR_CACHE`, `VALVUR_IMAGE` | `/root/.cache/valvur-build`, `valvur:dev`, set by the environment (D61c) |

## 2. Docker

`docker info` failed at first: the client (29.6.2) was installed, but no daemon was
listening on `/var/run/docker.sock`. Started `dockerd` in the background as root, so
`sudo` was not needed, and it answered on the third one-second retry. Server 29.6.2,
storage driver `overlayfs`, cgroup v1 with the `cgroupfs` driver (Docker warns that v1 is
deprecated). The session does not start the daemon by itself, so each new session has to
start it.

## 3. The image build: failed

`docker build -t valvur:dev .` **failed after 17 s**, at the Checkov layer
(`Dockerfile:113`).

| fetch | from | result |
|---|---|---|
| base and tool images (python alpine, gitleaks, trivy, osv-scanner, syft) | docker.io, ghcr.io | ok |
| Opengrep binary, `ADD https://github.com/...` | github.com, fetched by the daemon | ok |
| `apk add gcc musl-dev libffi-dev` | **dl-cdn.alpinelinux.org** | **refused** |
| `pip install` of Checkov and zizmor (not reached) | pypi.org, files.pythonhosted.org | reachable from the host |

**Why.** Image pulls and `ADD` run in the daemon, on the host, and pass through the
session's proxy. `RUN` steps run inside the build container. The first failure there was
TLS: `certificate verify failed`, because the proxy re-terminates TLS with its own CA,
which the container does not trust. A second build used a scratch Dockerfile that only
mounted the CA as a BuildKit secret on the two fetching `RUN`s, so nothing reached the
image. That cleared the TLS error and left the real one: `apk` still said `Permission
denied`, and `curl https://dl-cdn.alpinelinux.org/` from the host gets `CONNECT tunnel
failed, response 403`. That 403 is the environment's network policy refusing the host, so
it was not routed around.

**What unblocks it** is the owner's step: add `dl-cdn.alpinelinux.org` under **Allowed
domains** in the cloud environment's Network access settings, keeping the default package
managers ([cloud environments, network
access](https://code.claude.com/docs/en/cloud-environments#network-access)). Even then, a
build here needs the proxy's CA available to the `RUN` steps, as the secret mount did
above. That needs a change to how the image is built (a build-only secret, nothing in
the image) before the VM can build `valvur:dev`.

## 4. `valvur update` and `valvur scan tests/fixtures/broken-repo`

| command | exit | time | outcome |
|---|---|---|---|
| `uv run valvur update` | 1 | 1 s | `Image pull failed: ... pull access denied for valvur` |
| `uv run valvur scan tests/fixtures/broken-repo` | 1 | 1 s | the same refusal, as a **Python traceback** (`valvur.runner.ImagePullFailed` raised from `api._ensure_image`) |

**No verdict was produced.** No data fetch was attempted: both commands stop at the image,
because `valvur:dev` is local-only and cannot be pulled. **Failed fetches:** only the image
pull of `valvur:dev`, as expected for a local tag.

Two side measurements, made with `curl` from the host. These are not valvur's fetches:

- The data hosts the shim names answer: `www.cisa.gov` (KEV) 200, `epss.cyentia.com` 301,
  `osv-vulnerabilities.storage.googleapis.com` 200, `github.com` 200, `mirror.gcr.io` and
  `ghcr.io` 401 (the registry's auth challenge, as expected).
- `docker pull ghcr.io/maverickhq/valvur:1.3.1` succeeds. Scanning with the published
  image as a stand-in was not run in this session.

**Finding for R23.** `update` reports `ImagePullFailed` as a message, but `scan` lets it
escape as a traceback (`cli.py:668` to `api.py:327`). The CLI's scan path should print the
same message and exit non-zero. This was recorded and not fixed: R23 has not started.

## 5. GitHub

| command | result |
|---|---|
| `gh pr list --limit 1` | **fails**: `HTTP 403: GitHub GraphQL is not available from Claude Code sessions; use the REST API` |
| `gh workflow list` | works, 12 workflows listed |
| `gh api repos/MaverickHQ/valvur --jq .full_name` | works: `MaverickHQ/valvur` |
| REST fallback `gh api 'repos/MaverickHQ/valvur/pulls?per_page=1&state=all'` | works (#183, closed) |

This is D61f as written: any `gh` subcommand that uses GraphQL (`pr list`, `pr view`, `pr
create`, and others) has to be done with `gh api` REST calls.

## 6. The gate: `bash -o pipefail scripts/verify.sh`

**Exit 1, 121 s.** sync, lint, types, traceability and build pass. In tests, **1790
passed, 1 failed, 4 skipped, 91 deselected** (110 s).

The failure is
`tests/test_release_trust.py::test_the_allowed_signers_file_verifies_the_tree_it_is_committed_to`.
The test runs `git verify-commit`. In this session, git's `gpg.ssh.program` is the
session's own signing shim (`/tmp/code-sign`), and that shim says `unsupported code-sign
operation: currently only SSH-style signing (-Y sign) is supported`, so it cannot verify.
This is caused by the environment, not by the tree. Overriding the program for the test
was not tried in this session. Until that is settled, every cloud run of the gate fails
this one test. D61b's rule (commit only when `verify.sh` passes) then never allows a
commit, so the owner has to decide how the gate treats this test in a cloud session.

`scripts/verify.sh image` also fails, as expected, because no `valvur:dev` exists.

## 7. Signing

This file's commit is reported to the owner with GitHub's `commit.verification` for it.
D61g decides what an unverified result means.

## Second pre-flight

Run on 2026-10-03 in a new session on the same VM type, at `3651ed3` (D61 as amended),
before any R23 work.

**Verdict.** The image now builds in the session and checks as built from this tree.
**Downloads made inside running containers do not work:** the containers do not trust the
session's CA, so Trivy cannot fetch its vulnerability database (`x509: certificate signed
by unknown authority`, from `mirror.gcr.io`), and every scan is incomplete. **D61(i)'s
failure branch applies:** R20 and R25 move to the Mac. R23, R24, R21 and R22 stay, with
GitHub's CI as their container lane, and each exit says so. Downloads made on the host
work, except EPSS, whose host the session's network policy refuses.

### Docker

The daemon was down again at the start (a session does not keep it running), and started
in 2 s. **`scripts/cloud_image.py` needs the classic image store.** On the daemon's
default, Docker's containerd image store (`io.containerd.snapshotter.v1`), every build step
passed, including `apk add` and both `pip install`s through the CA secret, and then the
export failed after 107 s: `exporter option "rewrite-timestamp" conflicts with "unpack"`.
Bake's `dev` target asks for `type=docker,rewrite-timestamp=true`, and with the containerd
store the docker exporter unpacks, so the two conflict. With the daemon restarted as `dockerd
--feature containerd-snapshotter=false` (storage driver `overlay2`), the same script built
`valvur:dev` in **66 s** (691 MB; the first attempt's build cache may have been warm), and
`scripts/check_image.py` passed: `valvur:dev was built from this tree (b1ff1c8ddfb2)`. So a
session starts the daemon with that flag. `dl-cdn.alpinelinux.org`, which the first
pre-flight found refused, is now allowed (200).

### `valvur update`

**Exit 1 after less than a second.** The image was present. **The vulnerability database
failed**: `failed to download artifact from mirror.gcr.io/aquasec/trivy-db:2 ... tls: failed
to verify certificate: x509: certificate signed by unknown authority`. Trivy fetches it
inside the image's container, which does not trust the session's CA. `update` stops at the
first failure, so KEV, EPSS, the index and OSV were not attempted by it. The scan below
attempted them.

### `valvur scan tests/fixtures/broken-repo`

**Exit 0 after 35 s. Status `findings`, reason `97 active finding(s)`, and the scan is
INCOMPLETE because Trivy did not finish.** 8 critical, 49 high, 27 medium, 12 low and 1
unknown; 1 in KEV; npm dependencies not checked. Gitleaks, OSV-Scanner, Opengrep, Checkov,
zizmor and valvur's own Checks ran. The scan fetches absent data, and here is how each
fetch went:

| dataset | fetched by | result |
|---|---|---|
| vulnerability database (127 MB) | Trivy, in a container | **failed**: x509, unknown authority |
| package-name index (36 MB) | the host | fetched, 6 s |
| malicious list | the host | fetched, 3 s |
| KEV | the host | refreshed: 1733 entries, catalog 2026.10.02 |
| EPSS | the host | **failed**: `Tunnel connection failed: 403 Forbidden`. `epss.cyentia.com` redirects to `epss.empiricalsecurity.com`, which the session's network policy refuses (the proxy logs `connect_rejected`). Findings rank without EPSS. |
| OSV, PyPI and npm | the host | fetched, 1 s and 2 s |

### The e2e suite, `-m "e2e and not timing"`

**12 failed, 46 passed, 6 skipped, 1832 deselected, in 715 s.** Downloads inside containers
cause ten of the failures. One is probably a result of them. One comes from the session's
GitHub token:

| test | cause |
|---|---|
| `test_constraints_budgets.py::test_the_offline_profile_meets_its_time_budget` | Trivy, no database |
| `test_constraints_budgets.py::test_the_full_profile_meets_its_time_budget` | Trivy, no database; `dependency-reality` also failed because no registry was reachable from its container |
| `test_constraints_budgets.py::test_a_full_scan_stays_within_its_memory_budget` | as above |
| `test_constraints_canary.py::test_the_canary_fixture_still_exercises_every_scanner` | as above |
| `test_exclude_means_one_thing.py::test_every_scanner_reads_a_nested_directory_that_shares_an_excluded_name` | Trivy, no database |
| `test_file_set_e2e.py::test_a_data_directory_is_skipped_not_walked` | Trivy, no database |
| `test_pipeline_example.py::test_the_github_example_runs_against_the_image` | the example's `valvur update` in the image: x509 |
| `test_runtimes.py::test_the_offline_profile_finds_dev_dependency_vulnerabilities[docker]` | Trivy, no database |
| `test_two_scan_containers.py::test_a_full_scan_runs_both_containers_and_leaves_neither` | Trivy, no database |
| `test_licences.py::test_our_real_image_adds_no_gpl_component` | Syft, in a container, cannot pull `python:3.12-alpine3.22` from `index.docker.io`: x509 |
| `test_constraints_interruption.py::test_after_a_cancel_no_container_is_left` | `runtime.kill()` returned 0, not 1: probably the scan's own database fetch was the container it saw and had already exited; to rerun once the database is present |
| `test_repository_guards.py::test_the_repositorys_own_guards_are_on` | `gh api repos/MaverickHQ/valvur --jq .security_and_analysis` returns nothing to the session's token, so the test's JSON parse fails. The test skips when `gh` fails, but not when `gh` succeeds and returns nothing |

### The Score, `--tracks dependencies,secrets --compare tests/eval/baseline.json`

**Exit 0, 43 s, no track under its baseline.** The two tracks were measured without
Trivy's database (`database_age_days: null`, EPSS absent), so neither run is complete:

| track | score | baseline | complete | seconds |
|---|---|---|---|---|
| dependencies | 100.0 | 100.0 | **no** | 36.0 |
| secrets | 100.0 | 100.0 | **no** | 6.2 |

OSV-Scanner alone found every dependency case, so the track's score does not show Trivy's
absence. Only its completeness does.

### What D61(i) decides, and what would reopen it

Downloads inside containers failed, so the failure branch holds: R20 and R25, whose exits
rerun the Score, move to the Mac. R23, R24, R21 and R22 build here, and their e2e and
acceptance lanes are GitHub's CI. Two things would change that, both the owner's to decide:
handing the session's CA to the containers that fetch (the database update, and a `full`
scan), the way `cloud_image.py` hands it to the build, which touches the network boundary
in `CLAUDE.md` §3; or seeding `VALVUR_CACHE` with a database fetched elsewhere.
`epss.empiricalsecurity.com` would also need adding to the environment's allowed domains.
