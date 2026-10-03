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
