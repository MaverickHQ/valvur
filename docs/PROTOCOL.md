# The shim/image protocol

**Protocol 2.** Carried by the image as the label `org.valvur.protocol`, read by
the shim before a scan (task 26.3.1, F1.9). Protocol 2 is the Scan Container
(ADR-0022, R3.9): one container per network boundary runs every Scanner, fed a
Snapshot of the File Set on its standard input, and the source is never mounted.

valvur is two artifacts — a host shim installed from PyPI and an image pulled from
GHCR (ADR-0001) — and everything below is what the shim assumes of the image. A
test in `tests/test_protocol.py` holds this document to the code in both
directions: every path an adapter's `Invocation` names must be a row here, and
every row the image provides must exist in the image the e2e suite runs.

## The version rule

The label's value is a **major version, and only a major**. The shim compares it
with its own `compat.PROTOCOL`:

| the image says | the shim does |
|---|---|
| the same major | **runs.** The versions may differ; if the trees differ the scan says so in `SUMMARY.md` and `run.json` (`build.match`, 23.4.4), and never refuses. |
| a different major | **refuses**, naming both protocols and both versions, with the fix (`pip install -U valvur && <runtime> pull <image>`, or pin the image to the shim's version). This is the one thing the compatibility check refuses. A `0.6.0` image speaks protocol 1 and is refused by a `0.7.0` shim. |
| no label | an image from before protocol 1 — `0.3.0` and earlier. The version-series rule that served them applies: equal major.minor below 1.0, equal major from 1.0. |

A change that breaks anything on this page bumps the major. A change that adds
to it — a new binary, a new mount, a new label — does not, so long as a shim that
speaks the old protocol still gets what this page promises.

## The engine

The Scan Container runs `python -m valvur.engine` and nothing else:

1. It reads a **tar of the File Set on stdin** and unpacks it into `/workspace`,
   then says `{"event": "received", "files": N}` on stderr. The shim compares N with
   the File Set's count and refuses a scan of a partial Snapshot.
2. It reads **`/results/plan.json`**: `{"tools": [...], "budget_s": float | null,
   "jobs": int | null}`. Each tool is `{"tool", "version", "argv", "report",
   "timeout", "env", "files", "empty_when"}`; its argv names `/workspace` and
   `/results`, its report lands under `/results`, and its `files` are written into
   its working directory before it starts (Opengrep's `.semgrepignore`).
3. It starts the tools, at most `jobs` at once (all when null), each in its own
   process group, and says `{"event": "start", "tool": ...}` and `{"event": "end",
   "tool", "exit_code", "seconds", "timed_out"}` on stderr as each starts and ends.
   A tool past its `timeout` is killed with its group, exit 124. A tool that cannot
   start is exit 127.
4. At `budget_s` it stops what runs, marking each `"cut": true`, and marks what
   never started `"cut": true, "not_started": true`.
5. It writes **`/results/manifest.json`**: `{"received": N, "tools": [{"tool",
   "exit_code", "seconds", "timed_out", "cut", "stderr_tail"}]}`, and exits 0.
6. On **SIGTERM** it stops every tool it started and exits without a manifest; the
   shim's cancel and its grace kill send SIGTERM, then SIGKILL after five seconds,
   and `docker kill` for the container itself.

In a repository with Gitleaks planned, the shim also writes what each commit added
to `/results/history.txt` and plans a second Gitleaks pass over it (R3.7).

## Paths

Inside a Scan Container. Six are the shim's (`engine_host.ContainerRuntime.command`);
the rest are the image's, and the e2e test checks each of those exists.

| path | provided by | who relies on it |
|---|---|---|
| `/workspace` | the shim: the unpacked Snapshot, in a tmpfs up to 512 MB or a volume named for the scan beyond, removed after it; never a mount of the source | every Scanner and Check — the argument they scan |
| `/results` | the shim: a scratch directory mounted read-write, one per Scan Container, holding the plan, the reports and the manifest | the engine; every Scanner's report (`Invocation.report`) |
| `/cache/trivy` | the shim: the vulnerability database, mounted from the host cache (ADR-0012) | Trivy (`--cache-dir`, and `TRIVY_CACHE_DIR`), and `valvur update`'s fetch into it |
| `/cache/names` | the shim: the package-name index, mounted read-only from the host cache (ADR-0018) | the dependency-reality Check |
| `/cache/osv` | the shim: OSV's offline database, one zip per ecosystem, mounted read-only from the host cache (R4.6) | OSV-Scanner on `offline` (`OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY`) |
| `/tmp` | the shim: a tmpfs (`rw,exec,nosuid,size=512m`); `HOME` points here | Opengrep unpacks and runs opengrep-core here; any tool that needs scratch space |
| `/opt/valvur-rules` | the image: valvur's own Opengrep rules, licensed with the project (ADR-0004) | Opengrep (`--config`) |
| `/opt/checkov` | the image: Checkov's own virtual environment, hash-locked (23.4.1); `checkov` on PATH links into it | Checkov |
| `/usr/local/lib/python3.12/site-packages/valvur` | the image: the `valvur` package itself, so the engine and the Checks run in the container (ADR-0013) | `python -m valvur.engine`, `python -m valvur.checks` |
| `/etc/valvur/inputs.sha256` | the image: the digest of the tree it was built from (22.C.1, 23.4.4); `chmod 0444` | the shim's build-provenance comparison, `doctor`, the e2e guard |
| `/etc/valvur/Dockerfile` | the image: the Dockerfile it was built from — one of the digest's inputs | the digest |

## Binaries

On `PATH`, each invoked by name as the first element of its adapter's argv. The
versions are the image's to pin (`Dockerfile`, by digest) and the adapters' to
declare (`version` on each adapter); a golden fixture per Scanner holds the two
together.

| binary | from | pinned at |
|---|---|---|
| `gitleaks` | `zricethezav/gitleaks` | 8.30.1 |
| `trivy` | `aquasec/trivy` | 0.74.0 |
| `osv-scanner` | `ghcr.io/google/osv-scanner` | 2.6.0 |
| `syft` | `anchore/syft` | 1.52.0 |
| `opengrep` | `opengrep/opengrep` | 1.29.0 |
| `checkov` | `/opt/checkov`, from `requirements-checkov.txt` | 3.3.19 |
| `zizmor` | `/opt/zizmor`, from `requirements-zizmor.txt`, the musl wheel by hash (R4.2) | 1.30.1 |
| `python` | the base image's Python 3.12 | with the Checks |
| `valvur` | `/usr/local/bin/valvur`, which runs `python3 -m valvur.cli`: the image as a pipeline step (R8.1) | the image's own version |

## The Checks' entry point

valvur's own Checks run inside the Scan Container (ADR-0013), each as its own tool:

```
python -m valvur.checks <name> /workspace
```

It prints a JSON list of findings on stdout — each an object with `rule`, `path`,
`line`, `title`, `evidence`, `severity` and an `identity` for the Fingerprint — and
nothing else there. A refusal (an index absent, a registry unreachable) is one
sentence on stderr and exit 1; a wrong call is `usage:` on stderr and exit 2.
**`VALVUR_NETWORK=1`** in the environment means the container was launched with a
network, and only then; the dependency-reality Check asks a registry only when it
sees it (ADR-0018). **`VALVUR_DB_REPOSITORY`** names a database mirror for Trivy's
fetch (F10.5). Both are set by the shim from `egress.py`. Protocol 1's batch of
Checks and its `VALVUR_EXCLUDE` are gone: every tool shares one container, and the
Snapshot is already the File Set.

## The image as a pipeline step

Since R8.1 the image also scans on its own, for a pipeline job with no container
runtime to reach: `docker run --network=none -e VALVUR_CACHE=/cache -v <cache>:/cache/valvur
-v <checkout>:/src:ro -v <out>:/out <image> valvur scan /src --out /out`. The image sets
**`VALVUR_IN_IMAGE=1`**, and a `valvur` run with it starts no container: the engine
above runs as a process in the job's container, `/workspace`, `/results` and `/cache`
pointed at directories there, and Trivy's database is fetched by the image's own
Trivy. The image has no `git` (ADR-0005), so a checkout is walked and its history is
not read, each said. `run.json`'s `network.boundary` records the job's container and
whether it had a network: on `offline` the Scanners run with their offline flags
either way, and a job started with `--network=none` makes that structural. Nothing
here is specific to a cloud (F1.10).

## Labels

| label | value | read by |
|---|---|---|
| `org.opencontainers.image.version` | the valvur version the image was built as | `compat.image_version` — F1.9's version rule, and `doctor` |
| `org.valvur.protocol` | the protocol major, `2` | `compat.image_protocol` — the rule above |
| `org.opencontainers.image.source` | `https://github.com/MaverickHQ/valvur` | GHCR, to link the package to the repository |
| `org.opencontainers.image.licenses` | `Apache-2.0` | readers |

## The process

The shim starts every Scan Container the same way (`engine_host.ContainerRuntime`,
`egress.container_flags`):

- **one per network boundary**: `offline` starts one, with `--network=none`;
  `full` adds a second for what needs the network (OSV-Scanner, the dependency
  check's registry questions), with `VALVUR_NETWORK=1`, joining the network the
  `container_network` machine setting names, if it names one; Trivy never runs in it;
- **`-i`**, the Snapshot on stdin, and **`--rm`**;
- as user **`10001:10001`** — the image's `USER`, and the shim's `--user` on Linux
  so the scratch mount is writable (F10.2);
- **`--read-only`**, **`--cap-drop=ALL`** and the tmpfs above; on an enforcing
  SELinux host every mount the shim provides carries `:z` (F1.6);
- under a **ceiling** (D4): `--memory` and `--memory-swap` at 3 GiB, or three
  quarters of the runtime's memory when that is less; `--pids-limit=512`;
  `--security-opt=no-new-privileges`. Rootless Podman on a cgroup v1 host refuses
  the memory half and gets the other two, and `doctor` says so;
- with `--name valvur-<id>` and the labels **`valvur.pid`**, **`valvur.host`** and
  **`valvur.generation`** (R3.6): a cancel stops its container by name, a server's
  exit kills its own by label, and a scan start removes those whose owner has ended;
- with **no `ENTRYPOINT`** in the image: `python -m valvur.engine` is the command.

`CHECKOV_DISABLE_UPDATE_CHECK=true` and `PYTHONDONTWRITEBYTECODE=1` are set in the
image so nothing phones home or writes into a read-only root.

## History

- **Protocol 2** — 2026-09-28 (R3.9, ADR-0022). The Scan Container: the engine, the
  Snapshot on stdin, the plan and the manifest, one container per network boundary,
  the owner labels. Protocol 1's per-Scanner containers, source mount, Checks batch
  and `VALVUR_EXCLUDE` are gone.
- **Protocol 1** — 2026-09-21 (26.3.1). What `0.3.0`'s image already did, written
  down; `0.3.0`'s image carries no label and is served by the version rule.
