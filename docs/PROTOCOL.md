# The shim/image protocol

**Protocol 1.** Carried by the image as the label `org.valvur.protocol`, read by
the shim before a scan (task 26.3.1, F1.9).

valvur is two artifacts — a host shim installed from PyPI and an image pulled from
GHCR (ADR-0001) — and everything below is what the shim assumes of the image. It
was implicit in `runner.py`, the adapters and the `Dockerfile`, and pinned only by
the e2e suite exercising it; now it is written here, and a test in
`tests/test_protocol.py` holds this document to the code in both directions: every
path an adapter's `Invocation` names must be a row here, and every row here must
exist in the image the e2e suite runs.

## The version rule

The label's value is a **major version, and only a major**. The shim compares it
with its own `compat.PROTOCOL`:

| the image says | the shim does |
|---|---|
| the same major | **runs.** The versions may differ; if the trees differ the scan says so in `SUMMARY.md` and `run.json` (`build.match`, 23.4.4), and never refuses. |
| a different major | **refuses**, naming both protocols and both versions, with the fix (`pip install -U valvur && <runtime> pull <image>`, or pin the image to the shim's version). This is the one thing the compatibility check refuses. |
| no label | an image from before protocol 1 — `0.3.0` and earlier. The version-series rule that served them applies: equal major.minor below 1.0, equal major from 1.0. |

A change that breaks anything on this page bumps the major. A change that adds
to it — a new binary, a new mount, a new label — does not, so long as a shim that
speaks the old protocol still gets what this page promises.

## Paths

Inside a container the shim launches. Four are mounts the shim provides
(`runner._base_flags`); the rest are the image's, and the e2e test checks each of
those exists in the built image.

| path | provided by | who relies on it |
|---|---|---|
| `/workspace` | the shim: the source tree, bind-mounted read-only (F1.1); the container's working directory | every Scanner and Check — the argument they scan |
| `/results` | the shim: a scratch directory mounted read-write, fresh per Scanner; a Scanner writes its report here and the shim reads it back | Trivy, Gitleaks, OSV-Scanner, Checkov, Syft, Opengrep (`Invocation.report`) |
| `/cache/trivy` | the shim: the vulnerability database, mounted from the host cache (ADR-0012) | Trivy (`--cache-dir`, and `TRIVY_CACHE_DIR`), and `valvur update`'s fetch into it |
| `/cache/names` | the shim: the package-name index, mounted read-only from the host cache (ADR-0018) | the dependency-reality Check |
| `/tmp` | the shim: a tmpfs (`rw,nosuid,size=512m`), `noexec` unless the Invocation asks for `exec` — Opengrep alone; `HOME` points here | any Scanner that needs scratch space |
| `/opt/valvur-rules` | the image: valvur's own Opengrep rules, licensed with the project (ADR-0004) | Opengrep (`--config`) |
| `/opt/checkov` | the image: Checkov's own virtual environment, hash-locked (23.4.1); `checkov` on PATH links into it | Checkov |
| `/usr/local/lib/python3.12/site-packages/valvur` | the image: the `valvur` package itself, so the Checks run in the container (ADR-0013) | `python -m valvur.checks` |
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
| `syft` | `anchore/syft` | 1.51.1 |
| `opengrep` | `opengrep/opengrep` | 1.29.0 |
| `checkov` | `/opt/checkov`, from `requirements-checkov.txt` | 3.3.19 |
| `python` | the base image's Python 3.12 | with the Checks |

## The Checks' entry point

valvur's own Checks run inside the container (ADR-0013) through one module:

```
python -m valvur.checks <name> /workspace              one Check
python -m valvur.checks batch /workspace <name>...     several, one container (23.4.2)
```

- **One Check** prints a JSON list of findings on stdout — each an object with
  `rule`, `path`, `line`, `title`, `evidence`, `severity` and an `identity` for the
  Fingerprint — and nothing else on stdout. A refusal (an index absent, a registry
  unreachable) is one sentence on stderr and exit 1.
- **The batch** prints one JSON object, `{<name>: {"ok": bool, "findings": [...],
  "error": str, "duration_s": float}}`, in the order run; `dependency-reality`,
  the only Check that may reach out, runs last. A Check that raised is `"ok":
  false` with its error and no findings; the others are unaffected. An image
  from before the batch answers `usage:` on stderr with exit 2, and the shim runs
  the Checks one by one instead (`BatchUnsupported`).
- **`VALVUR_NETWORK=1`** in the environment means the container was launched with
  a network, and only then; the dependency-reality Check asks a registry only when
  it sees it (ADR-0018). **`VALVUR_DB_REPOSITORY`** names a database mirror for
  Trivy's fetch (F10.5). Both are set by the shim from `egress.py`.
- **`VALVUR_EXCLUDE`** (29.0.1) carries the repo-relative prefixes the scan
  skips — the committed `[scan] exclude` list — one per line; the Checks' walk
  never enters them, nor the vendored directories it always prunes. Through the
  environment rather than the arguments so that an image from before it ignores
  the variable, where the batch would have read `--exclude` as a Check's name.
  Absent means nothing configured. An addition, not a major.

## Labels

| label | value | read by |
|---|---|---|
| `org.opencontainers.image.version` | the valvur version the image was built as | `compat.image_version` — F1.9's version rule, and `doctor` |
| `org.valvur.protocol` | the protocol major, `1` | `compat.image_protocol` — the rule above |
| `org.opencontainers.image.source` | `https://github.com/MaverickHQ/valvur` | GHCR, to link the package to the repository |
| `org.opencontainers.image.licenses` | `Apache-2.0` | readers |

## The process

The shim launches every container the same way (`runner._base_flags`,
`egress.container_flags`):

- as user **`10001:10001`** — the image's `USER`, and the shim's `--user` on Linux
  so the scratch mount is writable (F10.2);
- **`--read-only`**, **`--cap-drop=ALL`**, the tmpfs above, and **`--network=none`**
  unless the Profile grants a network — in which case `VALVUR_NETWORK=1` is set and
  the container may join `VALVUR_CONTAINER_NETWORK`;
- under a **ceiling** (28.0.3, `runner.RESOURCE_LIMITS`): `--memory=2g` with swap
  equal to memory, so a container past it is killed rather than swapping the host
  — measured, 3 GB asked inside the box is an exit 137 in 8 s; `--pids-limit=512`;
  `--security-opt=no-new-privileges`. Rootless Podman on a cgroup v1 host refuses
  the memory half and gets the other two, and `doctor` says so;
- with `--name valvur-<id>`, so a cancel — or the MCP server's own exit (27.1.1) —
  can stop exactly the containers it started (F1.11);
- with **no `ENTRYPOINT`** in the image: the adapter's argv is the whole command.

`CHECKOV_DISABLE_UPDATE_CHECK=true` and `PYTHONDONTWRITEBYTECODE=1` are set in the
image so nothing phones home or writes into a read-only root.

## History

- **Protocol 1** — 2026-09-21 (26.3.1). What `0.3.0`'s image already did, written
  down; `0.3.0`'s image carries no label and is served by the version rule.
