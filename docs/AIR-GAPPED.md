# Air-gapped operation

`valvur update` fetches three things, and each has a mirror setting. Measured end to
end on 2026-09-12 — an OCI registry on a Docker network with no route out, a static
file server, and every other connection refused — `valvur update` and an `offline`
scan both complete from the mirrors alone, from an empty cache, with nothing
attempted beyond them.

What an air-gapped site runs is the **`offline`** Profile. Since ADR-0018 that
includes the hallucination check; only package age, OSV's second advisory source and
EPSS need the internet, and those are what `full` is.

## The three things, and where each comes from

| what | size | primary source | mirror as |
|---|---|---|---|
| vulnerability database (Trivy) | ~118MB | `ghcr.io/aquasecurity/trivy-db:2` | an OCI artifact, in any registry |
| package-name index (PyPI + npm) | ~30MB | PyPI's simple index; npm's replication feed | three plain files, on any web server |
| CISA KEV | ~2MB | `cisa.gov` | one JSON file, on any web server |

```bash
# 1. The vulnerability database, once, from a connected machine.
#    oras, crane and skopeo all work.
oras cp ghcr.io/aquasecurity/trivy-db:2 registry.internal/mirror/trivy-db:2

# 2. The name index and KEV, from a machine that has run `valvur update`.
cp ~/.cache/valvur/names/{pypi.txt,npm.txt,metadata.json} /srv/valvur-mirror/
curl -o /srv/valvur-mirror/kev.json \
  https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

# 3. On the air-gapped machine.
export VALVUR_DB_REPOSITORY=registry.internal/mirror/trivy-db
export VALVUR_DB_INSECURE=1              # only if the registry is plain HTTP or self-signed
export VALVUR_NAME_INDEX_URL=http://mirror.internal/valvur-mirror
export VALVUR_KEV_URL=http://mirror.internal/valvur-mirror/kev.json
valvur update          # fetches from your mirrors, not the internet
valvur scan            # scans offline against the cached copies
```

The index's `metadata.json` travels with its `built_at`, so the age a scan reports is
the age of the *data*, not of your copy. A copy taken this morning of a list built in
March is a March list, and `run.json` will say so.

## The settings

| variable | what it does |
|---|---|
| `VALVUR_DB_REPOSITORY` | The OCI repository Trivy fetches its database from. |
| `VALVUR_DB_INSECURE=1` | Allows plain HTTP, or a certificate the container does not trust. Trivy assumes TLS for any registry that is not `localhost` or a private-range IP literal; without this an internal mirror on HTTP fails with *"server gave HTTP response to HTTPS client"*. Found by the first real test, not by reading the docs. |
| `VALVUR_CONTAINER_NETWORK` | The container network the **update** container joins, when the mirror registry lives on a named one. Never applied to a scan container: `--network=none` is not negotiable. |
| `VALVUR_NAME_INDEX_URL` | A URL under which `pypi.txt`, `npm.txt` and `metadata.json` are served verbatim. |
| `VALVUR_KEV_URL` | A URL for the CISA KEV catalog JSON. Without it, an air-gapped `valvur update` tries cisa.gov, fails softly, and keeps the snapshot shipped in the image. |

## Prove it

```bash
VALVUR_DB_REPOSITORY=… VALVUR_NAME_INDEX_URL=… VALVUR_KEV_URL=… \
python3 scripts/verify-mirror.py /path/to/a/repo
```

Runs `valvur update` and an `offline` scan with every connection outside your mirrors
refused the way an air gap would refuse it, records every attempt, and fails if
anything tried to go elsewhere. The container half — whether the update container
could have reached the internet — is a property of the network it joins; put the
mirror on a network with no route out (Docker's `--internal`) and the gap is
structural. The recipe that was measured is in [`RELEASING.md`](RELEASING.md).

The database, the index and KEV all deliberately live **outside** the image
([ADR-0012](adr/0012-vulnerability-db-lives-outside-the-image.md),
[ADR-0018](adr/0018-offline-package-name-index.md)), so mirroring needs no special
build — and a six-month-old image never implies six-month-old data.
