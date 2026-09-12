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
| package-name index (PyPI, npm, RubyGems, Packagist, crates.io) | ~34MB | `ghcr.io/maverickhq/valvur-index:latest`, built daily from the five registries and cosign-signed | an OCI artifact, in any registry — **or** six plain files on any web server |
| CISA KEV | ~2MB | `cisa.gov` | one JSON file, on any web server |

```bash
# 1. The vulnerability database and the name index, once, from a connected machine.
#    Both are OCI artifacts; oras, crane and skopeo all copy them. The index is
#    signed, and `valvur update` verifies the signature when cosign is installed —
#    so copy the signature with it (`--recursive` for oras, or `cosign copy`).
oras cp ghcr.io/aquasecurity/trivy-db:2 registry.internal/mirror/trivy-db:2
oras cp --recursive ghcr.io/maverickhq/valvur-index:latest registry.internal/mirror/valvur-index:latest

# 2. KEV, from anywhere connected.
curl -o /srv/valvur-mirror/kev.json \
  https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

# 3. On the air-gapped machine.
export VALVUR_DB_REPOSITORY=registry.internal/mirror/trivy-db
export VALVUR_DB_INSECURE=1              # only if the registry is plain HTTP or self-signed
export VALVUR_INDEX_REPOSITORY=registry.internal/mirror/valvur-index
export VALVUR_INDEX_INSECURE=1           # likewise
export VALVUR_KEV_URL=http://mirror.internal/valvur-mirror/kev.json
valvur update          # fetches from your mirrors, not the internet
valvur scan            # scans offline against the cached copies
```

Without a registry, the index is also six plain files. Copy them from a machine that
has run `valvur update` onto any static web server and name it instead:

```bash
cp ~/.cache/valvur/names/{pypi,npm,rubygems,packagist,crates}.txt \
   ~/.cache/valvur/names/metadata.json /srv/valvur-mirror/
export VALVUR_NAME_INDEX_URL=http://mirror.internal/valvur-mirror
```

Either way the index's `metadata.json` travels with its `built_at`, so the age a scan
reports is the age of the *data*, not of your copy. A copy taken this morning of a
list built in March is a March list, and `run.json` will say so. A signature cannot
travel with plain files; a static mirror is verified by the digests of what it
serves and by being yours.

## The settings

| variable | what it does |
|---|---|
| `VALVUR_DB_REPOSITORY` | The OCI repository Trivy fetches its database from. |
| `VALVUR_DB_INSECURE=1` | Allows plain HTTP, or a certificate the container does not trust. Trivy assumes TLS for any registry that is not `localhost` or a private-range IP literal; without this an internal mirror on HTTP fails with *"server gave HTTP response to HTTPS client"*. Found by the first real test, not by reading the docs. |
| `VALVUR_CONTAINER_NETWORK` | The container network the **update** container joins, when the mirror registry lives on a named one. Never applied to a scan container: `--network=none` is not negotiable. |
| `VALVUR_INDEX_REPOSITORY` | The OCI repository the package-name index is pulled from, `host/name[:tag]`. Default `ghcr.io/maverickhq/valvur-index:latest`. Set explicitly, it is the only source tried: a mirror that fails is reported, not worked around by walking the registries. |
| `VALVUR_INDEX_INSECURE=1` | Plain HTTP, or an untrusted certificate, for that repository. The shim pulls the index itself — no container involved — so this is the shim's own switch, not Trivy's. |
| `VALVUR_NAME_INDEX_URL` | A URL under which the index's files — `pypi.txt`, `npm.txt`, `rubygems.txt`, `packagist.txt`, `crates.txt` and `metadata.json` — are served verbatim. Wins over the repository when both are set. |
| `VALVUR_KEV_URL` | A URL for the CISA KEV catalog JSON. Without it, an air-gapped `valvur update` tries cisa.gov, fails softly, and keeps the snapshot shipped in the image. |

## Prove it

```bash
VALVUR_DB_REPOSITORY=… VALVUR_INDEX_REPOSITORY=… VALVUR_KEV_URL=… \
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
