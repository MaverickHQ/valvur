# Air-gapped operation

A scan reads four things from the host cache, and each has a mirror setting: the
vulnerability database, the package-name index, CISA KEV, and OSV's offline database
for each ecosystem a project's lockfiles use. The image comes from any registry the
`image` setting names. Measured end to end on 2026-09-12 for the database, the index
and KEV (an OCI registry on a Docker network with no route out, a static file server,
and every other connection refused): `valvur update` and an `offline` scan both
completed from the mirrors alone, from an empty cache, with nothing attempted beyond
them. OSV's mirror joined when its database did (R4.6); R8.3 measures the whole set
again, in a registry of your own.

What an air-gapped site runs is the **`offline`** Profile. Since ADR-0018 that
includes the hallucination check, and since R4.6 OSV's known-malicious packages; only
OSV.dev's API, package age and adoption, and EPSS need the internet, and those are
what `full` is. For a machine that must never reach out, `fetch = "never"` in the
settings stops every fetch a scan would make on its own (ADR-0025): a scan then reads
what the cache holds, and says so when that is stale.

## The four things, and where each comes from

| what | to fetch | primary source | mirror as |
|---|---|---|---|
| vulnerability database (Trivy) | 123 MB | `mirror.gcr.io/aquasec/trivy-db:2` | an OCI artifact, in any registry |
| package-name index (PyPI, npm, RubyGems, Packagist, crates.io) | 36 MB | `ghcr.io/maverickhq/valvur-index:latest`, built daily from the five registries and cosign-signed | an OCI artifact, in any registry, **or** six plain files on any web server |
| CISA KEV | one JSON file | `cisa.gov` | one JSON file, on any web server |
| OSV's offline database, per ecosystem | 35 MB for PyPI, 217 MB for npm | `osv-vulnerabilities.storage.googleapis.com/<ecosystem>/all.zip` | the same paths, on any web server |

The sizes were measured on 2026-09-28 (`docs/acceptance/r7.md`).

```bash
# 1. The vulnerability database and the name index, once, from a connected machine.
#    Both are OCI artifacts; oras, crane and skopeo all copy them. The index is
#    signed, and `valvur update` verifies the signature when cosign is installed,
#    so copy the signature with it (`--recursive` for oras, or `cosign copy`).
oras cp mirror.gcr.io/aquasec/trivy-db:2 registry.internal/mirror/trivy-db:2
oras cp --recursive ghcr.io/maverickhq/valvur-index:latest registry.internal/mirror/valvur-index:latest

# 2. KEV and OSV's databases, from anywhere connected: one file each, per ecosystem
#    your projects use (PyPI, npm, crates.io, Go, Maven, RubyGems, Packagist).
curl -o /srv/valvur-mirror/kev.json \
  https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
for eco in PyPI npm; do
  mkdir -p /srv/valvur-mirror/osv/$eco
  curl -o /srv/valvur-mirror/osv/$eco/all.zip \
    https://osv-vulnerabilities.storage.googleapis.com/$eco/all.zip
done

# 3. On the air-gapped machine, in ~/.config/valvur/config.toml.
#    db_repository    = "registry.internal/mirror/trivy-db"
#    index_repository = "registry.internal/mirror/valvur-index"
#    kev_url          = "http://mirror.internal/valvur-mirror/kev.json"
#    osv_url          = "http://mirror.internal/valvur-mirror/osv"
#    db_insecure = "1" and index_insecure = "1" only if the registry is plain HTTP
#    or self-signed.
valvur doctor --network   # one TCP connect per mirror named above, and nothing else
valvur update             # fetches from your mirrors, not the internet
valvur scan               # scans offline against the cached copies
```

`valvur update` fetches the database, the index and KEV. OSV's databases are fetched
by the first scan of a project whose lockfiles need them, from `osv_url`, since only a
project says which ecosystems it uses. With `fetch = "never"` set, put each where a
scan reads it instead: `~/.cache/valvur/osv/osv-scalibr/<ecosystem>/all.zip`.

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

Each is a key in the machine's settings file, `~/.config/valvur/config.toml` (under
`$XDG_CONFIG_HOME` when it is set; D11), and an environment variable overrides it for a
CI job or a one-off command, the variable winning when both are set. `valvur doctor`
says which value came from where.

| key | variable | what it does |
|---|---|---|
| `db_repository` | `VALVUR_DB_REPOSITORY` | The OCI repository Trivy fetches its database from. |
| `db_insecure` | `VALVUR_DB_INSECURE=1` | Allows plain HTTP, or a certificate the container does not trust. Trivy assumes TLS for any registry that is not `localhost` or a private-range IP literal; without this an internal mirror on HTTP fails with *"server gave HTTP response to HTTPS client"*. Found by the first real test, not by reading the docs. |
| `index_repository` | `VALVUR_INDEX_REPOSITORY` | The OCI repository the package-name index is pulled from, `host/name[:tag]`. Default `ghcr.io/maverickhq/valvur-index:latest`. Set explicitly, it is the only source tried: a mirror that fails is reported, not worked around by walking the registries. |
| `index_insecure` | `VALVUR_INDEX_INSECURE=1` | Plain HTTP, or an untrusted certificate, for that repository. The shim pulls the index itself, no container involved, so this is the shim's own switch, not Trivy's. |
| `name_index_url` | `VALVUR_NAME_INDEX_URL` | A URL under which the index's files, `pypi.txt`, `npm.txt`, `rubygems.txt`, `packagist.txt`, `crates.txt` and `metadata.json`, are served verbatim. Wins over the repository when both are set. |
| `kev_url` | `VALVUR_KEV_URL` | A URL for the CISA KEV catalog JSON. Without it, an air-gapped `valvur update` tries cisa.gov, fails softly, and keeps the snapshot shipped in the image. |
| `osv_url` | `VALVUR_OSV_URL` | A URL under which OSV's databases are served as `<ecosystem>/all.zip`, OSV's own layout. The shim fetches them itself. |
| `image` | `VALVUR_IMAGE` | The image, from any registry: a mirror of `ghcr.io/maverickhq/valvur`. |
| `fetch` | `VALVUR_FETCH` | `never` stops every fetch a scan would make on its own (ADR-0025); `valvur update` and the `update` tool still fetch from the mirrors when asked. |
| `container_network` | `VALVUR_CONTAINER_NETWORK`, retired to the file | The container network the **update** container joins, when the mirror registry lives on a named one. Never applied to a scan container: `--network=none` is not negotiable. The variable still works through 1.x, and says so once. |

## In your own AWS account: ECR

The same mirror, in Amazon ECR, for an account whose pipelines reach nothing outside it.
**A documented shape, not measured here:** the measured run in an AWS account is the
owner's to record (`tasks.md` §8). What is measured is the same mirror in a local
`registry:2` on a Docker network with no route out, on every commit
(`tests/test_customer_mirror.py`, below).

```bash
REGISTRY=<account>.dkr.ecr.<region>.amazonaws.com
aws ecr create-repository --repository-name valvur
aws ecr create-repository --repository-name trivy-db
aws ecr get-login-password | docker login --username AWS --password-stdin "$REGISTRY"
aws ecr get-login-password | oras login --username AWS --password-stdin "$REGISTRY"

# The image, and the vulnerability database.
docker pull ghcr.io/maverickhq/valvur:1.0.0
docker tag ghcr.io/maverickhq/valvur:1.0.0 "$REGISTRY/valvur:1.0.0"
docker push "$REGISTRY/valvur:1.0.0"
oras cp mirror.gcr.io/aquasec/trivy-db:2 "$REGISTRY/trivy-db:2"
```

valvur fetches the index, KEV and OSV's databases itself, anonymously, and carries no
AWS credentials. So serve those as files from inside the account, an S3 bucket behind a
VPC endpoint or any web server, laid out as the file mirror above, and name them with
`name_index_url`, `kev_url` and `osv_url`. The database is fetched by Trivy, which reads
registry credentials from a Docker configuration: in the image, whose `HOME` is `/tmp`,
mount one holding the ECR login at `/tmp/.docker/config.json`. Then, in the job:

```bash
valvur update /src     # db_repository = "$REGISTRY/trivy-db:2" and the file mirrors set
valvur scan /src --out /out
```

## Prove it

```bash
python3 scripts/verify-mirror.py /path/to/a/repo
```

Runs `valvur update` and an `offline` scan with every connection outside your mirrors
refused the way an air gap would refuse it, records every attempt, and fails if
anything tried to go elsewhere. It reads the mirrors as a scan does, from the
variables or the settings file, OSV's included. The container half — whether the update container
could have reached the internet — is a property of the network it joins; put the
mirror on a network with no route out (Docker's `--internal`) and the gap is
structural. The recipe that was measured is in [`RELEASING.md`](RELEASING.md).

`tests/test_customer_mirror.py` measures the whole set on every commit: the image, the
database and the index copied into a `registry:2`, KEV and OSV's database on a file
server, both on a Docker network created `--internal`, and the image run there with the
mirror settings. `valvur update /src` and `valvur scan` complete, and `run.json` says
nothing left the machine and nothing was fetched during the scan.

The database, the index, KEV and OSV's databases all deliberately live **outside** the image
([ADR-0012](adr/0012-vulnerability-db-lives-outside-the-image.md),
[ADR-0018](adr/0018-offline-package-name-index.md)), so mirroring needs no special
build — and a six-month-old image never implies six-month-old data.
