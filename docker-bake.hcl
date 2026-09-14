# How the valvur image is built — the one place (task 23.4.3).
#
# `CONTRIBUTING.md`, `ci.yml`, `corpus.yml` and `release.yml` each carried their own
# copy of the build command, and 19.A.3 already showed what copies do: drift, found
# on tag day. Now every one of them runs `docker buildx bake`, and the version, the
# tags, the platforms and the outputs live here.
#
#   VALVUR_VERSION=0.2.0 docker buildx bake            # valvur:dev, loaded locally
#   BAKE_IMAGE=ghcr.io/… docker buildx bake release     # this runner's architecture,
#                                                       # pushed to BAKE_IMAGE by digest
#
# The version is an argument the Dockerfile turns into the OCI version label that
# the shim checks against its own (F1.9), so it must be the tree's — which is why
# every caller passes it rather than this file guessing.

variable "VALVUR_VERSION" {
  default = "0.0.0-dev"
}

# Where the release pushes. The workflow sets it to the real package or the
# rehearsal's throwaway one; `dev` never pushes. Named BAKE_* because bake reads
# variables from the environment, and the first rehearsal (2026-09-14) found the
# release workflow's own `IMAGE` variable turning the test image into
# `ghcr.io/…/valvur-rehearsal:dev` — a name nothing then found.
variable "BAKE_IMAGE" {
  default = "valvur"
}

variable "BAKE_TAG" {
  default = "dev"
}

group "default" {
  targets = ["dev"]
}

# The local and CI image: this machine's architecture, loaded into the runtime.
target "dev" {
  context    = "."
  dockerfile = "Dockerfile"
  args = {
    VALVUR_VERSION = VALVUR_VERSION
  }
  tags   = ["${BAKE_IMAGE}:${BAKE_TAG}"]
  output = ["type=docker"]
}

# The release, one architecture at a time: each runner builds its own natively —
# no QEMU, which cost the amd64 runner 4m50s for both on v0.2.0 — and pushes the
# manifest by digest, untagged. `docker buildx imagetools create` in the release
# job then writes one index over both digests and tags it; that index is what is
# signed and attested, because signing a child manifest would leave the other
# architecture unsigned.
target "release" {
  inherits = ["dev"]
  tags     = []
  output   = ["type=image,name=${BAKE_IMAGE},push=true,push-by-digest=true,name-canonical=true"]
}
