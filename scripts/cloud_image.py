"""Build `valvur:dev` in a Claude Code cloud session (tasks.md D61c).

    uv run python scripts/cloud_image.py

A cloud session's network re-terminates TLS with its own certificate authority. Image
pulls and `ADD` run in the daemon, on the host, which trusts it. `RUN` steps run in the
build's containers, which do not, so the Checkov layer's `apk add` and `pip install`
fail there (the cloud pre-flight, 2026-10-03).

This builds bake's `dev` target, as `docker buildx bake` does, from a Dockerfile derived
in a temporary directory: every `RUN` mounts the host's CA bundle as a BuildKit secret
and names it in `SSL_CERT_FILE` and `PIP_CERT`. A secret mount is never written to a
layer, and the image copies and hashes the build context's own Dockerfile, so the image
is the one the committed Dockerfile describes. Integrity never rested on TLS: pip installs
only by hash (`--require-hashes`), and apk only packages signed by Alpine's keys.

Measured 2026-10-03 against a TLS server whose certificate only a test CA vouched for.
Without the CA, apk said "Permission denied" (its word for a failed verification) and pip
said CERTIFICATE_VERIFY_FAILED. With `SSL_CERT_FILE` naming the CA, both got through. Both
add the named file to the system's trust rather than replacing it.

The CA bundle is `VALVUR_BUILD_CA` when set, else `SSL_CERT_FILE`, else the system's,
which in a session already trusts the proxy: its host-side fetches succeed.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from collections.abc import Mapping
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CA_ID = "build-ca"
CA_PATH = f"/run/secrets/{CA_ID}"
#: What every `RUN` becomes: the secret mounted for that step alone, and named where
#: OpenSSL (apk) and pip look for an extra authority.
PREFIX = (f"RUN --mount=type=secret,id={CA_ID} "
          f"export SSL_CERT_FILE={CA_PATH} PIP_CERT={CA_PATH} && ")
SYSTEM_BUNDLE = Path("/etc/ssl/certs/ca-certificates.crt")


def derive(dockerfile: str) -> str:
    """The Dockerfile with every shell-form `RUN` prefixed, and nothing else changed.
    A form the prefix would break (exec form, flags already given, a heredoc) is
    refused rather than guessed at."""
    lines = []
    for line in dockerfile.splitlines():
        if line.startswith("RUN "):
            rest = line.removeprefix("RUN ")
            if rest.lstrip().startswith(("[", "--", "<<")):
                raise ValueError(f"cannot prefix this RUN safely: {line}")
            line = PREFIX + rest
        lines.append(line)
    return "\n".join(lines) + ("\n" if dockerfile.endswith("\n") else "")


def ca_bundle(environ: Mapping[str, str], *, system: Path = SYSTEM_BUNDLE) -> Path | None:
    """The first of `VALVUR_BUILD_CA`, `SSL_CERT_FILE` and the system bundle that exists."""
    for candidate in (environ.get("VALVUR_BUILD_CA"), environ.get("SSL_CERT_FILE"), system):
        if candidate and Path(candidate).is_file():
            return Path(candidate)
    return None


def command(dockerfile: Path, ca: Path) -> list[str]:
    """Bake's `dev` target, with the derived Dockerfile and the CA as its secret. Bake
    reads a file outside the project only when allowed to ("additional privileges
    requested", measured 2026-10-03), so exactly those two are allowed, by their real
    paths: on macOS `/etc` is a link to `/private/etc`."""
    return ["docker", "buildx", "bake", "dev",
            "--set", f"dev.dockerfile={dockerfile}",
            "--set", f"dev.secrets=id={CA_ID},src={ca}",
            f"--allow=fs.read={dockerfile.parent.resolve()}",
            f"--allow=fs.read={ca.resolve()}"]


def _environment() -> dict[str, str]:
    """Bake's variables, as CONTRIBUTING.md's command sets them: the tree's version
    and the commit's time."""
    from valvur import __version__

    epoch = subprocess.run(["git", "-C", str(REPO), "log", "-1", "--format=%ct"],  # noqa: S603 — git, fixed arguments
                           capture_output=True, text=True, check=True).stdout.strip()
    return {**os.environ, "VALVUR_VERSION": __version__, "SOURCE_DATE_EPOCH": epoch}


def main() -> int:
    ca = ca_bundle(os.environ)
    if ca is None:
        print("no CA bundle: set VALVUR_BUILD_CA to the session's", file=sys.stderr)
        return 2
    with tempfile.TemporaryDirectory(prefix="valvur-cloud-image-") as scratch:
        dockerfile = Path(scratch) / "Dockerfile"
        dockerfile.write_text(derive((REPO / "Dockerfile").read_text()))
        print(f"building valvur:dev with {ca} as the build's CA, for RUN steps only")
        return subprocess.run(command(dockerfile, ca), cwd=REPO, env=_environment(),  # noqa: S603 — docker, fixed arguments
                              check=False).returncode


if __name__ == "__main__":
    sys.exit(main())
