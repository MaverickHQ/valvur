# OpenSSF Best Practices: the answers

The answers to every criterion of the OpenSSF Best Practices badge's *passing* level,
each with a link to its evidence, for the owner to paste into the form at
bestpractices.dev (`tasks.md` §8). The form needs the owner's account; nothing here is
submitted by the build. `tests/test_best_practices.py` holds this page to the
criteria's identifiers, and the link check reads it.

Each line is the criterion's identifier, the answer (**Met**, **Unmet** or **N/A**),
and why. Where only the owner can confirm an answer, the line says so.

## Basics

- **homepage_url**: Met. https://github.com/MaverickHQ/valvur, the repository and its README. [README](../README.md)
- **description_good**: Met. The README's first line says what valvur does: a fully offline security scanner for AI-generated code. [README](../README.md)
- **interact**: Met. The README says how to install it, report a problem and contribute. [README, Support](../README.md#support)
- **contribution**: Met. Contributions are pull requests, preceded by an issue for anything large. [CONTRIBUTING.md](../CONTRIBUTING.md)
- **contribution_requirements**: Met. Tests first, `scripts/verify.sh` green (lint, types, traceability, tests, build), Conventional Commits. [CONTRIBUTING.md](../CONTRIBUTING.md), [the pull request template](../.github/PULL_REQUEST_TEMPLATE.md)
- **floss_license**: Met. Apache-2.0. [LICENSE](../LICENSE)
- **floss_license_osi**: Met. Apache-2.0 is OSI-approved. [LICENSE](../LICENSE)
- **license_location**: Met. `LICENSE` at the repository's root. [LICENSE](../LICENSE)
- **documentation_basics**: Met. The README, and the documents under `docs/`. [README](../README.md), [EVALUATING.md](EVALUATING.md)
- **documentation_interface**: Met. The MCP tools' inputs and outputs, the CLI's commands, and the container protocol. [the MCP tools](../src/valvur/data/skills/valvur/references/tools.md), [PROTOCOL.md](PROTOCOL.md)
- **sites_https**: Met. The repository, PyPI and GHCR serve HTTPS only. [README](../README.md)
- **discussion**: Met. GitHub issues and pull requests: searchable, addressable by URL, open to anyone. [the issue tracker](https://github.com/MaverickHQ/valvur/issues)
- **english**: Met. Every document is in English, and reports are taken in English. [CONTRIBUTING.md](../CONTRIBUTING.md)
- **maintained**: Met. Releases and changes are recorded as they happen. [CHANGELOG.md](../CHANGELOG.md)

## Change control

- **repo_public**: Met. https://github.com/MaverickHQ/valvur. [README](../README.md)
- **repo_track**: Met. git records each change, its author and its time; commits on `main` are signed. [MAINTAINERS.md](../MAINTAINERS.md)
- **repo_interim**: Met. Every change lands through a reviewed pull request between releases. [CONTRIBUTING.md](../CONTRIBUTING.md)
- **repo_distributed**: Met. git. [CONTRIBUTING.md](../CONTRIBUTING.md)
- **version_unique**: Met. Each release has one version, held equal on every surface by a test. [RELEASING.md](RELEASING.md)
- **version_semver**: Met. Semantic Versioning. [CHANGELOG.md](../CHANGELOG.md)
- **version_tags**: Met. Each release is a signed tag `v<version>`. [RELEASING.md](RELEASING.md)
- **release_notes**: Met. Each release's section in the changelog, in Keep a Changelog's form. [CHANGELOG.md](../CHANGELOG.md)
- **release_notes_vulns**: N/A. No release has fixed a vulnerability in valvur that had a CVE or similar assignment; one would be named in its section. [CHANGELOG.md](../CHANGELOG.md), [SECURITY.md](../SECURITY.md)

## Reporting

- **report_process**: Met. GitHub issues, with the tarball `valvur doctor --bundle` writes. [README, Support](../README.md#support)
- **report_tracker**: Met. GitHub issues. [the issue tracker](https://github.com/MaverickHQ/valvur/issues)
- **report_responses**: Met, for the owner to confirm against the tracker's last 12 months. [the issue tracker](https://github.com/MaverickHQ/valvur/issues)
- **enhancement_responses**: Met, for the owner to confirm against the tracker's last 12 months. [the issue tracker](https://github.com/MaverickHQ/valvur/issues)
- **report_archive**: Met. Every issue and its replies stay public on GitHub. [the issue tracker](https://github.com/MaverickHQ/valvur/issues?q=is%3Aissue)
- **vulnerability_report_process**: Met. The security policy, linked from the README. [SECURITY.md](../SECURITY.md)
- **vulnerability_report_private**: Met. GitHub's private vulnerability reporting. [SECURITY.md](../SECURITY.md)
- **vulnerability_report_response**: Met. The policy promises acknowledgement within 5 working days; the owner confirms none in the last 6 months went past 14. [SECURITY.md](../SECURITY.md)

## Quality

- **build**: Met. `uv build` makes the package and `docker buildx bake` the image, from source, in CI on every pull request. [CONTRIBUTING.md](../CONTRIBUTING.md), [ci.yml](../.github/workflows/ci.yml)
- **build_common_tools**: Met. hatchling, uv, Docker Buildx. [pyproject.toml](../pyproject.toml), [docker-bake.hcl](../docker-bake.hcl)
- **build_floss_tools**: Met. Every tool in the build is FLOSS. [NOTICE](../NOTICE)
- **test**: Met. pytest, released with the project; how to run it is in CONTRIBUTING. [CONTRIBUTING.md](../CONTRIBUTING.md)
- **test_invocation**: Met. `pytest`, as Python projects do. [CONTRIBUTING.md](../CONTRIBUTING.md)
- **test_most**: Met. About two thousand unit tests, end-to-end tests against the real container, and a CI job that reverts each hunk of a change to see a test notice. [ci.yml](../.github/workflows/ci.yml)
- **test_continuous_integration**: Met. Every pull request runs the tests on Python 3.11, 3.12 and 3.13, end to end on amd64 and arm64. [ci.yml](../.github/workflows/ci.yml)
- **test_policy**: Met. Every change is test-driven: a failing test first, then the code. [CONTRIBUTING.md](../CONTRIBUTING.md)
- **tests_are_added**: Met. Each recent phase's changes came with their tests, recorded in each phase's exit. [docs/acceptance](acceptance/r21.md)
- **tests_documented_added**: Met. The pull request template's first item. [the pull request template](../.github/PULL_REQUEST_TEMPLATE.md)
- **warnings**: Met. ruff, with the bugbear and bandit rule sets, and mypy. [pyproject.toml](../pyproject.toml)
- **warnings_fixed**: Met. CI fails on any ruff or mypy warning. [ci.yml](../.github/workflows/ci.yml)
- **warnings_strict**: Met. ruff's `E, F, I, UP, B, S, RUF` sets, and a `noqa` carries its reason. [pyproject.toml](../pyproject.toml)

## Security

- **know_secure_design**: Met, for the owner to confirm of themselves. The design's security decisions are recorded as ADRs: a sealed container, source copied in and never mounted, no network on the default Profile. [the ADRs](adr/0001-thin-host-shim-read-only-container.md)
- **know_common_errors**: Met, for the owner to confirm of themselves. The constraint tests hold the mitigations: exfiltration, isolation, supply chain, interruption. [EVALUATING.md](EVALUATING.md)
- **crypto_published**: Met. valvur uses only published algorithms: SHA-256, and Sigstore's signatures, verified by cosign. [AIR-GAPPED.md](AIR-GAPPED.md)
- **crypto_call**: Met. valvur implements no cryptography; it calls Python's `hashlib` and `ssl`, and cosign. [PROTOCOL.md](PROTOCOL.md)
- **crypto_floss**: Met. Python and cosign are FLOSS. [NOTICE](../NOTICE)
- **crypto_keylength**: N/A. valvur creates no keys; it verifies signatures made by others. [AIR-GAPPED.md](AIR-GAPPED.md)
- **crypto_working**: Met. No broken algorithm secures anything: SHA-256 for integrity; MD5 and SHA-1 appear nowhere in a security mechanism. [SECURITY.md](../SECURITY.md)
- **crypto_weaknesses**: Met. No SHA-1 or CBC mode in a security mechanism. [SECURITY.md](../SECURITY.md)
- **crypto_pfs**: N/A. valvur implements no key agreement; TLS is Python's, at its defaults. [SECURITY.md](../SECURITY.md)
- **crypto_password_storage**: N/A. valvur stores no passwords; it has no accounts. [README, Privacy](../README.md#privacy)
- **crypto_random**: N/A. valvur generates no cryptographic keys or nonces. [README, Privacy](../README.md#privacy)
- **delivery_mitm**: Met. PyPI and GHCR over HTTPS, with PyPI's attestations and the image's signed provenance. [RELEASING.md](RELEASING.md)
- **delivery_unsigned**: Met. Every binary the image fetches is checked against a pinned SHA-256, and releases are verified by their provenance. [Dockerfile](../Dockerfile)
- **vulnerabilities_fixed_60_days**: Met. The release gate scans valvur with itself, clean, before each release. Scorecard's count of vulnerabilities comes from the lockfiles planted in `tests/fixtures/` to be found, which are not dependencies. [RELEASING.md](RELEASING.md)
- **vulnerabilities_critical_fixed**: Met. The self-scan gate blocks a release with an active finding. [RELEASING.md](RELEASING.md)
- **no_leaked_credentials**: Met. Gitleaks scans the repository and its history on every pull request; planted test credentials are assembled at runtime. [ci.yml](../.github/workflows/ci.yml)

## Analysis

- **static_analysis**: Met. ruff, mypy, and valvur's own scan of itself (Opengrep, Gitleaks, zizmor, Trivy, OSV-Scanner) on every pull request. [ci.yml](../.github/workflows/ci.yml)
- **static_analysis_common_vulnerabilities**: Met. ruff's bandit rules, and Opengrep's rules for injection, unsafe deserialisation and weak cryptography. [rules](../rules/python-security.yaml)
- **static_analysis_fixed**: Met. The self-scan gate fails on any active finding, at any severity. [ci.yml](../.github/workflows/ci.yml)
- **static_analysis_often**: Met. On every pull request. [ci.yml](../.github/workflows/ci.yml)
- **dynamic_analysis**: Unmet. No fuzzer or dynamic scanner is applied before a release; the end-to-end tests run the real container, which is testing, not dynamic analysis. [ci.yml](../.github/workflows/ci.yml)
- **dynamic_analysis_unsafe**: N/A. valvur is Python, a memory-safe language. [pyproject.toml](../pyproject.toml)
- **dynamic_analysis_enable_assertions**: Met. The tests run with Python's assertions on, as pytest requires. [CONTRIBUTING.md](../CONTRIBUTING.md)
- **dynamic_analysis_fixed**: N/A. No dynamic analysis tool is applied, so none has found anything. [ci.yml](../.github/workflows/ci.yml)
