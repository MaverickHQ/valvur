"""Whether a Scanner has anything to look at in this Workspace.

Checkov costs 11.2 seconds of fixed startup — measured 2026-09-05, more than every
other Scanner in the `offline` Profile combined — and a repository with no
infrastructure code pays all of it for nothing.

The danger in skipping is worse than the cost of running: **a conditional Scanner is
a Scanner that can silently stop running**, which is the failure class Phase 11
exists to catch. Three rules follow from that, and they are not optional.

  1. **Bias to running.** A marker we do not recognise means we scan. Every
     ambiguous case resolves towards doing the work.
  2. **Never silent.** The skip is recorded in `run.json` and named in `SUMMARY.md`.
     A Scanner that did not run must never look like one that found nothing.
  3. **Both branches are tested**, including that a repository with infrastructure
     still triggers the scan. A detector that always returned False would otherwise
     pass a test suite that only checks the skip.
"""

from __future__ import annotations

from pathlib import Path

from .exclusions import is_vendored

# Names and suffixes that are infrastructure code beyond argument. Matching one of
# these is enough on its own — no content check, no ambiguity.
_IAC_SUFFIXES = frozenset({
    ".tf", ".tfvars", ".bicep",
})
_IAC_NAMES = frozenset({
    "dockerfile", "containerfile", "docker-compose.yml", "docker-compose.yaml",
    "compose.yml", "compose.yaml", "serverless.yml", "serverless.yaml",
    "chart.yaml", "kustomization.yaml", "kustomization.yml",
    "template.yaml", "template.yml", ".gitlab-ci.yml",
    "bitbucket-pipelines.yml", "azure-pipelines.yml", "azure-pipelines.yaml",
})
_IAC_PARENTS = frozenset({".github/workflows", ".circleci", ".argo", "argo"})

# Markers inside a YAML or JSON file that make it infrastructure. Checkov's
# kubernetes, cloudformation, arm, openapi and ansible runners all act on files that
# carry no distinguishing name — deploy/app.yaml is a Kubernetes manifest or a CI
# config depending only on its contents.
_CONTENT_MARKERS = (
    ("apiVersion", "kind"),                       # kubernetes
    ("AWSTemplateFormatVersion",),                # cloudformation
    ("Resources", "AWS::"),                       # cloudformation, terser form
    ("deploymentTemplate.json",),                 # azure arm
    ("openapi",),                                 # openapi
    ("swagger",),                                 # openapi 2
)
_SNIFFABLE = frozenset({".yml", ".yaml", ".json"})

# Bounded so a large repository cannot turn detection into its own cost. Reading the
# head of a file is enough: these markers are all top-level keys.
_SNIFF_BYTES = 4096
_SNIFF_LIMIT = 400


def iac_present(workspace: Path) -> tuple[bool, str]:
    """Whether Checkov has infrastructure to analyse, and the evidence for it.

    Returns (True, "<the file that decided it>") or (False, ""). The evidence is
    reported rather than discarded: "we skipped Checkov" is a claim the reader should
    be able to check.
    """
    sniffed = 0
    for path in _candidates(workspace):
        name = path.name.lower()
        if path.suffix.lower() in _IAC_SUFFIXES or name in _IAC_NAMES:
            return True, _relative(path, workspace)
        if name.startswith("dockerfile."):
            return True, _relative(path, workspace)
        parent = _relative(path.parent, workspace)
        if parent in _IAC_PARENTS and path.suffix.lower() in {".yml", ".yaml"}:
            return True, _relative(path, workspace)

        if path.suffix.lower() in _SNIFFABLE and sniffed < _SNIFF_LIMIT:
            sniffed += 1
            if _looks_like_infrastructure(path):
                return True, _relative(path, workspace)

    return False, ""


def _candidates(workspace: Path):
    for path in workspace.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(workspace)
        if is_vendored(str(relative)):
            continue
        yield path


def _relative(path: Path, workspace: Path) -> str:
    try:
        return str(path.relative_to(workspace))
    except ValueError:
        return path.name


def _looks_like_infrastructure(path: Path) -> bool:
    """Read the head of a YAML or JSON file for a framework's fingerprint.

    An unreadable file counts as infrastructure. We cannot tell what it holds, and
    rule 1 says an unresolved case resolves towards scanning.
    """
    try:
        head = path.read_text(encoding="utf-8", errors="ignore")[:_SNIFF_BYTES]
    except OSError:
        return True
    return any(all(token in head for token in marker) for marker in _CONTENT_MARKERS)
