"""R10.5: what the README and the pipeline example claim (the review of 2026-09-29).

Four statements a first reader acts on, each held to what is true:
- the quick start never said a container runtime is needed;
- the platform table claimed every commit is tested on both runtimes and both
  architectures, while CI's e2e job runs on amd64 alone;
- the agent paragraph gave R7's first result, not its final one;
- the pipeline example cached nothing, so every run fetched the database again.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
README = (REPO / "README.md").read_text()


def test_the_quick_start_names_the_container_runtime_it_needs():
    quick_start = README.split("### From the command line", 1)[1].split("```", 1)[0]

    assert "Docker" in quick_start and "Podman" in quick_start


def test_the_platform_table_claims_only_the_architectures_ci_tests_end_to_end():
    ci = (REPO / ".github" / "workflows" / "ci.yml").read_text()
    e2e = ci.split("\n  e2e:", 1)[1].split("\n  published:", 1)[0]
    row = next(line for line in README.splitlines() if line.startswith("| Linux, Docker"))

    if "ubuntu-26.04-arm" not in e2e:
        # Until R16.1's arm64 leg: the e2e claim names amd64 alone, and arm64 only
        # where the published image is scanned.
        e2e_claim, published = row.split("published image", 1)
        assert "e2e" in e2e_claim and "`amd64`" in e2e_claim, row
        assert "arm64" not in e2e_claim, row
        assert "`arm64`" in published, row


def test_the_agent_paragraph_states_r7_s_final_record():
    agents = (REPO / "docs" / "AGENTS.md").read_text()  # moved there by R39.2
    paragraph = agents.split("Measured on the acceptance set with Claude Code", 1)[1]
    paragraph = " ".join(paragraph.split("\n\n", 1)[0].split())

    assert "every expected finding" in paragraph
    assert "five of the eight" not in paragraph or "six turns" in paragraph
    assert "the other three described one without naming it" not in paragraph


def test_the_pipeline_example_keeps_valvur_s_cache_between_runs():
    example = (REPO / "docs" / "examples" / "github-actions.yml").read_text()
    cache = re.search(r"uses: actions/cache@([0-9a-f]{40}) # v[\d.]+\n\s+with:\n"
                      r"\s+path: \$\{\{ runner\.temp \}\}/valvur-cache", example)

    assert cache, "the example does not cache $RUNNER_TEMP/valvur-cache with a pinned action"
    assert example.index("actions/cache@") < example.index("valvur update /src")
