"""R12.1: `check_package`, before the install (D28, F3.16, ADR-0028).

A scan reports a hallucinated dependency after it is written, and often after it is
installed: the install is when a squatted name runs its code. So the same answers the
dependency-reality Check gives are offered before: is this name real, is it one edit
from a popular one, is it on the malicious list, and does this project's registry
configuration expose it to confusion. From the host cache alone, and never from a
registry: asking a registry about a hallucinated name tells it, and anyone watching
it, what to register.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from valvur import packages
from valvur.name_index import malicious

FIXTURE = Path(__file__).parent / "fixtures" / "malicious-packages"
PRIVATE = "https://pypi.acme.example/simple"


@pytest.fixture
def index(name_index):
    directory = name_index(pip=["requests", "flask"], npm=["react", "atez"],
                           built_at="2026-09-29T09:57:48Z")
    assert malicious._main(["build-malicious", str(directory), str(FIXTURE)]) == 0
    return directory


def _one(ecosystem: str, name: str, version: str | None = None, **kwargs) -> packages.Answer:
    [answer] = packages.check([(ecosystem, name, version)], **kwargs)
    return answer


def test_a_real_package_exists_and_says_what_it_was_checked_against(index):
    answer = _one("pip", "requests")

    assert answer.verdict == "exists"
    assert answer.index_built == "2026-09-29"
    assert not answer.flagged


def test_a_hallucinated_package_is_nonexistent(index):
    answer = _one("pypi", "fastapi-auth-middleware-pro")    # OSV's spelling works too

    assert (answer.ecosystem, answer.verdict) == ("pip", "nonexistent")
    assert answer.flagged


def test_a_name_one_edit_from_a_popular_one_is_a_near_miss_naming_it(index):
    answer = _one("pip", "reqeusts")

    assert answer.verdict == "near-miss"
    assert answer.near == "requests"
    assert answer.flagged


def test_a_malicious_package_names_its_advisory(index):
    whole = _one("npm", "atez")
    locked = _one("npm", "@hyperion-util/cookies", "77.77.79")
    other = _one("npm", "@hyperion-util/cookies", "1.0.0")

    assert (whole.verdict, whole.ids) == ("malicious", ("MAL-2022-1153",))
    assert (locked.verdict, locked.ids) == ("malicious", ("MAL-2023-1",))
    assert other.verdict == "nonexistent"        # removed from npm; that version never listed


def _project(root: Path, requirements: str) -> Path:
    root.mkdir()
    (root / "requirements.txt").write_text(requirements)
    return root


def test_a_merged_private_index_makes_a_missing_name_a_confusion_exposure(index, tmp_path):
    project = _project(tmp_path / "p", f"--extra-index-url {PRIVATE}\n")

    answer = _one("pip", "acme-billing", workspace=project)

    assert answer.verdict == "confusion"
    assert answer.source == PRIVATE
    assert answer.flagged


def test_a_replaced_index_makes_a_missing_name_not_public(index, tmp_path):
    project = _project(tmp_path / "p", f"--index-url {PRIVATE}\n")

    answer = _one("pip", "acme-billing", workspace=project)

    assert answer.verdict == "not-public"
    assert not answer.flagged


def test_jvm_and_go_are_unknown_offline(index):
    answers = packages.check([("maven", "org.apache.logging.log4j:log4j-core", "2.14.0"),
                              ("gomod", "github.com/spf13/cobra", None)])

    assert [a.verdict for a in answers] == ["unknown", "unknown"]
    assert "no offline index" in answers[0].reason


def _fifty() -> list[tuple[str, str, str | None]]:
    names = [("pip", "requests", None), ("pip", "reqeusts", None), ("npm", "atez", None),
             ("npm", "react", "18.2.0"), ("gomod", "github.com/spf13/cobra", None)]
    return [names[i % len(names)] if i < 5 else ("pip", f"made-up-{i}", None)
            for i in range(50)]


def test_a_batch_of_fifty_is_answered_in_order(index):
    answers = packages.check(_fifty())

    assert len(answers) == 50
    assert [a.verdict for a in answers[:5]] == [
        "exists", "near-miss", "malicious", "exists", "unknown"]
    assert {a.verdict for a in answers[5:]} == {"nonexistent"}


def test_no_socket_is_opened(index, record_connections):
    packages.check(_fifty())

    assert record_connections == []


@pytest.mark.timing
def test_fifty_are_answered_in_under_a_second(index):
    started = time.monotonic()
    packages.check(_fifty())

    assert time.monotonic() - started < 1.0


def test_a_spec_is_a_name_and_an_optional_version():
    assert packages.parse("npm", "@scope/name@1.2.3") == ("npm", "@scope/name", "1.2.3")
    assert packages.parse("npm", "@scope/name") == ("npm", "@scope/name", None)
    assert packages.parse("pip", "requests@2.31.0") == ("pip", "requests", "2.31.0")
    assert packages.parse("pip", "requests==2.31.0") == ("pip", "requests", "2.31.0")


def test_a_gem_in_a_private_source_block_is_bound_not_nonexistent(index, tmp_path):
    project = tmp_path / "p"
    project.mkdir()
    (project / "Gemfile").write_text("source 'https://rubygems.org'\n\n"
                                     "source 'https://gems.acme.example' do\n"
                                     "  gem 'acme-billing'\nend\n")

    answer = _one("gem", "acme-billing", workspace=project)

    assert answer.verdict == "unknown" and answer.source == "https://gems.acme.example"


def test_a_crate_from_an_alternative_registry_is_bound_not_nonexistent(index, tmp_path):
    project = tmp_path / "p"
    (project / ".cargo").mkdir(parents=True)
    (project / "Cargo.toml").write_text('[package]\nname = "case"\nversion = "0.1.0"\n\n'
                                        '[dependencies]\n'
                                        'acme-billing = { version = "1", registry = "acme" }\n')
    (project / ".cargo" / "config.toml").write_text(
        '[registries.acme]\nindex = "sparse+https://cargo.acme.example/"\n')

    answer = _one("cargo", "acme-billing", workspace=project)

    assert answer.verdict == "unknown"
    assert answer.source == "sparse+https://cargo.acme.example/"
