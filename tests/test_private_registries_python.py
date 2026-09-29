"""R10.4: a Python project's own indexes (D27, F3.15).

Where a Python project installs from decides what a name missing from PyPI means:
- a private index that **replaces** PyPI means the name is served privately, and the
  advice is to reserve it;
- a private index **merged** with PyPI, where the resolver takes the best version
  from either (pip's `--extra-index-url`, a Poetry `supplemental` source), means a
  dependency-confusion exposure;
- a name **bound** to a private source is not looked up at all.

uv searches its configured indexes before PyPI and stops at the first that has the
package, so a plain uv index is not a merge. It becomes one only with
`index-strategy = "unsafe-best-match"`.
"""

from __future__ import annotations

from pathlib import Path

from valvur.checks.dependency_reality import DependencyRealityCheck

INDEX = "https://pypi.internal.example/simple"


def _repo(root: Path, files: dict[str, str]) -> Path:
    for name, body in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body)
    return root


def _rules(repo: Path) -> list[tuple[str, str]]:
    return [(f["rule"], f["severity"]) for f in DependencyRealityCheck().run(repo)]


def test_an_extra_index_in_a_requirements_file_is_a_confusion_exposure(tmp_path, name_index):
    name_index(pip=["requests"])
    repo = _repo(tmp_path, {"requirements.txt":
                            f"--extra-index-url {INDEX}\nacme-billing\nrequests\n"})

    assert _rules(repo) == [("valvur.dependency.confusion", "high")]


def test_an_index_url_alone_replaces_pypi_and_a_missing_name_is_advice(tmp_path, name_index):
    name_index(pip=["requests"])
    repo = _repo(tmp_path, {"requirements.txt": f"-i {INDEX}\nacme-billing\nrequests\n"})

    assert _rules(repo) == [("valvur.dependency.not-public", "low")]


def test_a_pip_conf_in_the_tree_is_the_project_s_declaration(tmp_path, name_index):
    name_index(pip=["requests"])
    repo = _repo(tmp_path, {"pip.conf": f"[global]\nextra-index-url = {INDEX}\n",
                            "requirements.txt": "acme-billing\nrequests\n"})

    assert _rules(repo) == [("valvur.dependency.confusion", "high")]


def test_a_uv_index_is_searched_first_and_merges_only_on_the_unsafe_strategy(
    tmp_path, name_index
):
    name_index(pip=["requests"])
    first = _repo(tmp_path / "first", {"pyproject.toml": (
        '[project]\nname = "app"\ndependencies = ["acme-billing", "requests"]\n\n'
        f'[[tool.uv.index]]\nname = "acme"\nurl = "{INDEX}"\n')})
    merged = _repo(tmp_path / "merged", {"pyproject.toml": (
        '[project]\nname = "app"\ndependencies = ["acme-billing", "requests"]\n\n'
        '[tool.uv]\nindex-strategy = "unsafe-best-match"\n\n'
        f'[[tool.uv.index]]\nname = "acme"\nurl = "{INDEX}"\n')})

    assert _rules(first) == [("valvur.dependency.not-public", "low")]
    assert _rules(merged) == [("valvur.dependency.confusion", "high")]


def test_a_name_bound_to_an_explicit_uv_index_is_not_looked_up(tmp_path, name_index):
    name_index(pip=["requests"])
    repo = _repo(tmp_path, {"pyproject.toml": (
        '[project]\nname = "app"\ndependencies = ["acme-billing", "requests"]\n\n'
        f'[[tool.uv.index]]\nname = "acme"\nurl = "{INDEX}"\nexplicit = true\n\n'
        '[tool.uv.sources]\nacme-billing = { index = "acme" }\n')})

    assert _rules(repo) == [("valvur.dependency.private-registry", "low")]


def test_poetry_supplemental_merges_and_explicit_binds(tmp_path, name_index):
    name_index(pip=["requests"])
    supplemental = _repo(tmp_path / "supplemental", {"pyproject.toml": (
        '[tool.poetry.dependencies]\npython = "^3.12"\nacme-billing = "^1"\nrequests = "^2"\n\n'
        f'[[tool.poetry.source]]\nname = "acme"\nurl = "{INDEX}"\npriority = "supplemental"\n')})
    explicit = _repo(tmp_path / "explicit", {"pyproject.toml": (
        '[tool.poetry.dependencies]\npython = "^3.12"\nrequests = "^2"\n'
        'acme-billing = { version = "^1", source = "acme" }\n\n'
        f'[[tool.poetry.source]]\nname = "acme"\nurl = "{INDEX}"\npriority = "explicit"\n')})

    assert _rules(supplemental) == [("valvur.dependency.confusion", "high")]
    assert _rules(explicit) == [("valvur.dependency.private-registry", "low")]


def test_a_pipfile_s_sources_are_read_with_its_packages(tmp_path, name_index):
    name_index(pip=["requests"])
    replaced = _repo(tmp_path / "replaced", {"Pipfile": (
        f'[[source]]\nname = "acme"\nurl = "{INDEX}"\nverify_ssl = true\n\n'
        '[packages]\nacme-billing = "*"\nrequests = "*"\n')})
    bound = _repo(tmp_path / "bound", {"Pipfile": (
        '[[source]]\nname = "pypi"\nurl = "https://pypi.org/simple"\nverify_ssl = true\n\n'
        f'[[source]]\nname = "acme"\nurl = "{INDEX}"\nverify_ssl = true\n\n'
        '[packages]\nrequests = "*"\nacme-billing = { version = "*", index = "acme" }\n'
        'nope-hallucinated-sdk = "*"\n')})

    assert _rules(replaced) == [("valvur.dependency.not-public", "low")]
    assert sorted(_rules(bound)) == [("valvur.dependency.nonexistent", "high"),
                                     ("valvur.dependency.private-registry", "low")]
