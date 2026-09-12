"""Tasks 23.2.2 and 23.2.3 — Ruby, PHP and Rust, offline, from the index.

Measured 2026-09-12 before deciding: RubyGems is case-sensitive (`rails.json` 200,
`Rails.json` 404); Packagist is not (`Monolog/Monolog` answers with
`monolog/monolog`); crates.io folds case and `-`/`_` (`Serde` and `serde-json`
answer `serde` and `serde_json`). Each registry's first-publish date comes from a
different place: every gem version's `created_at`, Composer 2's minified `p2`
metadata, `crate.created_at`.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import valvur.checks.dependency_reality as mod
from valvur.checks.dependency_reality import DependencyRealityCheck


def _repo(root: Path, files: dict[str, str]) -> Path:
    for name, body in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body)
    return root


def _declared(root: Path, ecosystem: str) -> set[str]:
    return {name for eco, name, _ in mod._declared_packages(root) if eco == ecosystem}


def _nonexistent(found) -> list[str]:
    return sorted(f["identity"][2] for f in found if f["rule"] == "valvur.dependency.nonexistent")


# ------------------------------------------------------------------------ Ruby

GEMFILE = """\
source "https://rubygems.org"

gemspec

gem 'rails', '~> 7.1'
gem "puma", ">= 5.0", require: false
gem "nokogiri", platforms: [:ruby]
gem 'acme-internal', git: "https://git.acme.internal/acme-internal.git"
gem 'local-thing', path: "vendor/local-thing"
gem 'from-github', github: "acme/from-github", branch: "main"
gem "hash-rocket", :git => "https://example.com/x.git"

group :test do
  gem "rspec"
  gem 'nope-invented-gem'
end

source "https://gems.acme.internal" do
  gem "acme-private"
end

path "engines" do
  gem "engine-a"
end

git "https://github.com/acme/mono.git" do
  gem "mono-part"
end

platforms :jruby do
  gem "jruby-openssl"
end
# gem "commented-out"
"""

GEMSPEC = """\
Gem::Specification.new do |spec|
  spec.name = "acme-lib"
  spec.version = "1.0"
  spec.add_dependency "rack", ">= 2"
  spec.add_runtime_dependency('rake')
  spec.add_development_dependency "rspec", "~> 3"
  spec.add_development_dependency "nope-dev-gem"
end
"""


def test_gemfile_lines_are_read_and_non_registry_sources_are_not(tmp_path):
    names = _declared(_repo(tmp_path, {"Gemfile": GEMFILE}), "gem")

    assert {"rails", "puma", "nokogiri", "rspec", "nope-invented-gem", "jruby-openssl"} <= names
    assert not names & {"acme-internal", "local-thing", "from-github", "hash-rocket"}, \
        "git:, path:, github: and :git => are not on RubyGems"
    assert not names & {"acme-private", "engine-a", "mono-part"}, \
        "a source/path/git block's gems are not on RubyGems either"
    assert "commented-out" not in names


def test_a_gemspec_declares_its_dependencies_and_defines_its_own_gem(tmp_path):
    root = _repo(tmp_path, {"acme-lib.gemspec": GEMSPEC, "Gemfile": "gemspec\ngem 'acme-lib'\n"})

    names = _declared(root, "gem")

    assert {"rack", "rake", "rspec", "nope-dev-gem"} <= names
    assert "acme-lib" not in names, "the gem this tree defines is never asked about"


def test_offline_a_hallucinated_gem_is_found_from_the_index(tmp_path, name_index):
    name_index(gem=["rails", "puma", "nokogiri", "rspec", "jruby-openssl"])

    found = DependencyRealityCheck().run(_repo(tmp_path, {"Gemfile": GEMFILE}))

    assert _nonexistent(found) == ["nope-invented-gem"]
    assert "RubyGems" in found[0]["title"]
    assert found[0]["identity"] == ("dependency_reality", "gem", "nope-invented-gem")


def test_gem_names_are_case_sensitive_like_the_registry(tmp_path, name_index):
    """`gem "Rails"` names a gem that does not exist; the index must not fold it into
    the one that does."""
    name_index(gem=["rails"])

    found = DependencyRealityCheck().run(_repo(tmp_path, {"Gemfile": 'gem "Rails"\n'}))

    assert _nonexistent(found) == ["Rails"]


# ------------------------------------------------------------------------- PHP

COMPOSER = """\
{
  "name": "acme/app",
  "require": {
    "php": ">=8.1",
    "ext-json": "*",
    "lib-curl": "*",
    "composer-plugin-api": "^2",
    "Monolog/Monolog": "^3.0",
    "symfony/console": "^6",
    "acme/private-lib": "dev-main",
    "acme/path-lib": "@dev",
    "acme/packaged": "1.0",
    "nope/invented-package": "^1"
  },
  "require-dev": { "phpunit/phpunit": "^10" },
  "repositories": [
    { "type": "vcs", "url": "https://git.acme.internal/acme/private-lib.git" },
    { "type": "path", "url": "../acme/path-lib" },
    { "type": "package", "package": { "name": "acme/packaged", "version": "1.0" } }
  ]
}
"""


def test_composer_requires_are_read_and_platform_packages_are_not(tmp_path):
    names = _declared(_repo(tmp_path, {"composer.json": COMPOSER}), "composer")

    assert {"monolog/monolog", "symfony/console", "phpunit/phpunit",
            "nope/invented-package"} <= names
    assert not names & {"php", "ext-json", "lib-curl", "composer-plugin-api"}
    assert "acme/app" not in names, "the package this manifest defines"
    assert not names & {"acme/private-lib", "acme/path-lib", "acme/packaged"}, \
        "packages fetched from a vcs, path or package repository are not on Packagist"


def test_offline_a_hallucinated_composer_package_is_found_from_the_index(tmp_path, name_index):
    name_index(composer=["monolog/monolog", "symfony/console", "phpunit/phpunit"])

    found = DependencyRealityCheck().run(_repo(tmp_path, {"composer.json": COMPOSER}))

    assert _nonexistent(found) == ["nope/invented-package"]
    assert "Packagist" in found[0]["title"]


def test_a_malformed_composer_json_yields_nothing_rather_than_failing_the_check(tmp_path):
    assert _declared(_repo(tmp_path, {"composer.json": "{not json"}), "composer") == set()


# ------------------------------------------------------------------------ Rust

CARGO = """\
[package]
name = "acme-cli"
version = "0.1.0"

[dependencies]
serde = { version = "1", features = ["derive"] }
serde_json = "1"
tokio = { version = "1", features = ["full"] }
acme-core = { path = "../acme-core" }
from-git = { git = "https://github.com/acme/from-git" }
renamed = { package = "clap", version = "4" }
shared = { workspace = true }
private = { version = "1", registry = "acme-internal" }
nope-invented-crate = "0.1"

[dev-dependencies]
anyhow = "1"

[build-dependencies]
cc = "1"

[target.'cfg(windows)'.dependencies]
winapi = "0.3"

[workspace]
members = ["crates/*"]

[workspace.dependencies]
shared = "1"
regex = "1"
"""


def test_cargo_dependency_tables_are_read_in_every_shape(tmp_path):
    names = _declared(_repo(tmp_path, {"Cargo.toml": CARGO}), "cargo")

    assert {"serde", "serde_json", "tokio", "anyhow", "cc", "winapi", "regex", "shared",
            "nope-invented-crate"} <= names
    assert "clap" in names and "renamed" not in names, "`package =` names the real crate"
    assert not names & {"acme-core", "from-git", "private"}, "path, git and registry"
    assert "acme-cli" not in names


def test_a_workspace_member_is_not_reported_as_hallucinated(tmp_path):
    root = _repo(tmp_path, {
        "Cargo.toml": CARGO,
        "crates/acme-core/Cargo.toml":
            '[package]\nname = "acme-core"\n[dependencies]\nacme-cli = "0.1"\n',
    })

    names = _declared(root, "cargo")

    assert not names & {"acme-core", "acme-cli"}


def test_offline_a_hallucinated_crate_is_found_and_names_fold_like_crates_io(
    tmp_path, name_index
):
    """The index holds `serde_json`; `serde-json` in a manifest is the same crate.
    `Serde` would be too. `nope-invented-crate` is nothing."""
    name_index(cargo=["serde", "serde_json", "tokio", "clap", "anyhow", "cc", "winapi",
                      "regex", "shared"])
    manifest = CARGO.replace('serde_json = "1"', 'serde-json = "1"').replace(
        'serde = { version', 'Serde = { version')

    found = DependencyRealityCheck().run(_repo(tmp_path, {"Cargo.toml": manifest}))

    assert _nonexistent(found) == ["nope-invented-crate"]
    assert "crates.io" in found[0]["title"]


# --------------------------------------------------------------- on `full`: age

@pytest.fixture
def registry(monkeypatch, network_granted):
    asked: list[tuple[str, str]] = []

    def lookup(ecosystem: str, name: str):
        asked.append((ecosystem, name))
        return None if "nope" in name else {}

    monkeypatch.setattr(mod, "_lookup", lookup)
    return asked


def test_on_full_existing_names_are_asked_for_their_age_and_absent_ones_are_not(
    tmp_path, name_index, registry
):
    name_index(gem=["rails"], composer=["monolog/monolog"], cargo=["serde"])

    DependencyRealityCheck().run(_repo(tmp_path, {
        "Gemfile": 'gem "rails"\ngem "nope-gem"\n',
        "composer.json": '{"require": {"monolog/monolog": "^3", "nope/x": "*"}}',
        "Cargo.toml": '[dependencies]\nserde = "1"\nnope-crate = "1"\n',
    }))

    assert set(registry) == {("gem", "rails"), ("composer", "monolog/monolog"), ("cargo", "serde")}


def test_each_registry_is_asked_at_its_own_endpoint(monkeypatch):
    seen: list[str] = []

    def fetch(url, *, as_json=True):
        seen.append(url)
        return {}

    monkeypatch.setattr(mod, "_fetch", fetch)

    mod._lookup("gem", "rails")
    mod._lookup("composer", "monolog/monolog")
    mod._lookup("cargo", "serde-json")

    assert seen == [
        "https://rubygems.org/api/v1/versions/rails.json",
        "https://repo.packagist.org/p2/monolog/monolog.json",
        "https://crates.io/api/v1/crates/serde_json",
    ]


def test_a_gem_version_list_is_wrapped_so_the_age_reads_its_earliest_created_at(monkeypatch):
    monkeypatch.setattr(mod, "_fetch", lambda url, *, as_json=True: [
        {"number": "2.0", "created_at": "2026-01-01T00:00:00.000Z"},
        {"number": "1.0", "created_at": "2010-06-01T00:00:00.000Z"},
    ])

    meta = mod._lookup("gem", "rails")

    assert mod._age_days("gem", meta) > 365 * 10


def test_packagist_minified_metadata_carries_time_forward(monkeypatch):
    """Composer 2's `p2` files omit a field that did not change since the previous
    version. A missing `time` is "same as before", not "no date"."""
    meta = {"packages": {"acme/x": [
        {"version": "3.0.0", "time": "2026-09-01T00:00:00+00:00"},
        {"version": "2.9.0"},                                     # same time, minified
        {"version": "1.0.0", "time": "2012-03-04T00:00:00+00:00"},
        {"version": "0.9.0"},                                     # same as 1.0.0
    ]}}

    assert mod._packagist_times(meta) == [
        "2026-09-01T00:00:00+00:00", "2026-09-01T00:00:00+00:00",
        "2012-03-04T00:00:00+00:00", "2012-03-04T00:00:00+00:00",
    ]
    assert mod._age_days("composer", meta) > 365 * 10


def test_a_crate_dates_from_its_created_at():
    assert mod._age_days("cargo", {"crate": {"created_at": "2015-01-01T00:00:00.000000Z"}}) > 3000
    assert mod._age_days("cargo", {"crate": {}}) is None


# ------------------------------------------------------- the coverage contract

def test_the_contract_reads_all_five_ecosystems_offline(tmp_path):
    from valvur.adapters import DEFAULT_ADAPTERS

    reality = next(a for a in DEFAULT_ADAPTERS if a.name == "dependency-reality")
    declared = reality.coverage(tmp_path)

    inspected = " ".join(declared.inspects)
    for manifest in ("requirements*.txt", "package.json", "Gemfile", "*.gemspec",
                     "composer.json", "Cargo.toml"):
        assert manifest in inspected, manifest
    assert not any("Ruby" in line or "PHP" in line or "Rust" in line for line in declared.ignores)


def test_without_a_gem_index_an_offline_ruby_scan_fails_loudly(tmp_path, name_index):
    """A cache built before 23.2.2 has no `rubygems.txt`. The Check must not read
    silence as "checked and clean" — it says which index is missing and what
    fetches it (F3.5)."""
    from valvur.name_index import FILES

    directory = name_index(gem=["rails"])
    (directory / FILES["gem"]).unlink()

    with pytest.raises(mod.IndexMissing, match="RubyGems"):
        DependencyRealityCheck().run(_repo(tmp_path, {"Gemfile": 'gem "rails"\n'}))
