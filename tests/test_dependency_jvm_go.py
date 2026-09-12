"""Task 22.A.4 — existence checks for JVM and Go, on `full` only.

Measured 2026-09-12 before deciding: Maven Central's only name index is the Lucene
one at **3.24GB**; its search API holds 661,801 coordinates and pages 200 at a time.
The Go module index is a *version* feed — 2,000 entries did not cover seventeen
minutes of one day — with no distinct-module list. Neither can be fetched into the
offline index, so both are asked of the registry per name, on `full`, and stated as a
Profile omission on `offline` — never a failure, never a gap Finding (F7.16).

Live probes the same day: `org.apache.commons:commons-lang3` → 200 and an invented
coordinate → 404 from `repo1.maven.org` in 70 to 350ms; `github.com/gorilla/mux` → 200
and an invented module → 404 from `proxy.golang.org` in 0.4 to 1.5s.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import valvur.checks.dependency_reality as mod
from valvur.checks.dependency_reality import DependencyRealityCheck


@pytest.fixture
def registry(monkeypatch, network_granted):
    """The `full` Profile. Everything exists except names containing `nope`; the
    list of (ecosystem, name) pairs asked is what most assertions are about."""
    asked: list[tuple[str, str]] = []

    def lookup(ecosystem: str, name: str):
        asked.append((ecosystem, name))
        return None if "nope" in name else {}

    monkeypatch.setattr(mod, "_lookup", lookup)
    return asked


def _repo(root: Path, files: dict[str, str]) -> Path:
    for name, body in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body)
    return root


def _names(asked, ecosystem):
    return sorted(n for eco, n in asked if eco == ecosystem)


POM = """<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>com.acme</groupId>
  <artifactId>app</artifactId>
  <dependencies>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-lang3</artifactId>
      <version>3.14.0</version>
    </dependency>
    <dependency>
      <groupId>com.acme.nope</groupId>
      <artifactId>Invented-Helper</artifactId>
    </dependency>
    <dependency>
      <groupId>${project.groupId}</groupId>
      <artifactId>app-core</artifactId>
    </dependency>
    <dependency>
      <groupId>${some.property}</groupId>
      <artifactId>unknowable</artifactId>
    </dependency>
  </dependencies>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>org.junit</groupId>
        <artifactId>junit-bom</artifactId>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>
"""


# --------------------------------------------------------------------------- Maven

def test_a_pom_is_read_and_a_hallucinated_coordinate_is_a_finding(tmp_path, registry):
    found = DependencyRealityCheck().run(_repo(tmp_path, {"pom.xml": POM}))

    assert [f["rule"] for f in found] == ["valvur.dependency.nonexistent"]
    assert "com.acme.nope:invented-helper" in found[0]["title"]
    assert "Maven Central" in found[0]["title"]
    assert found[0]["identity"] == ("dependency_reality", "maven", "com.acme.nope:invented-helper")


def test_pom_properties_are_resolved_only_where_they_can_be(tmp_path, registry):
    """`${project.groupId}` is this pom's own group; anything else is a name we
    cannot know, and asking a registry about `${some.property}` would be noise."""
    DependencyRealityCheck().run(_repo(tmp_path, {"pom.xml": POM}))

    asked = _names(registry, "maven")
    assert "com.acme:app-core" in asked
    assert not any("${" in name for name in asked)
    assert "org.junit:junit-bom" in asked, "dependencyManagement is where BOMs are declared"


def test_a_pom_without_the_maven_namespace_is_read_too(tmp_path, registry):
    plain = POM.replace(' xmlns="http://maven.apache.org/POM/4.0.0"', "")

    DependencyRealityCheck().run(_repo(tmp_path, {"pom.xml": plain}))

    assert "org.apache.commons:commons-lang3" in _names(registry, "maven")


def test_a_reactor_module_is_not_reported_as_hallucinated(tmp_path, registry):
    """The monorepo defect (19.F.4), in Maven's shape: a multi-module build declares
    its own modules as dependencies, with the group inherited from `<parent>`."""
    DependencyRealityCheck().run(_repo(tmp_path, {
        "pom.xml": POM.replace("<artifactId>app-core</artifactId>",
                               "<artifactId>nope-core</artifactId>"),
        "core/pom.xml": """<project>
  <parent><groupId>com.acme</groupId><artifactId>app</artifactId></parent>
  <artifactId>nope-core</artifactId>
</project>""",
    }))

    assert "com.acme:nope-core" not in _names(registry, "maven")
    assert "com.acme:app" not in _names(registry, "maven")


def test_a_malformed_pom_does_not_take_the_scanner_down(tmp_path, registry):
    found = DependencyRealityCheck().run(_repo(tmp_path, {
        "pom.xml": "<project><dependencies>not closed",
        "requirements.txt": "nope-invented\n",
    }))

    assert [f["rule"] for f in found] == ["valvur.dependency.nonexistent"]


# -------------------------------------------------------------------------- Gradle

@pytest.mark.parametrize("script,filename", [
    ("""
plugins { id 'java' }
dependencies {
    implementation 'org.apache.commons:commons-lang3:3.14.0'
    testImplementation "org.junit.jupiter:junit-jupiter:5.10.0"
    implementation project(':lib')
    implementation "com.acme.nope:invented:1.0" // a comment: 'x:y:z'
    api 'no-colon-here'
}
""", "build.gradle"),
    ("""
dependencies {
    implementation("org.apache.commons:commons-lang3:3.14.0")
    testImplementation("org.junit.jupiter:junit-jupiter")
    implementation(project(":lib"))
    implementation("com.acme.nope:invented:1.0")
    implementation(libs.guava)
}
""", "build.gradle.kts"),
])
def test_gradle_coordinates_are_read_in_both_dsls(tmp_path, registry, script, filename):
    found = DependencyRealityCheck().run(_repo(tmp_path, {filename: script}))

    assert _names(registry, "maven") == [
        "com.acme.nope:invented", "org.apache.commons:commons-lang3",
        "org.junit.jupiter:junit-jupiter",
    ]
    assert [f["title"].split("'")[1] for f in found] == ["com.acme.nope:invented"]


def test_the_gradle_version_catalog_is_read(tmp_path, registry):
    """A project that declares everything in `libs.versions.toml` and references
    `libs.foo` from its build script would otherwise scan clean."""
    DependencyRealityCheck().run(_repo(tmp_path, {
        "build.gradle.kts": "dependencies { implementation(libs.guava) }\n",
        "gradle/libs.versions.toml": """
[versions]
guava = "33.0.0-jre"
[libraries]
guava = { module = "com.google.guava:guava", version.ref = "guava" }
nope = { group = "com.acme.nope", name = "catalogued", version = "1" }
bare = "org.slf4j:slf4j-api:2.0.0"
""",
    }))

    assert _names(registry, "maven") == [
        "com.acme.nope:catalogued", "com.google.guava:guava", "org.slf4j:slf4j-api",
    ]


# ------------------------------------------------------------------------------ Go

GO_MOD = """module github.com/acme/app

go 1.22

require (
\tgithub.com/gorilla/mux v1.8.1
\tgithub.com/nope-zz/invented v0.1.0
\tgolang.org/x/text v0.14.0 // indirect
\tgithub.com/BurntSushi/toml v1.3.2
)

require github.com/acme/app/internal v0.0.0

replace github.com/acme/app/internal => ./internal
"""


def test_go_mod_direct_requires_are_read(tmp_path, registry):
    found = DependencyRealityCheck().run(_repo(tmp_path, {"go.mod": GO_MOD}))

    assert _names(registry, "gomod") == [
        "github.com/BurntSushi/toml", "github.com/gorilla/mux", "github.com/nope-zz/invented",
    ]
    assert [f["title"].split("'")[1] for f in found] == ["github.com/nope-zz/invented"]
    assert "the Go module proxy" in found[0]["title"]
    assert found[0]["identity"] == ("dependency_reality", "gomod", "github.com/nope-zz/invented")


def test_indirect_and_locally_replaced_modules_are_not_asked_about(tmp_path, registry):
    """`// indirect` is the transitive tree — a lockfile's contents in a manifest's
    clothing — and a `replace ... => ./local` names something on no registry."""
    DependencyRealityCheck().run(_repo(tmp_path, {"go.mod": GO_MOD}))

    asked = _names(registry, "gomod")
    assert "golang.org/x/text" not in asked
    assert "github.com/acme/app/internal" not in asked
    assert "github.com/acme/app" not in asked


def test_the_go_proxy_url_escapes_uppercase_the_way_the_protocol_requires(monkeypatch):
    """`github.com/BurntSushi/toml` is served at `github.com/!burnt!sushi/toml`.
    Verified live 2026-09-12: the escaped form returns 200."""
    seen: list[str] = []
    monkeypatch.setattr(mod, "_fetch", lambda url, **kw: seen.append(url) or {})

    mod._lookup("gomod", "github.com/BurntSushi/toml")
    mod._lookup("maven", "org.apache.commons:commons-lang3")

    assert seen[0] == "https://proxy.golang.org/github.com/!burnt!sushi/toml/@v/list"
    assert seen[1] == (
        "https://repo1.maven.org/maven2/org/apache/commons/commons-lang3/maven-metadata.xml"
    )


def test_a_gone_module_is_absent_not_unreachable(monkeypatch):
    """The proxy answers 410 for a module it will not serve; `go get` fails the
    same way, so for existence it is a 404."""
    import urllib.error

    def gone(request, timeout=None):
        raise urllib.error.HTTPError(request.full_url, 410, "Gone", {}, None)

    monkeypatch.setattr(mod.urllib.request, "urlopen", gone)

    assert mod._fetch("https://proxy.golang.org/x/@v/list", as_json=False) is None


# ------------------------------------------------------------- offline: stated, not failed

def test_offline_a_jvm_or_go_project_is_neither_failed_nor_asked(tmp_path, monkeypatch):
    """No index exists for these registries, by design. On `offline` the Check has
    nothing to do for them and says so in its Coverage contract — it must not raise
    `IndexMissing`, which would tell the user to run `valvur update` for something
    `valvur update` cannot fetch."""
    monkeypatch.setattr(mod, "_lookup", lambda eco, name: pytest.fail(f"asked about {name}"))

    found = DependencyRealityCheck().run(_repo(tmp_path, {"pom.xml": POM, "go.mod": GO_MOD}))

    assert found == []


def test_offline_python_is_still_checked_beside_an_unchecked_jvm_manifest(tmp_path, name_index):
    """Dropping the full-only ecosystems must not drop the ones the index covers."""
    name_index(pip=["requests"])

    found = DependencyRealityCheck().run(_repo(tmp_path, {
        "pom.xml": POM, "requirements.txt": "requests\nnope-invented\n",
    }))

    assert [f["title"].split("'")[1] for f in found] == ["nope-invented"]


def test_the_scan_level_verdict_offline_is_a_profile_omission_not_inconclusive(
    tmp_path, runner_finding_nothing
):
    """F7.16 as amended: valvur can check JVM on `full`, so an `offline` scan of a
    JVM project reads `clean` with the omission named — the same rule osv-scanner
    follows — rather than `inconclusive`, which is for jobs nobody could decline."""
    from valvur import scan

    ws = _repo(tmp_path / "ws", {"pom.xml": POM, "LICENSE": "MIT"})
    run = scan(ws, runner=runner_finding_nothing, profile="offline")

    assert run.coverage_notes == []
    assert "JVM (Maven/Gradle): existence checked on `full` only" in " ".join(
        run.coverage["dependency-reality"]["ignores"]
    )
