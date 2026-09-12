"""ADR-0018 — the package-name index: exact, from primary sources, in the host cache.

Two halves. The reader runs in the container and must be right about the first
line, the last line, a prefix of a real name and an empty file — bisection over byte
offsets is exactly the code that passes on `requests` and fails at the edges. The
builder runs on the host and must refuse to write anything that would report real
packages as hallucinated.
"""

from __future__ import annotations

import gzip
import io
import json
import urllib.request
from pathlib import Path

import pytest
from conftest import write_name_index

from valvur import cache, name_index
from valvur.name_index import NameIndex


def _write(path: Path, names: list[str], *, trailing_newline: bool = True) -> Path:
    body = "\n".join(sorted(names)) + ("\n" if trailing_newline else "")
    path.write_bytes(body.encode())
    return path


# ------------------------------------------------------------------ the reader

@pytest.mark.parametrize("name", ["aaa", "mmm", "zzz", "requests", "a", "z-last"])
def test_every_name_in_the_file_is_found(tmp_path, name):
    names = ["a", "aaa", "mmm", "requests", "z-last", "zzz"]
    with NameIndex(_write(tmp_path / "i.txt", names)) as index:
        assert index.contains(name)


@pytest.mark.parametrize("name", [
    "", "0", "aa", "aaaa", "request", "requestsx", "reqeusts", "zzzz", "z", "~",
])
def test_a_name_not_in_the_file_is_not_found(tmp_path, name):
    """Neighbours on every side: shorter, longer, a prefix, one past the end, before
    the first line. A bisection that lands on a partial line would say yes to some."""
    names = ["a", "aaa", "mmm", "requests", "z-last", "zzz"]
    with NameIndex(_write(tmp_path / "i.txt", names)) as index:
        assert not index.contains(name)


def test_the_last_line_is_found_without_a_trailing_newline(tmp_path):
    with NameIndex(_write(tmp_path / "i.txt", ["a", "b", "zzz"], trailing_newline=False)) as index:
        assert index.contains("zzz") and index.contains("a")
        assert not index.contains("zz") and not index.contains("zzzz")


def test_an_empty_index_contains_nothing_and_does_not_crash(tmp_path):
    """mmap refuses a zero-length file. An empty list is a valid index of nothing."""
    with NameIndex(_write(tmp_path / "i.txt", [])) as index:
        assert not index.contains("anything")


def test_a_single_line_index(tmp_path):
    with NameIndex(_write(tmp_path / "i.txt", ["only"])) as index:
        assert index.contains("only")
        assert not index.contains("onl") and not index.contains("onlyx")


def test_the_real_file_format_round_trips_through_the_reader(tmp_path):
    """Written by the builder's writer, read by the reader: the two halves agree on
    the bytes. Scoped npm names and PEP 503 forms included."""
    names = {"@types/node", "@scope/pkg", "zope-interface", "requests", "0", "a-b-c"}
    name_index._write_names(tmp_path / "npm.txt", names)

    with NameIndex(tmp_path / "npm.txt") as index:
        for name in names:
            assert index.contains(name), name
        assert not index.contains("@types/nope")


def test_membership_agrees_with_a_set_on_a_thousand_random_probes(tmp_path):
    """Property check against the obvious implementation. If bisection ever
    disagrees with `in set`, this finds the case the hand-picked ones missed."""
    import random

    rng = random.Random(1804)  # noqa: S311 — a seeded property check, not a secret
    alphabet = "abc-_.09"
    names = {"".join(rng.choices(alphabet, k=rng.randint(1, 6))) for _ in range(400)}
    name_index._write_names(tmp_path / "i.txt", names)

    with NameIndex(tmp_path / "i.txt") as index:
        for _ in range(1000):
            probe = "".join(rng.choices(alphabet, k=rng.randint(1, 6)))
            assert index.contains(probe) == (probe in names), probe


def test_open_index_returns_none_for_an_unfetched_or_unknown_ecosystem(tmp_path):
    assert name_index.open_index(tmp_path, "pip") is None
    assert name_index.open_index(tmp_path, "cargo") is None
    (tmp_path / "pypi.txt").write_text("a\n")
    index = name_index.open_index(tmp_path, "pip")
    assert index is not None
    index.close()


# ----------------------------------------------------------------- the builder

class _FakeHTTP:
    """Serves canned bodies by URL prefix, gzip-encoded when the request asks for it,
    and records every URL — the builder's whole contract with the network."""

    def __init__(self, routes: dict[str, object]):
        self.routes = routes
        self.urls: list[str] = []

    def __call__(self, request, timeout=None):
        url = request.full_url
        self.urls.append(url)
        # Longest prefix wins: the replicate root `/` is a prefix of every other
        # replicate URL.
        for prefix, body in sorted(self.routes.items(), key=lambda kv: -len(kv[0])):
            if url.startswith(prefix):
                payload = body(url) if callable(body) else body
                if isinstance(payload, Exception):
                    raise payload
                raw = json.dumps(payload).encode()
                headers = {"Content-Encoding": "gzip"}
                return _Response(gzip.compress(raw), headers)
        raise urllib.error.HTTPError(url, 404, "not found", {}, None)


class _Response(io.BytesIO):
    def __init__(self, body: bytes, headers: dict):
        super().__init__(body)
        self.headers = headers
        self.status = 200

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


@pytest.fixture
def http(monkeypatch):
    fake = _FakeHTTP({})
    monkeypatch.setattr(urllib.request, "urlopen", fake)
    monkeypatch.setattr(name_index.time, "sleep", lambda _: None)
    return fake


def _pypi(names):
    return {"meta": {"api-version": "1.4"}, "projects": [{"name": n} for n in names]}


def _npm_all_docs(names):
    ordered = sorted(names)

    def page(url):
        from urllib.parse import parse_qs, urlparse

        query = parse_qs(urlparse(url).query)
        start = json.loads(query["start_key"][0]) if "start_key" in query else None
        rows = [n for n in ordered if start is None or n >= start][: name_index.PAGE]
        return {"total_rows": len(ordered), "rows": [{"id": n, "key": n} for n in rows]}

    return page


def test_pypi_names_are_stored_in_pep_503_form(http, monkeypatch):
    monkeypatch.setattr(name_index, "MINIMUM_NAMES", {"pip": 1, "npm": 1})
    http.routes[name_index.PYPI_SIMPLE] = _pypi(["Zope.Interface", "requests", "Django_Rest"])

    names = name_index.fetch_pypi()

    assert names == {"zope-interface", "requests", "django-rest"}
    assert http.urls == [name_index.PYPI_SIMPLE]


def test_a_full_npm_walk_pages_by_start_key_and_drops_the_repeated_boundary(http, monkeypatch):
    """The server caps pages at 10,000 and `start_key` is inclusive, so every page
    after the first begins with the previous page's last key. Counting it twice is
    harmless; missing the first row of a page is not — and the sequence number must
    be read BEFORE the walk so the next refresh replays anything that changed."""
    monkeypatch.setattr(name_index, "PAGE", 4)
    everything = [f"pkg-{i:02d}" for i in range(10)] + ["@scope/x", "_design/app", "UPPER"]
    http.routes[name_index.NPM_REPLICATE + "/_all_docs"] = _npm_all_docs(everything)
    http.routes[name_index.NPM_REPLICATE + "/"] = {"update_seq": 777, "doc_count": 13}

    names, seq = name_index.fetch_npm_full()

    assert names == {f"pkg-{i:02d}" for i in range(10)} | {"@scope/x", "upper"}
    assert seq == 777
    assert http.urls[0] == name_index.NPM_REPLICATE + "/", "sequence read after the walk"
    assert all("skip=" not in u for u in http.urls), "the server refuses `skip`"


def test_the_change_feed_adds_republished_names_and_removes_deleted_ones(http, monkeypatch):
    http.routes[name_index.NPM_REPLICATE + "/_changes"] = {
        "results": [
            {"seq": 1, "id": "brand-new", "changes": [{"rev": "1-a"}]},
            {"seq": 2, "id": "Old-Spam", "changes": [{"rev": "3-b"}], "deleted": True},
            {"seq": 3, "id": "existing", "changes": [{"rev": "9-c"}]},
            {"seq": 4, "id": "_design/x", "changes": [{"rev": "1-d"}]},
        ],
        "last_seq": 4,
    }

    names, last = name_index.fetch_npm_changes({"existing", "old-spam", "keep"}, since=0)

    assert names == {"existing", "keep", "brand-new"}
    assert last == 4
    assert "since=0" in http.urls[0]


def test_refresh_is_incremental_once_an_index_exists_and_full_before(http, monkeypatch, tmp_path):
    monkeypatch.setattr(name_index, "MINIMUM_NAMES", {"pip": 1, "npm": 1})
    http.routes[name_index.PYPI_SIMPLE] = _pypi(["requests"])
    http.routes[name_index.NPM_REPLICATE + "/_all_docs"] = _npm_all_docs(["a", "b"])
    http.routes[name_index.NPM_REPLICATE + "/"] = {"update_seq": 10}
    http.routes[name_index.NPM_REPLICATE + "/_changes"] = {
        "results": [{"seq": 11, "id": "c", "changes": [{"rev": "1-x"}]}], "last_seq": 11,
    }

    first = name_index.refresh(tmp_path)
    assert first["ecosystems"]["npm"]["update_seq"] == 10
    assert (tmp_path / "npm.txt").read_text() == "a\nb\n"
    assert any("_all_docs" in u for u in http.urls) and not any("_changes" in u for u in http.urls)

    http.urls.clear()
    second = name_index.refresh(tmp_path)
    assert second["ecosystems"]["npm"]["update_seq"] == 11
    assert (tmp_path / "npm.txt").read_text() == "a\nb\nc\n"
    assert any("_changes" in u for u in http.urls) and not any("_all_docs" in u for u in http.urls)


def test_an_index_older_than_the_repull_threshold_is_walked_in_full(http, monkeypatch, tmp_path):
    monkeypatch.setattr(name_index, "MINIMUM_NAMES", {"pip": 1, "npm": 1})
    http.routes[name_index.PYPI_SIMPLE] = _pypi(["requests"])
    http.routes[name_index.NPM_REPLICATE + "/_all_docs"] = _npm_all_docs(["fresh"])
    http.routes[name_index.NPM_REPLICATE + "/"] = {"update_seq": 99}
    write_name_index(tmp_path, pip=["requests"], npm=["stale"], built_at="2020-01-01T00:00:00Z")
    (tmp_path / "metadata.json").write_text(json.dumps({"schema": 1, "ecosystems": {
        "pip": {"built_at": "2020-01-01T00:00:00Z"},
        "npm": {"built_at": "2020-01-01T00:00:00Z", "update_seq": 1},
    }}))

    name_index.refresh(tmp_path)

    assert (tmp_path / "npm.txt").read_text() == "fresh\n"
    assert not any("_changes" in u for u in http.urls)


def test_a_truncated_registry_response_is_refused_and_the_old_index_kept(http, tmp_path):
    """A list of 200 names is not PyPI. Writing it would report every real package as
    hallucinated — the worst finding this product can emit, at scale."""
    http.routes[name_index.PYPI_SIMPLE] = _pypi([f"p{i}" for i in range(200)])
    (tmp_path / "pypi.txt").write_text("previous\n")

    with pytest.raises(name_index.IndexUnavailable, match="truncated"):
        name_index.refresh(tmp_path, ecosystems=("pip",))

    assert (tmp_path / "pypi.txt").read_text() == "previous\n"
    assert not (tmp_path / "metadata.json").exists()


def test_a_network_failure_leaves_the_previous_index_untouched(http, tmp_path):
    http.routes[name_index.PYPI_SIMPLE] = urllib.error.URLError("no route to host")
    (tmp_path / "pypi.txt").write_text("previous\n")

    with pytest.raises(name_index.IndexUnavailable):
        name_index.refresh(tmp_path, ecosystems=("pip",))

    assert (tmp_path / "pypi.txt").read_text() == "previous\n"


def test_a_non_https_source_is_refused():
    with pytest.raises(name_index.IndexUnavailable, match="https"):
        name_index._get("http://pypi.org/simple/")


def test_the_writer_produces_bytewise_sorted_lines_the_reader_bisects(tmp_path):
    """Sorted as BYTES, not as Python strings under a locale: `@types/x` before
    `a`, `Z` before `a`, and the reader's comparison is on bytes too."""
    name_index._write_names(tmp_path / "i.txt", {"b", "@types/x", "a", "z", "0"})

    lines = (tmp_path / "i.txt").read_bytes().split(b"\n")[:-1]
    assert lines == sorted(lines)
    assert lines[0] == b"0" and lines[1] == b"@types/x"


# ------------------------------------------------------------- age and staleness

def test_the_index_age_is_the_oldest_ecosystem(tmp_path, monkeypatch):
    """One verdict, so the age that counts is the one that would mislead: a fresh
    PyPI list beside an old npm list is an old answer for a `package.json`."""
    monkeypatch.setattr(cache, "name_index", lambda: tmp_path)
    (tmp_path / "metadata.json").write_text(json.dumps({"schema": 1, "ecosystems": {
        "pip": {"built_at": name_index._now()},
        "npm": {"built_at": "2020-01-01T00:00:00Z"},
    }}))

    age = cache.name_index_age_days()

    assert age is not None and age > 365


@pytest.mark.parametrize("body", [
    "", "{not json", '{"ecosystems": []}', '{"ecosystems": {}}',
    '{"ecosystems": {"pip": {"built_at": "yesterday"}}}',
    '{"ecosystems": {"pip": {"built_at": "2026-01-01T00:00:00Z"}, "npm": {}}}',
])
def test_an_unreadable_metadata_file_is_not_a_fresh_index(tmp_path, monkeypatch, body):
    """Unreadable is not zero. A confident "0 days old" from a corrupt file is the
    failure the whole staleness model exists to remove (F6.11)."""
    monkeypatch.setattr(cache, "name_index", lambda: tmp_path)
    (tmp_path / "metadata.json").write_text(body)

    assert cache.name_index_age_days() is None


def test_no_index_has_no_age(tmp_path, monkeypatch):
    monkeypatch.setattr(cache, "name_index", lambda: tmp_path / "nothing")
    assert cache.name_index_age_days() is None
    assert not cache.name_index_present()
