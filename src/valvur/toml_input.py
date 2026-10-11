"""TOML read so that no input raises past a parse error.

`tomllib` recurses once or twice for each nested array or inline table, so about a
thousand levels, two kilobytes, raise `RecursionError` on Python 3.11 to 3.13. Every
reader here caught `TOMLDecodeError`, and a scanned repository's `.security-scan.toml`
of nested brackets ended the scan (ClusterFuzzLite, PR #224). Nested too deep is a
file that does not parse.
"""

from __future__ import annotations


def loads(text: str) -> dict:
    """`tomllib.loads`, with nesting past the interpreter's limit a `TOMLDecodeError`,
    which every caller already answers."""
    import tomllib  # stdlib, loaded when a file is first read, as each reader did

    try:
        return tomllib.loads(text)
    except RecursionError:
        raise tomllib.TOMLDecodeError("nested too deeply to read") from None
