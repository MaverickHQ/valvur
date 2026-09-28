"""Text shortened for a bounded surface, never mid-word (R5.2)."""

from __future__ import annotations


def cut(text: str, limit: int) -> str:
    """At most `limit` characters, ending on a whole word, and `…` when cut: the
    second gate read *… exclud (609.1s)*, a word halved and run into the duration;
    the review's lab report cut titles the same way."""
    if len(text) <= limit:
        return text
    head = text[:limit]
    space = head.rfind(" ")
    return (head[:space] if space > limit // 2 else head).rstrip(" ,;:") + "…"
