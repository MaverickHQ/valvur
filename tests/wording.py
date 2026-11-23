"""The one rule of wording about a list (ADR-0037): *mapped to*.

`claims(text)` gives each sentence that names a list beside a word of coverage, compliance
or certification. A word set in emphasis or in code is a mention of the word, which is how
a document states the rule, and is not a claim.
"""

from __future__ import annotations

import re

#: A list, or one of its identifiers.
LIST = re.compile(r"OWASP|\bCWE\b|CWE-\d+|\bTop 10\b|\bLLM\d\d\b|\bASI\d\d\b|\bA\d\d:20\d\d\b")
CLAIM = re.compile(r"\bcover(s|ed|age|ing)?\b|\bcompl(y|ies|ied|iant|iance)\b|\bcertif\w+",
                   re.I)
_MENTION = re.compile(r"\*[^*\n]+\*|`[^`\n]+`")
#: valvur's own word for what it could not inspect (CONTEXT.md), which is not a claim.
_OWN = re.compile(r"\bcoverage (note|gap)s?\b|\bCoverage\b(?= \()", re.I)


def claims(text: str) -> list[str]:
    found = []
    for paragraph in re.split(r"\n\s*\n|\n(?=\s*[-|#])|\\n", text):
        for sentence in re.split(r"(?<=[.!?])\s+", " ".join(paragraph.split())):
            said = _OWN.sub("", _MENTION.sub("", sentence))
            if LIST.search(said) and CLAIM.search(said):
                found.append(sentence)
    return found
