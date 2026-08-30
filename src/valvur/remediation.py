"""REMEDIATION.md — a ranked proposal, never an execution script (ADR-0009).

A **Remediation Item** is one *action*, not one **Finding** (F7.14). Four CVEs in
`loader-utils@1.4.0` are one change — "upgrade webpack" — and emitting four items
would be exactly the noise Phase 5 removed.

The developer chooses which of these to apply and when to rescan. Each item is
therefore independently applicable, because they will cherry-pick.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .findings import Finding


@dataclass
class Item:
    action: str
    where: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def rank(self) -> int:
        return min((f.rank or 10**9) for f in self.findings)

    @property
    def exploited(self) -> bool:
        return any(f.exploit and f.exploit.kev for f in self.findings)


def group(findings: list[Finding]) -> list[Item]:
    """Collapse Findings into the changes that resolve them."""
    items: dict[tuple[str, str], Item] = {}
    for finding in findings:
        key, action, where = _key(finding)
        item = items.setdefault((key, where), Item(action=action, where=where))
        item.findings.append(finding)
    return sorted(items.values(), key=lambda i: i.rank)


def _key(finding: Finding) -> tuple[str, str, str]:
    """The change that fixes this, and where it is made."""
    dependency = finding.dependency
    if dependency and dependency.package:
        # Group by the package the developer can actually change — the Dependency
        # Path root where there is one (5.4). "Upgrade json5" is useless when
        # something else pins it.
        root = dependency.path[0] if len(dependency.path) > 1 else ""
        target = root.split("@")[0] if root else dependency.package
        fix = dependency.fixed_version
        action = (
            f"Upgrade `{target}`" + (f" so `{dependency.package}` reaches {fix}"
                                     if root and fix else f" to {fix}" if fix else "")
        ) if fix or root else f"Replace or remove `{dependency.package}` — no fix available"
        return (f"dep:{target}", action, finding.path)

    if finding.rule.startswith("valvur.dependency."):
        return ("slopsquat:" + finding.path, "Remove the hallucinated dependencies", finding.path)
    if finding.rule.startswith("valvur.ai-artifact."):
        return ("agent:" + finding.path, f"Review the agent instruction file `{finding.path}`", finding.path)
    if finding.rule.startswith("valvur.licence."):
        return ("licence", "Resolve licensing", finding.path)
    if finding.rule in {"aws-access-token", "generic-api-key"} or "secret" in finding.rule:
        return ("secret:" + finding.path, f"Rotate the credentials in `{finding.path}`", finding.path)
    return (f"code:{finding.path}", f"Fix the issues in `{finding.path}`", finding.path)


def render(findings: list[Finding], *, top: int = 25) -> str:
    items = group(findings)
    lines = [
        "# Remediation proposal",
        "",
        "> **This is a proposal, not a script.** Each item below is independently",
        "> applicable — apply the ones you judge worth applying, in any order, then",
        "> rescan. valvur never changes your code (ADR-0009).",
        "",
        "> A finding disappearing is **not** proof it was fixed. Deleting code and",
        "> correctly fixing it look identical from here.",
        "",
    ]
    if not items:
        lines += ["No findings. Nothing to remediate.", ""]
        return "\n".join(lines)

    lines.append(f"**{len(items)} action(s)** resolve **{len(findings)} finding(s)**.")
    lines.append("")

    for number, item in enumerate(items[:top], start=1):
        flag = " **[known exploited]**" if item.exploited else ""
        lines.append(f"## {number}. {item.action}{flag}")
        lines.append("")
        lines.append(f"Resolves {len(item.findings)} finding(s) in `{item.where}`:")
        lines.append("")
        for finding in sorted(item.findings, key=lambda f: f.rank or 10**9)[:8]:
            lines.append(f"- {finding.rule} — {finding.title[:100]}")
        if len(item.findings) > 8:
            lines.append(f"- _…and {len(item.findings) - 8} more_")
        lines.append("")

    if len(items) > top:
        lines.append(f"_{len(items) - top} further action(s) in `findings.json`._")
        lines.append("")
    return "\n".join(lines)
