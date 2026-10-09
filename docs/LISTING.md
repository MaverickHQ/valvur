# Listing valvur

The text each directory asks for, for the owner to paste when submitting (`tasks.md`
§8), and the repository's own GitHub page. Every field is drawn from the manifests it names, and
`tests/test_listing.py` holds the two equal, so a change to a manifest that this page
does not follow fails there. Nothing here is submitted by the build.

## The GitHub page

The repository's About box, applied with the owner's yes on 2026-10-09 (R39.4), and read
back by `gh api repos/MaverickHQ/valvur`. `tests/test_github_page.py` holds GitHub's
limits. The website is the PyPI page until there is a documentation site.

- **Description:** Offline security scanner for AI-generated code: secrets, vulnerable and hallucinated dependencies, poisoned agent configuration, infrastructure and code flaws, from seven open-source scanners in one sealed container. An MCP server for Claude Code, Kiro and other agents, and a CLI. Your source never leaves your machine.
- **Website:** https://pypi.org/project/valvur/
- **Topics:** `security`, `security-scanner`, `sast`, `static-analysis`, `secrets-detection`, `vulnerability-scanner`, `supply-chain-security`, `sbom`, `devsecops`, `offline`, `mcp`, `mcp-server`, `claude-code`, `kiro`, `ai-security`, `llm-security`, `ai-generated-code`, `slopsquatting`, `agentic-ai`, `python`
- **Discussions:** on, with GitHub's default categories.
- **Social preview:** `docs/social-preview.png`, uploaded by the owner (GitHub's API cannot set it).

## Anthropic's plugin directory: the Claude Code plugin

From [`plugins/valvur/.claude-plugin/plugin.json`](../plugins/valvur/.claude-plugin/plugin.json)
and the marketplace, [`.claude-plugin/marketplace.json`](../.claude-plugin/marketplace.json).

- **Name:** valvur
- **Description:** Scan a project for security problems locally and offline, check a package before installing it, and work through the findings with the human. The skill that runs the workflow, and valvur's MCP server.
- **Keywords:** security, scanner, offline, mcp, sast, secrets, dependencies
- **Repository:** https://github.com/MaverickHQ/valvur
- **Licence:** Apache-2.0
- **Author:** MaverickHQ, https://github.com/MaverickHQ
- **Install:** `/plugin marketplace add MaverickHQ/valvur`, then `/plugin install valvur@valvur`
- **Privacy:** valvur collects nothing. [README, Privacy](../README.md#privacy)
- **Support:** https://github.com/MaverickHQ/valvur/issues

## Kiro's catalog: the power

From [`powers/valvur/plugin.json`](../powers/valvur/plugin.json) and
[`powers/valvur/mcp.json`](../powers/valvur/mcp.json).

- **Name:** valvur
- **Description:** Scan a project for security problems locally and offline, check a package before installing it, and work through the findings with the human. The skill that runs the workflow, and valvur's MCP server.
- **Keywords:** security, scan, vulnerabilities, secrets, dependencies, supply chain, offline, valvur
- **Repository:** https://github.com/MaverickHQ/valvur
- **Licence:** Apache-2.0
- **Author:** MaverickHQ, https://github.com/MaverickHQ
- **Install:** *Add Custom Power*, *Import power from GitHub*, `https://github.com/MaverickHQ/valvur/tree/main/powers/valvur`
- **Privacy:** valvur collects nothing. [README, Privacy](../README.md#privacy)
- **Support:** https://github.com/MaverickHQ/valvur/issues

## What both directories are told

valvur runs on the developer's machine. Its Scanners run in one container with no
network interface; the host fetches only public data (the image, the vulnerability
database, the package-name index, KEV, EPSS and OSV's databases) and records each
fetch in `run.json`. No account, no API key, no telemetry. The plugin and the power
add the skill and the MCP server; the plugin also adds a hook that asks before an
install of a package valvur flags, and nothing else.
