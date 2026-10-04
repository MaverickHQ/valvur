# Listing valvur

The text each directory asks for, for the owner to paste when submitting (`tasks.md`
§8). Every field is drawn from the manifests it names, and
`tests/test_listing.py` holds the two equal, so a change to a manifest that this page
does not follow fails there. Nothing here is submitted by the build.

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
