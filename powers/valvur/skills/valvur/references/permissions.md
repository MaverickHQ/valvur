# Allowing valvur's tools

A permission mode that refuses every tool not on an allow list, such as Claude Code's
*don't ask*, refuses valvur's too, and the scan never runs. These are the rules to
allow them. **Give them to the human; never write them yourself.** A rule in a
project's settings grants every contributor's agent, so where it goes is theirs to
decide: their own `~/.claude/settings.json`, or the project's
`.claude/settings.local.json`, which is not committed.

The read-only tools, and `scan`, which writes only `.security-scan/` and fetches only
public data, and `scan_cancel`:

```json
{
  "permissions": {
    "allow": [
      "mcp__plugin_valvur_valvur__check_package",
      "mcp__plugin_valvur_valvur__findings",
      "mcp__plugin_valvur_valvur__scan_status",
      "mcp__plugin_valvur_valvur__doctor",
      "mcp__plugin_valvur_valvur__scan",
      "mcp__plugin_valvur_valvur__scan_cancel"
    ]
  }
}
```

Those names are the plugin's. When the server is configured by hand under the name
`valvur`, in `.mcp.json` or by `valvur init`, the same tools are named
`mcp__valvur__check_package`, `mcp__valvur__findings`, `mcp__valvur__scan_status`,
`mcp__valvur__doctor`, `mcp__valvur__scan` and `mcp__valvur__scan_cancel`.

`update` is left to ask: it fetches the image and the data into this machine's cache,
which the human should see happen.
