# Claude Desktop — install pki-mcp (MCP + skill)

## Run

```powershell
cd <PKI project root>
PowerShell -ExecutionPolicy Bypass -File scripts\install\skills_and_mcp\install-claude-desktop.ps1
```

## What it writes

| Artifact | Location |
|---|---|
| MCP server entry `pki-mcp` | `%APPDATA%\Claude\claude_desktop_config.json` → `mcpServers` |
| Skill zip for upload | `build\claude-skills\rad-pki-operations.zip` |

The script opens `build\claude-skills\` automatically after writing the config.

## After install

1. Restart Claude Desktop
2. Upload the skill zip: **Claude Desktop → Customize → Skills → upload `rad-pki-operations.zip`**
3. Try: *"show me the PKI dashboard stats"*
