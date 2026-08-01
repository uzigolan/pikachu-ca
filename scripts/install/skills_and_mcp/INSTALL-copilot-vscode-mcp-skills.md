# GitHub Copilot VS Code — install pki-mcp (MCP + skill)

One script wires both artifacts: the `pki-mcp` MCP server entry and the
`rad-pki-operations` skill into Copilot for VS Code.

## Prerequisites

- VS Code with GitHub Copilot + Copilot Chat extensions (latest)
- Python 3.10+ (the installer bootstraps the project venv automatically)
- A PKI API token — create one in the PKI UI: **Account → API Tokens**

## Run

```powershell
cd <PKI project root>
PowerShell -ExecutionPolicy Bypass -File scripts\install\skills_and_mcp\install-copilot-vscode.ps1
```

The script prompts for:
1. **Transport** — `stdio` (default; VS Code launches the server locally) or `HTTP` (URL + token for a shared server)
2. **PKI server URL** — e.g. `https://localhost:443`
3. **PKI_TOKEN** — the API token

## What it writes

| Artifact | Location |
|---|---|
| MCP server entry `pki-mcp` | `%APPDATA%\Code\User\mcp.json` → `servers` |
| Skill | `~\.copilot\skills\rad-pki-operations\SKILL.md` |

## After install

1. Reload the VS Code window (`Ctrl+Shift+P` → *Developer: Reload Window*)
2. Accept the MCP trust dialog for `pki-mcp`
3. Switch Copilot Chat to **AGENT** mode
4. Try: *"show me the PKI dashboard stats"*

## Non-interactive (HTTP mode)

```powershell
.\install-copilot-vscode.ps1 -HTTP -Url http://my-server:8080/HTTP -Token <token>
```

## Re-configure

```powershell
.\install-copilot-vscode.ps1 -Reconfigure
```
