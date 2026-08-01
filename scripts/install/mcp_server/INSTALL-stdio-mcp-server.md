# pki-mcp stdio preparation

Bootstraps the project venv so stdio MCP clients (VS Code Copilot, Claude Desktop)
can launch the server locally. Run this once before the client installer.

## Run

```powershell
cd <PKI project root>
PowerShell -ExecutionPolicy Bypass -File scripts\install\mcp_server\install-stdio-mcp-server.ps1
```

Then wire the MCP entry into your IDE:

```powershell
PowerShell -ExecutionPolicy Bypass -File scripts\install\skills_and_mcp\install-copilot-vscode.ps1
# or
PowerShell -ExecutionPolicy Bypass -File scripts\install\skills_and_mcp\install-claude-desktop.ps1
```
