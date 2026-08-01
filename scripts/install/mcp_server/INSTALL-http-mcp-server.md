# pki-mcp HTTP server — start for shared/remote access

Starts the pki-mcp MCP server in HTTP/SSE mode so multiple clients can share one running instance.

## Run

```powershell
cd <PKI project root>
$env:PKI_BASE_URL = "https://localhost:443"
$env:PKI_TOKEN    = "<your-api-token>"
PowerShell -ExecutionPolicy Bypass -File scripts\install\mcp_server\install-HTTP-mcp-server.ps1
# Custom port:
PowerShell -ExecutionPolicy Bypass -File scripts\install\mcp_server\install-HTTP-mcp-server.ps1 -Port 9090
```

## Client config

Point any MCP client at `http://<host>:<port>/HTTP` with `Authorization: Bearer <PKI_TOKEN>`.

VS Code `mcp.json` example:
```json
{
  "servers": {
    "pki-mcp": {
      "type": "http",
      "url": "http://localhost:8080/mcp",
      "headers": { "Authorization": "Bearer <PKI_TOKEN>" }
    }
  }
}
```


