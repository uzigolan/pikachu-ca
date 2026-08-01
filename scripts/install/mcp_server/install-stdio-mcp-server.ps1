<#
Prepare pki-mcp for stdio clients (VS Code Copilot, Claude Desktop).

  .\install-stdio-mcp-server.ps1                  # interactive (prompts for PKI credentials)
  .\install-stdio-mcp-server.ps1 -Reconfigure     # force re-prompt even if credentials exist

Ensures the project venv exists and pki_mcp dependencies are installed.
Saves PKI credentials to .mcp-stdio.env (reused by client installers and on subsequent runs).
Does NOT start the server -- stdio clients (VS Code, Claude Desktop) launch it themselves.
#>
param([switch]$Reconfigure)

. (Join-Path $PSScriptRoot '..\_common.ps1')
Assert-Venv

# -- keep existing credentials? -----------------------------------------------
if (-not $Reconfigure -and (Test-KeepStdioConfig)) {
    Write-Host ""
    Write-Host "Done. Existing stdio credentials kept."
    Write-Host "Now run: scripts\install\skills_and_mcp\install-copilot-vscode.ps1"
    exit 0
}

# -- collect PKI credentials --------------------------------------------------
Write-Host ""
Write-Host "=== PKI server connection (for stdio MCP) ==="
$creds = Prompt-PkiCredentials

# Save to .mcp-stdio.env
$cfg = [ordered]@{
    PKI_BASE_URL   = $creds.BaseUrl
    PKI_TOKEN      = $creds.Token
    PKI_VERIFY_SSL = 'false'
}
Write-EnvFile $script:StdioEnvFile $cfg

# -- smoke-test import --------------------------------------------------------
$eap = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
$out = & $script:VenvPython -c "from pki_mcp.server import build_server; print('OK')" 2>&1
$ErrorActionPreference = $eap

if ($LASTEXITCODE -ne 0 -or "$out" -notmatch 'OK') {
    Write-Host "  WARNING: pki_mcp import check failed:"
    Write-Host "  $out"
    Write-Host "  Run: pip install -r pki_mcp\requirements.txt inside the venv."
} else {
    Write-Host "  import check -> OK"
}

Write-Host ""
Write-Host "Done. The venv is ready for stdio MCP usage."
Write-Host "Now run: scripts\install\skills_and_mcp\install-copilot-vscode.ps1"
