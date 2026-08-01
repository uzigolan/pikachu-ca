<#
Install pki-mcp (MCP entry + skill) for Claude Desktop.

  .\install-claude-desktop.ps1
  .\install-claude-desktop.ps1 -Reconfigure   # replace existing entry

Walks you through two sections:
  Section 1 -- Pikachu CA server  (Flask PKI URL + API token)
  Section 2 -- PKI MCP server     (stdio only -- Claude Desktop launches it locally)

Backs up the Claude Desktop config, merges the pki-mcp stdio entry,
builds the skill zip, and opens the zip folder for manual upload.
#>
param(
    [string]$Name = 'pki-mcp',
    [switch]$Reconfigure
)
. (Join-Path $PSScriptRoot '..\_common.ps1')

# Detect config path: Windows Store package first, then traditional
$cfgPath = "$env:LOCALAPPDATA\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\Claude\claude_desktop_config.json"
if (-not (Test-Path (Split-Path $cfgPath))) {
    $cfgPath = "$env:APPDATA\Claude\claude_desktop_config.json"
}
New-Item -ItemType Directory -Force (Split-Path $cfgPath) | Out-Null
Backup-JsonConfig -Path $cfgPath

# -- keep existing? ----------------------------------------------------------
if ((-not $Reconfigure) -and (Test-KeepExisting -Path $cfgPath -RootKey 'mcpServers' -Name $Name)) {
    Write-Host "  mcp   -> kept existing $Name entry in $cfgPath"
} else {
    # ── Section 1 : Pikachu CA server ────────────────────────────────────────
    $ca = Invoke-Section1-Stdio     # prompts for / loads PKI URL + token

    # ── Section 2 : PKI MCP server ───────────────────────────────────────────
    Show-Section2-Stdio
    Assert-Venv
    Show-PkiServerStatus -Mode 'stdio' -BaseUrl $ca.BaseUrl

    $entry = New-StdioEntry -BaseUrl $ca.BaseUrl -Token $ca.Token
    Set-JsonMcpEntry -Path $cfgPath -RootKey 'mcpServers' -Entry $entry -Name $Name
}

# -- build skill zip for manual upload ---------------------------------------
$zipDir = Join-Path $script:PkiRoot 'build\claude-skills'
New-Item -ItemType Directory -Force $zipDir | Out-Null
foreach ($s in $script:SkillNames) {
    $src = Join-Path $script:SkillsSrc $s
    $zip = Join-Path $zipDir "$s.zip"
    if (Test-Path $src) {
        Compress-Archive -Path (Join-Path $src '*') -DestinationPath $zip -Force
        Write-Host "  skill -> $zip"
    }
}

Write-Host ""
Write-Host "Done. Now:"
Write-Host "  1. Restart Claude Desktop"
Write-Host "  2. Upload the skill zip: Customize -> Skills -> upload rad-pki-operations.zip"
Write-Host "     (zip location: $zipDir)"
Write-Host "  3. Try: 'show me the PKI dashboard stats'"

Start-Process explorer.exe $zipDir
