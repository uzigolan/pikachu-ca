# Shared helpers for pki-mcp install scripts. Dot-source, don't run directly.
# PowerShell 5.1 compatible. Saved with UTF-8 BOM -- do not resave without BOM.

$ErrorActionPreference = 'Stop'

# Repo layout: this file lives at scripts/install/
$script:PkiRoot        = (Resolve-Path (Join-Path $PSScriptRoot '..\..') -ErrorAction Stop).Path
# Dedicated MCP-server venv -- isolated from the CA server's main .venv.
# Lives inside pki_mcp\ so the MCP server is fully self-contained.
$script:McpVenvDir     = Join-Path $script:PkiRoot 'pki_mcp\.venv'
$script:VenvPython     = Join-Path $script:McpVenvDir 'Scripts\python.exe'
$script:SkillsSrc      = Join-Path $script:PkiRoot 'skills'
$script:SkillNames     = @('rad-pki-operations')
$script:HttpEnvFile    = Join-Path $script:PkiRoot '.mcp-http.env'
$script:StdioEnvFile   = Join-Path $script:PkiRoot '.mcp-stdio.env'
$script:McpModule  = 'pki_mcp.server'

# ---------------------------------------------------------------------------
# Python / venv bootstrap
# ---------------------------------------------------------------------------

function Get-BestPython {
    $probe = "import sys; sys.stdout.write('PKIPY'); raise SystemExit(0 if sys.version_info[:2] >= (3,10) else 1)"
    foreach ($c in @('python3.13','python3.12','python3.11','python3.10','python','python3')) {
        $cmd = Get-Command $c -ErrorAction SilentlyContinue
        if (-not $cmd) { continue }
        try {
            $out = & $c -c $probe 2>$null
            if ($LASTEXITCODE -eq 0 -and "$out" -match 'PKIPY') { return $c }
        } catch { }
    }
    $pyLauncher = Get-Command py -ErrorAction SilentlyContinue
    if ($pyLauncher) {
        foreach ($sel in @('-3.13','-3.12','-3.11','-3.10','-3')) {
            try {
                $out = & py $sel -c $probe 2>$null
                if ($LASTEXITCODE -ne 0 -or "$out" -notmatch 'PKIPY') { continue }
                $exeOut = & py $sel -c 'import sys; print(sys.executable)' 2>$null
                if ($LASTEXITCODE -eq 0 -and $exeOut) {
                    $exe = ($exeOut -split "`r?`n" | Select-Object -First 1).Trim()
                    if ($exe -and (Test-Path $exe)) { return $exe }
                }
            } catch { }
        }
    }
    return $null
}

function Install-PortablePython {
    # Self-contained fallback when the machine has no Python >= 3.10:
    # download the official CPython NuGet package and unzip it inside the repo
    # (pki_mcp\.python). Nothing is installed system-wide — no PATH, no registry,
    # no admin required. Deleting the repo folder removes it completely.
    $dest = Join-Path $script:PkiRoot 'pki_mcp\.python'
    $exe  = Join-Path $dest 'tools\python.exe'
    if (Test-Path $exe) { return $exe }
    Write-Host "No Python >= 3.10 found — downloading portable CPython into pki_mcp\.python"
    Write-Host "(one-time, ~30 MB, repo-local only; nothing installed on Windows) ..."
    $zip = Join-Path $env:TEMP "pki-portable-python-$PID.zip"
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri 'https://www.nuget.org/api/v2/package/python/3.12.10' `
            -OutFile $zip -UseBasicParsing
        Expand-Archive -Path $zip -DestinationPath $dest -Force
    } catch {
        Write-Host "  portable python download failed: $($_.Exception.Message)"
        return $null
    } finally {
        Remove-Item $zip -ErrorAction SilentlyContinue
    }
    if (Test-Path $exe) {
        Write-Host "  portable python -> $exe"
        return $exe
    }
    return $null
}

function Assert-Venv {
    # Verify the venv is healthy (pki_mcp importable). If half-built from a
    # prior aborted run, delete and rebuild clean (same pattern as rad-agent-toolkit).
    if (Test-Path $script:VenvPython) {
        $eap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
        try { & $script:VenvPython -c "import pki_mcp" 2>$null } finally { $ErrorActionPreference = $eap }
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  venv/deps -> ready ($script:VenvPython)"
            return
        }
        Write-Host "MCP venv is incomplete (a prior setup did not finish) - rebuilding clean ..."
        Remove-Item -Recurse -Force $script:McpVenvDir -ErrorAction SilentlyContinue
    }

    $py = Get-BestPython
    if (-not $py) { $py = Install-PortablePython }
    if (-not $py) {
        throw ("No Python >= 3.10 found, and the portable-python download failed " +
               "(no network / no NuGet access?). Either fix network access and re-run, " +
               "or install Python 3.10+ from python.org, then re-run.")
    }
    Write-Host "Setting up the pki-mcp server venv (one-time, using $py) ..."
    Write-Host "  location : $script:McpVenvDir"
    Write-Host "  (this venv is separate from the CA server venv and contains only MCP dependencies)"
    $eap = $ErrorActionPreference ; $ErrorActionPreference = 'Continue'
    try {
        & $py -m venv $script:McpVenvDir
        if ($LASTEXITCODE -ne 0) { throw "venv creation failed." }

        Write-Host "  installing pki-mcp dependencies ..."
        & $script:VenvPython -m pip install --quiet --upgrade pip 2>$null
        & $script:VenvPython -m pip install --quiet -r (Join-Path $script:PkiRoot 'pki_mcp\requirements.txt')
        if ($LASTEXITCODE -ne 0) {
            throw "pip install failed (check network / PyPI access, then re-run)."
        }

        # Add the PKI repo root to sys.path inside this venv so that
        # `import pki_mcp` resolves correctly without needing a full editable
        # install of the CA server (mirrors the server\.venv approach in rad-agent-toolkit).
        $sitePkgs = & $script:VenvPython -c "import site; print(site.getsitepackages()[0])" 2>$null
        $sitePkgs = ($sitePkgs -split "`r?`n" | Select-Object -First 1).Trim()
        if ($sitePkgs -and (Test-Path $sitePkgs)) {
            $pthFile = Join-Path $sitePkgs 'pki_root.pth'
            Set-Content -Path $pthFile -Value $script:PkiRoot -NoNewline
            Write-Host "  path     -> $script:PkiRoot -> $pthFile"
        }
    } finally { $ErrorActionPreference = $eap }
    Write-Host "  venv ready: $script:VenvPython"
}

# ---------------------------------------------------------------------------
# Skills
# ---------------------------------------------------------------------------

function Copy-SkillsTo {
    param([Parameter(Mandatory)][string]$Dest)
    New-Item -ItemType Directory -Force $Dest | Out-Null
    foreach ($s in $script:SkillNames) {
        $src = Join-Path $script:SkillsSrc $s
        if (-not (Test-Path $src)) { Write-Host "  WARNING: skill source not found: $src" ; continue }
        Copy-Item -Recurse -Force $src $Dest
        Write-Host "  skill -> $Dest\$s"
    }
}

# ---------------------------------------------------------------------------
# JSON helpers  (same quality as rad-agent-toolkit)
# ---------------------------------------------------------------------------

function Format-Json {
    # Re-indent compact JSON with 2-space indentation.
    # String-literal-aware so braces/brackets inside strings are untouched.
    param([Parameter(Mandatory)][string]$Json)
    $sb    = [System.Text.StringBuilder]::new()
    $unit  = '  '
    $depth = 0
    $inStr = $false
    $esc   = $false
    $chars = $Json.ToCharArray()
    for ($i = 0; $i -lt $chars.Length; $i++) {
        $c = $chars[$i]
        if ($inStr) {
            [void]$sb.Append($c)
            if ($esc)          { $esc = $false }
            elseif ($c -eq '\') { $esc = $true  }
            elseif ($c -eq '"') { $inStr = $false }
            continue
        }
        switch ($c) {
            '"'  { $inStr = $true ; [void]$sb.Append($c) }
            '{'  {
                if (($i+1) -lt $chars.Length -and $chars[$i+1] -eq '}') {
                    [void]$sb.Append('{}') ; $i++
                } else {
                    $depth++ ; [void]$sb.Append("{`n" + ($unit * $depth))
                }
            }
            '['  {
                if (($i+1) -lt $chars.Length -and $chars[$i+1] -eq ']') {
                    [void]$sb.Append('[]') ; $i++
                } else {
                    $depth++ ; [void]$sb.Append("[`n" + ($unit * $depth))
                }
            }
            '}'  { $depth-- ; [void]$sb.Append("`n" + ($unit * $depth) + '}') }
            ']'  { $depth-- ; [void]$sb.Append("`n" + ($unit * $depth) + ']') }
            ','  { [void]$sb.Append(",`n" + ($unit * $depth)) }
            ':'  { [void]$sb.Append(': ') }
            ' '  {}  "`t" {}  "`n" {}  "`r" {}
            default { [void]$sb.Append($c) }
        }
    }
    return $sb.ToString()
}

function Remove-JsonComments {
    # Strip // and /* */ comments outside string literals (JSONC -> JSON).
    # IntelliJ seeds mcp.json with a commented template; this lets us parse it.
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Json)
    $sb    = [System.Text.StringBuilder]::new()
    $inStr = $false
    $esc   = $false
    $chars = $Json.ToCharArray()
    for ($i = 0; $i -lt $chars.Length; $i++) {
        $c = $chars[$i]
        if ($inStr) {
            [void]$sb.Append($c)
            if ($esc)           { $esc = $false }
            elseif ($c -eq '\') { $esc = $true  }
            elseif ($c -eq '"') { $inStr = $false }
            continue
        }
        if ($c -eq '"') { $inStr = $true ; [void]$sb.Append($c) ; continue }
        if ($c -eq '/' -and ($i+1) -lt $chars.Length) {
            if ($chars[$i+1] -eq '/') {
                while ($i -lt $chars.Length -and $chars[$i] -ne "`n") { $i++ }
                if ($i -lt $chars.Length) { [void]$sb.Append("`n") }
                continue
            }
            if ($chars[$i+1] -eq '*') {
                $end = $Json.IndexOf('*/', $i+2)
                $i = if ($end -lt 0) { $chars.Length } else { $end+1 }
                continue
            }
        }
        [void]$sb.Append($c)
    }
    return $sb.ToString()
}

function Set-JsonMcpEntry {
    # Create/merge a JSON config file, replacing any existing entry named $Name
    # under the given root key.  Produces clean 2-space-indented output.
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$RootKey,
        [Parameter(Mandatory)]$Entry,
        [string]$Name = 'pki-mcp'
    )
    if (Test-Path $Path) {
        $raw = Get-Content $Path -Raw -ErrorAction SilentlyContinue
        $rawSafe = if ($raw) { $raw } else { '' }
        $cfg = try { (Remove-JsonComments $rawSafe) | ConvertFrom-Json } catch { [pscustomobject]@{} }
    } else {
        New-Item -ItemType Directory -Force (Split-Path $Path) | Out-Null
        $cfg = [pscustomobject]@{}
    }
    if (-not $cfg.PSObject.Properties[$RootKey]) {
        $cfg | Add-Member -NotePropertyName $RootKey -NotePropertyValue ([pscustomobject]@{})
    }
    $root = $cfg.$RootKey
    if ($root.PSObject.Properties[$Name]) {
        $root.PSObject.Properties.Remove($Name)
    }
    $root | Add-Member -NotePropertyName $Name -NotePropertyValue ([pscustomobject]$Entry)
    $json = Format-Json ($cfg | ConvertTo-Json -Depth 10 -Compress)
    [System.IO.File]::WriteAllText($Path, $json + "`n", [System.Text.UTF8Encoding]::new($false))
    Write-Host "  mcp   -> $Name in $Path"
}

function Backup-JsonConfig {
    param([string]$Path)
    if (Test-Path $Path) {
        $bak = "$Path.bak"
        Copy-Item $Path $bak -Force
        Write-Host "  backup -> $bak"
    }
}

function Test-KeepExisting {
    param([string]$Path, [string]$RootKey, [string]$Name)
    if (-not (Test-Path $Path)) { return $false }
    try {
        $cfg = (Remove-JsonComments (Get-Content $Path -Raw)) | ConvertFrom-Json
        $root = $cfg.$RootKey
        if ($root -and $root.PSObject.Properties[$Name]) {
            $existing = $root.$Name
            $existingType = if ($existing.url) { "http ($($existing.url))" } else { "stdio" }
            Write-Host ""
            Write-Host "  pki-mcp is already configured in $Path"
            Write-Host "  existing entry: $existingType"
            $ans = Read-Host "  Keep existing MCP entry? [Y/n]"
            return ($ans -notmatch '^[nN]')
        }
    } catch { }
    return $false
}

# ---------------------------------------------------------------------------
# PKI server reachability check
# ---------------------------------------------------------------------------

function Show-PkiServerStatus {
    param(
        [ValidateSet('stdio','http')][string]$Mode,
        [string]$BaseUrl = ''
    )
    # For HTTP mode, check if the server URL is reachable
    $checkUrl = if ($Mode -eq 'http') { $BaseUrl } else { '' }
    if (-not $checkUrl) {
        # stdio: read from env or skip
        $checkUrl = $env:PKI_BASE_URL
    }
    if (-not $checkUrl) {
        Write-Host "  checker status: UNKNOWN (PKI_BASE_URL not set; set it in the MCP config env block)"
        return
    }
    try {
        $resp = Invoke-WebRequest -Uri "$checkUrl/certs/state" -UseBasicParsing `
                    -TimeoutSec 4 -ErrorAction Stop -SkipCertificateCheck 2>$null
        if ($resp.StatusCode -lt 500) {
            Write-Host "  checker status: OK (PKI server reachable at $checkUrl)"
        } else {
            Write-Host "  checker status: DEGRADED (PKI server returned $($resp.StatusCode) at $checkUrl)"
        }
    } catch {
        Write-Host "  checker status: DEGRADED (PKI server not reachable at $checkUrl)"
        Write-Host "  NOTE: the MCP server will work once the PKI server is started."
    }
}

# ---------------------------------------------------------------------------
# MCP entry constructors
# ---------------------------------------------------------------------------

function New-StdioEntry {
    param([switch]$WithType, [string]$BaseUrl = 'https://localhost:443', [string]$Token = '')
    $e = [ordered]@{}
    if ($WithType) { $e.type = 'stdio' }
    $e.command = $script:VenvPython
    $e.args    = @('-m', $script:McpModule, '--transport', 'stdio')
    $e.cwd     = $script:PkiRoot
    $e.env     = [ordered]@{
        PKI_BASE_URL   = $BaseUrl
        PKI_TOKEN      = $Token
        PKI_VERIFY_SSL = 'false'
    }
    return $e
}

function New-HttpEntry {
    param(
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][string]$Token,
        [switch]$RequestInit   # JetBrains uses requestInit instead of top-level headers
    )
    if ($RequestInit) {
        return [ordered]@{
            type        = 'http'
            url         = $Url
            requestInit = @{ headers = @{ Authorization = "Bearer $Token" } }
        }
    }
    return [ordered]@{
        type    = 'http'
        url     = $Url
        headers = @{ Authorization = "Bearer $Token" }
    }
}

# ---------------------------------------------------------------------------
# Interactive prompts -- two-section structure used by all client installers
# ---------------------------------------------------------------------------

# Helper: print a numbered section banner
function Write-SectionHeader {
    param([string]$Label)
    Write-Host ""
    Write-Host "  ┌─────────────────────────────────────────────────────┐"
    Write-Host "  │  $Label"
    Write-Host "  └─────────────────────────────────────────────────────┘"
}

# Brief (no section header) transport choice -- called before the two sections
# so Section 1 content can be tailored to the mode.
# Returns 'stdio' or 'http'.
function Get-TransportChoice {
    Write-Host ""
    Write-Host "  PKI MCP server transport:"
    Write-Host "    1) stdio  -- AI client launches the server locally [default]"
    Write-Host "    2) http   -- connect to a running PKI MCP HTTP server"
    $ans = (Read-Host "  Choice [1]").Trim()
    if ($ans -match '^2$|^http') { return 'http' }
    return 'stdio'
}

# --- Section 1 helpers ------------------------------------------------------

# Section 1 for stdio mode: prompt for Pikachu CA credentials (or reuse saved ones).
# Returns @{BaseUrl; Token}.
function Invoke-Section1-Stdio {
    Write-SectionHeader "Section 1 of 2  --  Pikachu CA server"
    Write-Host "  The Flask PKI/CA server that the MCP server connects to."
    $saved = Read-EnvFile $script:StdioEnvFile
    if ($saved['PKI_TOKEN']) {
        Write-Host ""
        Write-Host "  Saved credentials found ($script:StdioEnvFile):"
        Write-Host "    PKI_BASE_URL : $($saved['PKI_BASE_URL'])"
        Write-Host "    PKI_TOKEN    : $($saved['PKI_TOKEN'].Substring(0,[Math]::Min(8,$saved['PKI_TOKEN'].Length)))..."
        $ans = (Read-Host "  Use saved credentials? [Y/n]").Trim()
        if ($ans -notmatch '^[nN]') {
            return @{ BaseUrl = $saved['PKI_BASE_URL']; Token = $saved['PKI_TOKEN'] }
        }
    }
    Write-Host ""
    $url = (Read-Host "  Pikachu CA base URL [https://localhost:443]").Trim()
    if (-not $url) { $url = 'https://localhost:443' }
    Write-Host "  API token: create in the PKI web UI -- Account -> API Tokens"
    Write-Host "  (admin-role token enables all [ADMIN] tools)"
    $token = (Read-Host "  PKI_TOKEN").Trim()
    return @{ BaseUrl = $url; Token = $token }
}

# Section 1 for HTTP mode: display Pikachu CA info from the saved HTTP server config.
# Returns the PKI base URL (string, may be empty).
function Invoke-Section1-Http {
    Write-SectionHeader "Section 1 of 2  --  Pikachu CA server"
    Write-Host "  Managed by the MCP HTTP server -- no client config needed here."
    $cfg = Read-EnvFile $script:HttpEnvFile
    if ($cfg['PKI_BASE_URL']) {
        Write-Host "    PKI_BASE_URL : $($cfg['PKI_BASE_URL'])"
        Write-Host "    TLS verify   : $($cfg['PKI_VERIFY_SSL'])"
    } else {
        Write-Host "  (no saved HTTP server config found -- run install-http-mcp-server.ps1 first)"
    }
    return $cfg['PKI_BASE_URL']
}

# --- Section 2 helpers ------------------------------------------------------

# Section 2 for stdio mode: informational only.
function Show-Section2-Stdio {
    Write-SectionHeader "Section 2 of 2  --  PKI MCP server"
    Write-Host "  Transport : stdio"
    Write-Host "  The AI client will launch the MCP server locally using the"
    Write-Host "  Pikachu CA credentials embedded in the client config env block."
}

# Section 2 for HTTP mode: ask MCP server URL + RW/RO token.
# Returns @{Url; Token}.
function Invoke-Section2-Http {
    Write-SectionHeader "Section 2 of 2  --  PKI MCP server"
    Write-Host "  Transport : http  (the HTTP server must already be running)"
    # Auto-fill URL from saved HTTP server config
    $cfg = Read-EnvFile $script:HttpEnvFile
    $defUrl = ''
    if ($cfg['MCP_PORT']) {
        $s = if ($cfg['MCP_SSL_CERTFILE']) { 'https' } else { 'http' }
        $defUrl = "$s`://localhost:$($cfg['MCP_PORT'])/mcp"
    }
    $prompt = if ($defUrl) { "  MCP server URL [$defUrl]" } else { "  MCP server URL (e.g. http://localhost:8080/mcp)" }
    $url = (Read-Host $prompt).Trim()
    if (-not $url -and $defUrl) { $url = $defUrl }
    $token = Select-McpToken
    if (-not $token) { $token = (Read-Host "  Bearer token").Trim() }
    return @{ Url = $url; Token = $token }
}

# Legacy wrapper kept for backward compat (install-http-mcp-server uses it internally)
function Prompt-PkiCredentials {
    Write-Host ""
    $url = (Read-Host "  Pikachu CA base URL [https://localhost:443]").Trim()
    if (-not $url) { $url = 'https://localhost:443' }
    Write-Host "  API token: create in the PKI web UI -- Account -> API Tokens"
    Write-Host "  (admin-role token enables all [ADMIN] tools)"
    $token = (Read-Host "  PKI_TOKEN").Trim()
    return @{ BaseUrl = $url; Token = $token }
}

# Legacy: kept for scripts that still call it directly
function Invoke-TransportPrompt {
    # Returns @{Mode='stdio'|'http', Url='', Token=''}
    $mode = Get-TransportChoice
    if ($mode -eq 'http') {
        $mcp = Invoke-Section2-Http
        return @{ Mode = 'http'; Url = $mcp.Url; Token = $mcp.Token }
    }
    return @{ Mode = 'stdio'; Url = ''; Token = '' }
}

function Resolve-HttpArgs {
    # Resolve -Url / -Token flags: prompt for any that are missing.
    param([string]$Url, [string]$Token)
    if (-not $Url)   { $Url   = Read-Host "  HTTP server URL (e.g. http://localhost:8080/mcp)" }
    if (-not $Token) { $Token = Read-Host "  Bearer token for the MCP HTTP server" }
    return $Url, $Token
}

# ---------------------------------------------------------------------------
# .env file helpers (HTTP server and stdio stored config)
# ---------------------------------------------------------------------------

function Read-EnvFile {
    param([string]$Path)
    $cfg = [ordered]@{}
    if (-not (Test-Path $Path)) { return $cfg }
    Get-Content $Path -Encoding UTF8 | ForEach-Object {
        $line = $_.Trim()
        if ($line -and -not $line.StartsWith('#') -and $line -match '^([^=]+)=(.*)$') {
            $cfg[$Matches[1].Trim()] = $Matches[2].Trim()
        }
    }
    return $cfg
}

function Write-EnvFile {
    param([string]$Path, [System.Collections.IDictionary]$Cfg)
    $lines = $Cfg.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }
    [System.IO.File]::WriteAllLines($Path, $lines, [System.Text.UTF8Encoding]::new($false))
    Write-Host "  config -> $Path"
}

# ---------------------------------------------------------------------------
# Keep-config prompts
# ---------------------------------------------------------------------------

function Test-KeepHttpConfig {
    $cfg = Read-EnvFile $script:HttpEnvFile
    if ($cfg.Count -eq 0) { return $false }
    Write-Host ""
    Write-Host "  Existing MCP HTTP server config found ($script:HttpEnvFile):"
    Write-Host "  PKI_BASE_URL      = $($cfg['PKI_BASE_URL'])"
    Write-Host "  MCP_PORT          = $($cfg['MCP_PORT'])"
    $tls = if ($cfg['MCP_SSL_CERTFILE']) { "yes ($($cfg['MCP_SSL_CERTFILE']))" } else { "no" }
    Write-Host "  TLS               = $tls"
    if ($cfg['MCP_AUTH_TOKEN'])     { Write-Host "  RW token          = $($cfg['MCP_AUTH_TOKEN'].Substring(0,[Math]::Min(8,$cfg['MCP_AUTH_TOKEN'].Length)))..." }
    if ($cfg['MCP_READONLY_TOKEN']) { Write-Host "  RO token          = $($cfg['MCP_READONLY_TOKEN'].Substring(0,[Math]::Min(8,$cfg['MCP_READONLY_TOKEN'].Length)))..." }
    $ans = Read-Host "  Keep existing config? [Y/n]"
    return ($ans -notmatch '^[nN]')
}

function Test-KeepStdioConfig {
    $cfg = Read-EnvFile $script:StdioEnvFile
    if ($cfg.Count -eq 0 -or -not $cfg['PKI_TOKEN']) { return $false }
    Write-Host ""
    Write-Host "  Existing stdio credentials found ($script:StdioEnvFile):"
    Write-Host "  PKI_BASE_URL = $($cfg['PKI_BASE_URL'])"
    Write-Host "  PKI_TOKEN    = $($cfg['PKI_TOKEN'].Substring(0,[Math]::Min(8,$cfg['PKI_TOKEN'].Length)))..."
    $ans = Read-Host "  Keep existing credentials? [Y/n]"
    return ($ans -notmatch '^[nN]')
}

# ---------------------------------------------------------------------------
# TLS prompt + self-signed cert generation
# ---------------------------------------------------------------------------

function Invoke-TlsPrompt {
    # Returns @{Mode='none'|'self-signed'|'import'; CertFile=''; KeyFile=''}
    Write-Host ""
    Write-Host "TLS for the MCP HTTP server:"
    Write-Host "  1) No TLS       -- plain http:// [default]"
    Write-Host "  2) Self-signed  -- generate a new self-signed cert (localhost/127.0.0.1)"
    Write-Host "  3) Import       -- provide paths to an existing cert + key"
    $ans = Read-Host "Choice [1]"
    switch -Regex ($ans) {
        '^2$|^s' {
            $certDir  = Join-Path $script:PkiRoot 'pki_mcp\certs'
            $certFile = Join-Path $certDir 'mcp-cert.pem'
            $keyFile  = Join-Path $certDir 'mcp-key.pem'
            New-SelfSignedMcpCert -CertFile $certFile -KeyFile $keyFile
            return @{ Mode = 'self-signed'; CertFile = $certFile; KeyFile = $keyFile }
        }
        '^3$|^i' {
            $certFile = (Read-Host "  Certificate file path (PEM)").Trim()
            $keyFile  = (Read-Host "  Private key file path (PEM)").Trim()
            return @{ Mode = 'import'; CertFile = $certFile; KeyFile = $keyFile }
        }
        default {
            return @{ Mode = 'none'; CertFile = ''; KeyFile = '' }
        }
    }
}

function New-SelfSignedMcpCert {
    param([string]$CertFile, [string]$KeyFile)
    New-Item -ItemType Directory -Force (Split-Path $CertFile) | Out-Null
    # Try OpenSSL first
    $ossl = (Get-Command openssl -ErrorAction SilentlyContinue)
    if ($ossl) {
        & openssl req -x509 -newkey rsa:2048 -keyout $KeyFile -out $CertFile `
            -days 365 -nodes -subj "/CN=localhost" 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  cert  -> $CertFile (openssl)"
            Write-Host "  key   -> $KeyFile"
            return
        }
    }
    # Fallback: Python cryptography (available in the PKI venv)
    $py = @"
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime, ipaddress, pathlib

key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
cert = (
    x509.CertificateBuilder()
    .subject_name(subject).issuer_name(issuer)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.now(datetime.UTC))
    .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365))
    .add_extension(x509.SubjectAlternativeName([
        x509.DNSName('localhost'),
        x509.IPAddress(ipaddress.IPv4Address('127.0.0.1')),
    ]), critical=False)
    .sign(key, hashes.SHA256())
)
pathlib.Path(r'KEYFILE').write_bytes(
    key.private_bytes(serialization.Encoding.PEM,
                      serialization.PrivateFormat.TraditionalOpenSSL,
                      serialization.NoEncryption()))
pathlib.Path(r'CERTFILE').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
print('OK')
"@
    $py = $py.Replace('KEYFILE', $KeyFile.Replace('\','/')).Replace('CERTFILE', $CertFile.Replace('\','/'))
    $out = & $script:VenvPython -c $py 2>&1
    if ("$out" -match 'OK') {
        Write-Host "  cert  -> $CertFile (python cryptography)"
        Write-Host "  key   -> $KeyFile"
    } else {
        throw "Failed to generate self-signed cert: $out"
    }
}

# ---------------------------------------------------------------------------
# MCP HTTP server auth tokens
# ---------------------------------------------------------------------------

function New-RandomToken {
    $t = & $script:VenvPython -c "import secrets; print(secrets.token_urlsafe(32))" 2>$null
    return ($t -split "`r?`n" | Select-Object -First 1).Trim()
}

function Invoke-McpTokensPrompt {
    # Returns @{RwToken=''; RoToken=''}
    Write-Host ""
    Write-Host "MCP HTTP server auth tokens (sent by clients as: Authorization: Bearer <token>):"
    Write-Host "  Press Enter to auto-generate a secure random token."
    $rw = (Read-Host "  Read-Write token [auto-generate]").Trim()
    if (-not $rw) { $rw = New-RandomToken ; Write-Host "  Generated RW: $rw" }
    $ro = (Read-Host "  Read-Only token  [auto-generate]").Trim()
    if (-not $ro) { $ro = New-RandomToken ; Write-Host "  Generated RO: $ro" }
    return @{ RwToken = $rw; RoToken = $ro }
}

function Select-McpToken {
    # Pick rw or ro token from .mcp-http.env (for client config).
    # Returns the chosen token string.
    param([string]$DefaultToken = '')
    $cfg = Read-EnvFile $script:HttpEnvFile
    $rw = $cfg['MCP_AUTH_TOKEN']
    $ro = $cfg['MCP_READONLY_TOKEN']
    if ($rw -or $ro) {
        Write-Host ""
        Write-Host "  Available MCP HTTP server tokens:"
        if ($rw) { Write-Host "  1) Read-Write : $($rw.Substring(0,[Math]::Min(8,$rw.Length)))..." }
        if ($ro) { Write-Host "  2) Read-Only  : $($ro.Substring(0,[Math]::Min(8,$ro.Length)))..." }
        $ans = Read-Host "  Which token for this client? [1=RW / 2=RO, default 1]"
        if ($ans -match '^2') { return $ro }
        return $rw
    }
    return $DefaultToken
}

