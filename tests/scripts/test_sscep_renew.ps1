param(
    [string]$ChallengePassword,
    [string]$CommonName
)

$ErrorActionPreference = "Stop"

function Get-ConfigValue {
    param([string]$ConfigPath, [string]$Section, [string]$Key)

    $inSection = $false
    foreach ($line in Get-Content -LiteralPath $ConfigPath) {
        $trimmed = $line.Trim()
        if ($trimmed -match "^\[" + [regex]::Escape($Section) + "\]") {
            $inSection = $true
        } elseif ($trimmed -match "^\[.*\]") {
            $inSection = $false
        } elseif ($inSection -and $trimmed -match "^" + [regex]::Escape($Key) + "\s*=\s*(.+)") {
            return $matches[1].Trim()
        }
    }
    return $null
}

function Skip-Test {
    param([string]$Reason)
    Write-Host "[SKIP] $Reason" -ForegroundColor Yellow
    exit 0
}

function Invoke-Native {
    param([string]$Description, [string]$FilePath, [string[]]$Arguments)

    Write-Host "  > $Description" -ForegroundColor DarkGray
    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Description failed with exit code $LASTEXITCODE."
    }
}

function Get-CertificateSnapshot {
    param([string]$CertificatePath, [string]$PublicKeyPath)

    $serial = (& openssl x509 -in $CertificatePath -noout -serial).Trim()
    $subject = (& openssl x509 -in $CertificatePath -noout -subject -nameopt RFC2253).Trim()
    $publicKey = & openssl x509 -in $CertificatePath -pubkey -noout
    if ($LASTEXITCODE -ne 0) {
        throw "Could not extract public key from $CertificatePath."
    }
    $publicKey | Set-Content -LiteralPath $PublicKeyPath -Encoding ascii
    return @{
        Serial = $serial
        Subject = $subject
        PublicKeyHash = (Get-FileHash -LiteralPath $PublicKeyPath -Algorithm SHA256).Hash
    }
}

$workspace = (Get-Location).Path
$configPath = Join-Path $workspace "config.ini"
if (-not (Test-Path -LiteralPath $configPath)) {
    Skip-Test "config.ini is unavailable."
}

$renewalEnabled = Get-ConfigValue $configPath "SCEP" "certificate_renewal_enabled"
if ($renewalEnabled -eq $null -or $renewalEnabled.ToLowerInvariant() -ne "true") {
    Skip-Test "[SCEP] certificate_renewal_enabled is not true."
}

$httpPort = Get-ConfigValue $configPath "DEFAULT" "http_port"
if ([string]::IsNullOrWhiteSpace($httpPort)) {
    Skip-Test "[DEFAULT] http_port is unavailable."
}

$sscepExe = Join-Path $workspace "tests\sscep\sscep.exe"
if (-not (Test-Path -LiteralPath $sscepExe)) {
    $sscepExe = Join-Path $workspace "tests\sscep\build\Release\sscep.exe"
}
if (-not (Test-Path -LiteralPath $sscepExe)) {
    Skip-Test "sscep.exe is unavailable under tests\sscep."
}
if (-not (Get-Command openssl -ErrorAction SilentlyContinue)) {
    Skip-Test "openssl is unavailable."
}

$runDir = Join-Path ([System.IO.Path]::GetTempPath()) ("pki-sscep-renew-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $runDir | Out-Null

try {
    $keyPath = Join-Path $runDir "renew.key"
    $initialCsrPath = Join-Path $runDir "initial.csr"
    $renewalCsrPath = Join-Path $runDir "renewal.csr"
    # sscep reads -O before writing -l, so this intentionally replaces the old certificate.
    $certificatePath = Join-Path $runDir "certificate.crt"
    $caCertificatePath = Join-Path $runDir "ca.crt"
    $oldPublicKeyPath = Join-Path $runDir "old-public-key.pem"
    $newPublicKeyPath = Join-Path $runDir "new-public-key.pem"
    if ([string]::IsNullOrWhiteSpace($CommonName)) {
        $CommonName = "sscep-renew-$([guid]::NewGuid().ToString('N'))"
    }
    $subject = "/C=IL/ST=TLV/L=Tel-Aviv/O=TestOrg/OU=IT/CN=$CommonName"
    $scepUrl = "http://127.0.0.1:$httpPort/scep"

    Invoke-Native "generate renewal key" "openssl" @("genrsa", "-out", $keyPath, "2048")
    if ([string]::IsNullOrEmpty($ChallengePassword)) {
        Invoke-Native "generate initial CSR" "openssl" @("req", "-new", "-key", $keyPath, "-out", $initialCsrPath, "-subj", $subject)
    } else {
        $initialConfigPath = Join-Path $runDir "initial-openssl.cnf"
        $escapedPassword = $ChallengePassword.Replace("\", "\\").Replace('"', '\"')
        @(
            "[ req ]"
            "distinguished_name = dn"
            "attributes = req_attrs"
            "prompt = no"
            "[ dn ]"
            "C = IL"
            "ST = TLV"
            "L = Tel-Aviv"
            "O = TestOrg"
            "OU = IT"
            "CN = $CommonName"
            "[ req_attrs ]"
            "challengePassword = `"$escapedPassword`""
        ) | Set-Content -LiteralPath $initialConfigPath -Encoding ascii
        Invoke-Native "generate initial CSR with challenge password" "openssl" @("req", "-new", "-key", $keyPath, "-out", $initialCsrPath, "-config", $initialConfigPath)
    }

    Invoke-Native "download SCEP CA certificate" $sscepExe @("getca", "-u", $scepUrl, "-c", $caCertificatePath)
    Invoke-Native "initial SCEP enrollment" $sscepExe @("enroll", "-u", $scepUrl, "-k", $keyPath, "-r", $initialCsrPath, "-c", $caCertificatePath, "-l", $certificatePath, "-E", "aes", "-S", "sha256")
    if (-not (Test-Path -LiteralPath $certificatePath)) {
        throw "Initial enrollment did not produce a certificate."
    }
    $oldCertificate = Get-CertificateSnapshot $certificatePath $oldPublicKeyPath

    Invoke-Native "generate renewal CSR without challenge password" "openssl" @("req", "-new", "-key", $keyPath, "-out", $renewalCsrPath, "-subj", $subject)
    Invoke-Native "SCEP renewal signed by old certificate" $sscepExe @("enroll", "-u", $scepUrl, "-k", $keyPath, "-r", $renewalCsrPath, "-c", $caCertificatePath, "-K", $keyPath, "-O", $certificatePath, "-l", $certificatePath, "-E", "aes", "-S", "sha256")
    if (-not (Test-Path -LiteralPath $certificatePath)) {
        throw "Renewal did not produce a certificate."
    }
    $newCertificate = Get-CertificateSnapshot $certificatePath $newPublicKeyPath

    if ($oldCertificate.Serial -eq $newCertificate.Serial) {
        throw "Renewal certificate serial did not change."
    }
    if ($oldCertificate.Subject -ne $newCertificate.Subject) {
        throw "Renewal certificate subject changed."
    }
    if ($oldCertificate.PublicKeyHash -ne $newCertificate.PublicKeyHash) {
        throw "Renewal certificate public key changed."
    }
    Write-Host "[OK] Renewal issued a new serial with the same subject and public key." -ForegroundColor Green
} finally {
    if (Test-Path -LiteralPath $runDir) {
        Remove-Item -LiteralPath $runDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
