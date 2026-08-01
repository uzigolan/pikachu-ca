# run_tests_ui.ps1
# Run the full UI certificate test suite and generate a self-contained HTML report.
#
# Usage (from repo root):
#   powershell -ExecutionPolicy Bypass -File scripts\run_tests_ui.ps1
#
# Optional: set CERT_TEST_STEP=<1-17> to run a single step only.

param(
    [string]$Step = $env:CERT_TEST_STEP
)

Set-Location (Split-Path -Parent $PSScriptRoot)
$env:PYTHONPATH = (Resolve-Path .).Path
$env:PIKACHU_EDITION = if ($env:PIKACHU_EDITION) { $env:PIKACHU_EDITION } else { "enterprise" }

$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm"
$report    = "tests_repo\reports\pikachu_test_ui_full_$timestamp.html"

$pytest = ".\.venv\Scripts\pytest.exe"
if (-not (Test-Path $pytest)) { $pytest = "pytest" }

$args_list = @(
    "tests_repo/test_certificates_ui.py",
    "--capture=tee-sys",
    "--self-contained-html",
    "--html=$report"
)

if ($Step) {
    Write-Host "Running single UI step: $Step" -ForegroundColor Cyan
    $env:CERT_TEST_STEP = $Step
}

Write-Host "Starting UI tests → $report" -ForegroundColor Cyan
& $pytest @args_list
$exit_code = $LASTEXITCODE

Write-Host ""
if ($exit_code -eq 0) {
    Write-Host "UI tests PASSED. Report: $report" -ForegroundColor Green
} else {
    Write-Host "UI tests FAILED (exit $exit_code). Report: $report" -ForegroundColor Red
}

exit $exit_code
