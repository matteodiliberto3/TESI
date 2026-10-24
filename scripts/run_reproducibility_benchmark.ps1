<#
==============================================================================
Full Scientific Reproducibility Benchmark Runner (PowerShell)
Executes the full battery of experiments (Exp 1 to Exp 6 + 30-seed Causal Ablation)
==============================================================================
#>
[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

$ProjectRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $ProjectRoot

Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host "    MLOps Security Testbed: Full Reproducibility Benchmark Runner" -ForegroundColor Cyan
Write-Host "    Executing: Baseline, Exp 1-6, and 30-Seed Causal Ablation Study" -ForegroundColor Cyan
Write-Host "==============================================================================" -ForegroundColor Cyan

# Detect Python interpreter (prefer virtual environment if present)
$VenvPy = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
if (Test-Path $VenvPy) {
    $PyBin = $VenvPy
} elseif (Get-Command python -ErrorAction SilentlyContinue) {
    $PyBin = "python"
} else {
    Write-Error "Python interpreter not found."
    exit 1
}

Write-Host "[*] Python Environment: (& $PyBin --version)" -ForegroundColor Green

# Ensure directories exist
$Dirs = @("data_storage", "feature_store_storage", "artifacts", "reports", "keys")
foreach ($Dir in $Dirs) {
    $Path = Join-Path $ProjectRoot $Dir
    if (-not (Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

# Execute complete experimental battery
Write-Host "[*] Launching Master Experiment Runner with --full flag..." -ForegroundColor Yellow
& $PyBin experiments/run_all_experiments.py --full
if ($LASTEXITCODE -ne 0) {
    Write-Error "Master experiment runner failed with exit code $LASTEXITCODE"
    exit $LASTEXITCODE
}

# Run test suite to verify artifact schema and invariant compliance
Write-Host "[*] Verifying artifact integrity and statistical schemas with pytest..." -ForegroundColor Yellow
& $PyBin -m pytest tests/ -v
if ($LASTEXITCODE -ne 0) {
    Write-Error "Pytest verification failed with exit code $LASTEXITCODE"
    exit $LASTEXITCODE
}

Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host "[+] REPRODUCIBILITY BENCHMARK COMPLETE" -ForegroundColor Green
Write-Host "    Generated Ground Truth Artefacts:" -ForegroundColor Green
Write-Host "    - reports/causal_ablation_results.json" -ForegroundColor Gray
Write-Host "    - reports/CAUSAL_ABLATION_REPORT.md" -ForegroundColor Gray
Write-Host "    - reports/EXPERIMENT_RESULTS.md" -ForegroundColor Gray
Write-Host "    - reports/evasion_results.json" -ForegroundColor Gray
Write-Host "==============================================================================" -ForegroundColor Cyan
