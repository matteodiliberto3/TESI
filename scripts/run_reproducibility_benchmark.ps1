<#
==============================================================================
Full Scientific Reproducibility Benchmark Runner (PowerShell)
Executes the full battery of experiments (Exp 1 to Exp 6 + 30-seed Causal Ablation)
==============================================================================
#>
[CmdletBinding()]
param(
    [int]$Seeds = 30
)

$ErrorActionPreference = "Stop"

$ProjectRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $ProjectRoot

Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host "    MLOps Security Testbed: Full Reproducibility Benchmark Runner" -ForegroundColor Cyan
Write-Host "    Executing: Baseline, Exp 1-6, and Causal Ablation Study ($Seeds Seeds)" -ForegroundColor Cyan
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

Write-Host "[*] Python Environment: $(& $PyBin --version)" -ForegroundColor Green

# Ensure directories exist
$Dirs = @("data_storage", "feature_store_storage", "artifacts", "reports", "keys")
foreach ($Dir in $Dirs) {
    $Path = Join-Path $ProjectRoot $Dir
    if (-not (Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

# Provision ephemeral cryptographic signing keys if absent on clean runner checkout
$PrivKey = Join-Path $ProjectRoot "keys\private_key.pem"
if (-not (Test-Path $PrivKey)) {
    Write-Host "[*] Provisioning ephemeral RSA keypair for experiment artifact signing..." -ForegroundColor Yellow
    & $PyBin pipeline/crypto_signer.py --generate-keys
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Key provisioning failed with exit code $LASTEXITCODE"
        exit $LASTEXITCODE
    }
}

# Execute complete experimental battery
Write-Host "[*] Launching Master Experiment Runner with --full --seeds $Seeds..." -ForegroundColor Yellow
& $PyBin experiments/run_all_experiments.py --full --seeds $Seeds
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

# Run numerical invariant and boundary verification
Write-Host "[*] Verifying numerical bounds against Chapter 5 ground truth..." -ForegroundColor Yellow
& $PyBin scripts/verify_reproducibility_results.py
if ($LASTEXITCODE -ne 0) {
    Write-Error "Numerical invariant verification failed with exit code $LASTEXITCODE"
    exit $LASTEXITCODE
}

Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host "[+] REPRODUCIBILITY BENCHMARK COMPLETE AND NUMERICALLY VERIFIED" -ForegroundColor Green
Write-Host "    Generated Ground Truth Artefacts:" -ForegroundColor Green
Write-Host "    - reports/causal_ablation_results.json" -ForegroundColor Gray
Write-Host "    - reports/CAUSAL_ABLATION_REPORT.md" -ForegroundColor Gray
Write-Host "    - reports/EXPERIMENT_RESULTS.md" -ForegroundColor Gray
Write-Host "    - reports/evasion_results.json" -ForegroundColor Gray
Write-Host "    - reports/system_benchmarks.json" -ForegroundColor Gray
Write-Host "==============================================================================" -ForegroundColor Cyan
