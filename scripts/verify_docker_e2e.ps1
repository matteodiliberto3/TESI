param(
    [switch]$SkipBuild = $false
)

$ErrorActionPreference = "Stop"

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "  MLOps Security Testbed: Docker Compose End-to-End Verification      " -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

# 1. Check Docker daemon availability
Write-Host "`n[1/6] Verifying Docker CLI and Daemon connectivity..." -ForegroundColor Yellow
try {
    docker info > $null 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Docker daemon is not running. Please start Docker Desktop and retry."
    }
    Write-Host "  -> Docker daemon is ACTIVE." -ForegroundColor Green
} catch {
    Write-Host "  ERROR: $_" -ForegroundColor Red
    exit 1
}

# 2. Validate Compose configuration
Write-Host "`n[2/6] Validating docker-compose specification..." -ForegroundColor Yellow
docker compose config --quiet
if ($LASTEXITCODE -ne 0) {
    Write-Host "  ERROR: docker-compose configuration validation failed." -ForegroundColor Red
    exit 1
}
Write-Host "  -> docker compose config is valid (0 errors)." -ForegroundColor Green

# 3. Clean prior transient containers
Write-Host "`n[3/6] Ensuring clean runtime environment..." -ForegroundColor Yellow
docker compose down -v > $null 2>&1

# 4. Launch Producer then Consumer
Write-Host "`n[4/6] Building and launching Producer & Consumer services..." -ForegroundColor Yellow
if ($SkipBuild) {
    docker compose up -d mlops-inference-consumer
} else {
    docker compose up --build -d mlops-inference-consumer
}

if ($LASTEXITCODE -ne 0) {
    Write-Host "  ERROR: docker compose up failed." -ForegroundColor Red
    exit 1
}

# 5. Wait for Consumer to become healthy
Write-Host "`n[5/6] Waiting for mlops_inference_consumer healthcheck (depends_on producer)..." -ForegroundColor Yellow
$maxAttempts = 30
$attempt = 0
$healthy = $false

while ($attempt -lt $maxAttempts) {
    Start-Sleep -Seconds 2
    $attempt++
    $status = docker inspect --format="{{.State.Health.Status}}" mlops_inference_consumer 2>$null
    if ($status -eq "healthy") {
        $healthy = $true
        Write-Host "  -> mlops_inference_consumer is HEALTHY (attempt $attempt)." -ForegroundColor Green
        break
    }
    Write-Host "  ... waiting for healthcheck (status: '$status', attempt $attempt/$maxAttempts)" -ForegroundColor Gray
}

if (-not $healthy) {
    Write-Host "  ERROR: Service failed to reach healthy status within timeout." -ForegroundColor Red
    docker compose logs
    docker compose down -v
    exit 1
}

# 6. Verify security contracts
Write-Host "`n[6/6] Verifying security isolation and inference endpoints..." -ForegroundColor Yellow

# A. Endpoint /health check
$healthRes = Invoke-RestMethod -Uri "http://localhost:8000/health" -Method Get
Write-Host "  -> /health response: $($healthRes | ConvertTo-Json -Compress)" -ForegroundColor Green

if ($healthRes.signature_verified -ne $true) {
    Write-Host "  ERROR: Model signature verification failed!" -ForegroundColor Red
    docker compose down -v
    exit 1
}

if ($healthRes.private_key_absent_from_consumer -ne $true) {
    Write-Host "  ERROR: Consumer detected private key present! Least Privilege violation." -ForegroundColor Red
    docker compose down -v
    exit 1
}

# B. Direct container filesystem probe (assert absence of private key)
$probe = docker compose exec mlops-inference-consumer sh -c "test -f /app/keys/private_key.pem && echo PRESENT || echo ABSENT"
$probe = $probe.Trim()
if ($probe -ne "ABSENT") {
    Write-Host "  ERROR: Container filesystem contains /app/keys/private_key.pem!" -ForegroundColor Red
    docker compose down -v
    exit 1
}
Write-Host "  -> Filesystem isolation confirmed: /app/keys/private_key.pem is strictly ABSENT inside consumer container." -ForegroundColor Green

# C. Inference request check
$body = @{
    amount = 49.99
    transaction_hour = 4.0
    distance_from_home = 10.0
    velocity_last_24h = 1
    foreign_transaction = 0
    high_risk_merchant = 0
} | ConvertTo-Json

$predictRes = Invoke-RestMethod -Uri "http://localhost:8000/predict" -Method Post -Body $body -ContentType "application/json"
Write-Host "  -> /predict response: is_fraud=$($predictRes.is_fraud), prob=$($predictRes.fraud_probability)" -ForegroundColor Green

Write-Host "`n======================================================================" -ForegroundColor Cyan
Write-Host "  ALL DOCKER COMPOSE E2E CHECKS PASSED SUCCESSFULLY!                   " -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

# Cleanup
Write-Host "Tearing down test containers..." -ForegroundColor Gray
docker compose down -v > $null 2>&1
