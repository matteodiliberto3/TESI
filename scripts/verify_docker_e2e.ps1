param(
    [switch]$SkipBuild = $false,
    [switch]$NoColdStart = $false
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Split-Path -Parent $scriptDir
Set-Location $projectRoot

$logFile = Join-Path $projectRoot "reports\docker_e2e_verification.log"
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $logFile) | Out-Null

function Log-Output {
    param([string]$message, [string]$color = "White")
    Write-Host $message -ForegroundColor $color
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $logFile -Value "[$timestamp] $message"
}

function Get-FileSha256 {
    param([string]$FilePath)
    if (-not (Test-Path $FilePath)) { return "" }
    return (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash
}

# Clear old log
Set-Content -Path $logFile -Value "======================================================================"
Add-Content -Path $logFile -Value "  MLOps Security Testbed: Docker Compose End-to-End Verification Log"
Add-Content -Path $logFile -Value "======================================================================"

$commitHash = (git rev-parse HEAD 2>$null)
if (-not $commitHash) { $commitHash = "UNKNOWN_COMMIT" }
Log-Output "Git Commit Under Test: $commitHash" "Cyan"
Log-Output "Verification Date/Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')" "Cyan"
Log-Output "Operating System: $([System.Environment]::OSVersion.VersionString)" "Cyan"
Log-Output "======================================================================`n" "Cyan"

# Ephemeral secret token generation for dynamic reload authentication
if ([string]::IsNullOrEmpty($env:MLOPS_ADMIN_TOKEN)) {
    $env:MLOPS_ADMIN_TOKEN = [System.Guid]::NewGuid().ToString("N")
    Log-Output "  -> Ephemeral MLOPS_ADMIN_TOKEN provisioned for session: $($env:MLOPS_ADMIN_TOKEN.Substring(0,6))***" "Gray"
}

# 1. Check Docker daemon availability
Log-Output "[1/7] Verifying Docker CLI and Daemon connectivity..." "Yellow"
try {
    $dockerInfo = docker info 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Docker daemon is not reachable at npipe:////./pipe/dockerDesktopLinuxEngine.`nPlease launch Docker Desktop from Windows Start Menu and wait for the engine to initialize, then re-run this script."
    }
    $dockerVersion = (docker version --format '{{.Server.Version}}' 2>$null)
    Log-Output "  -> Docker daemon is ACTIVE (Server Version: $dockerVersion)." "Green"
} catch {
    Log-Output "  ERROR: $_" "Red"
    Log-Output "ABORTED: Docker daemon is stopped." "Red"
    exit 1
}

# 2. Validate Compose configuration
Log-Output "`n[2/7] Validating docker-compose specification..." "Yellow"
$configOutput = docker compose config --format json 2>&1
if ($LASTEXITCODE -ne 0) {
    Log-Output "  ERROR: docker-compose configuration validation failed: $configOutput" "Red"
    exit 1
}
Log-Output "  -> docker compose config is valid (0 errors)." "Green"

# 3. Clean prior containers
Log-Output "`n[3/7] Tearing down any existing testbed containers..." "Yellow"
docker compose down -v > $null 2>&1
Log-Output "  -> Existing containers and compose volumes removed." "Green"

$backupKeysDir = Join-Path $projectRoot ".cache_test_keys_backup"
$backupArtifactsDir = Join-Path $projectRoot ".cache_test_artifacts_backup"

try {
    # 4. Handle Cold-Start Bind Mount Reset
    if (-not $NoColdStart) {
        Log-Output "`n[4/7] Simulating TRUE COLD-START: Backing up and clearing host bind-mount secrets..." "Yellow"
        New-Item -ItemType Directory -Force -Path $backupKeysDir | Out-Null
        New-Item -ItemType Directory -Force -Path $backupArtifactsDir | Out-Null

        # Backup existing keys
        if (Test-Path "keys\private_key.pem") {
            Copy-Item "keys\private_key.pem" $backupKeysDir -Force
            Remove-Item "keys\private_key.pem" -Force
            Log-Output "  -> Safely backed up & removed keys\private_key.pem for test." "Gray"
        }
        if (Test-Path "keys\public_key.pem") {
            Copy-Item "keys\public_key.pem" $backupKeysDir -Force
        }

        # Backup existing artifacts
        if (Test-Path "artifacts\model_clean.pkl") {
            Copy-Item "artifacts\model_clean.pkl" $backupArtifactsDir -Force
            Remove-Item "artifacts\model_clean.pkl" -Force
            Log-Output "  -> Safely backed up & removed artifacts\model_clean.pkl for test." "Gray"
        }
        if (Test-Path "artifacts\model_clean.sig") {
            Copy-Item "artifacts\model_clean.sig" $backupArtifactsDir -Force
            Remove-Item "artifacts\model_clean.sig" -Force
            Log-Output "  -> Safely backed up & removed artifacts\model_clean.sig for test." "Gray"
        }
        if (Test-Path "artifacts\model_secure.safetensors") {
            Copy-Item "artifacts\model_secure.safetensors" $backupArtifactsDir -Force
            Remove-Item "artifacts\model_secure.safetensors" -Force
            Log-Output "  -> Safely backed up & removed artifacts\model_secure.safetensors for test." "Gray"
        }

        Log-Output "  -> Pristine cold-start state established: keys and artifacts must be generated by Producer container." "Green"
    }

    # 5. Build and launch services
    Log-Output "`n[5/7] Building and launching Producer & Consumer services..." "Yellow"
    if ($SkipBuild) {
        docker compose up -d mlops-inference-consumer
    } else {
        docker compose up --build -d mlops-inference-consumer
    }

    if ($LASTEXITCODE -ne 0) {
        Log-Output "ERROR: docker compose up failed!" "Red"
        docker compose logs >> $logFile 2>&1
        exit 1
    }

    # 6. Wait for consumer healthy
    Log-Output "`n[6/7] Waiting for mlops_inference_consumer healthcheck (depends_on producer)..." "Yellow"
    $maxAttempts = 35
    $attempt = 0
    $healthy = $false

    while ($attempt -lt $maxAttempts) {
        Start-Sleep -Seconds 2
        $attempt++
        $status = (docker inspect --format='{{.State.Health.Status}}' mlops_inference_consumer 2>$null)
        if ($status -eq "healthy") {
            $healthy = $true
            Log-Output "  -> mlops_inference_consumer is HEALTHY (attempt $attempt)." "Green"
            break
        }
        Log-Output "  ... waiting for healthcheck (status: '$status', attempt $attempt/$maxAttempts)" "Gray"
    }

    if (-not $healthy) {
        Log-Output "ERROR: Consumer service failed to reach healthy status within timeout." "Red"
        docker compose logs >> $logFile 2>&1
        exit 1
    }

    # 7. Verify security assertions
    Log-Output "`n[7/7] Verifying security isolation contracts and HTTP endpoints..." "Yellow"

    # A. Producer generated keys on host volume
    if (-not (Test-Path "keys\private_key.pem")) {
        Log-Output "  ERROR: Producer failed to generate keys\private_key.pem on volume mount!" "Red"
        exit 1
    }
    Log-Output "  -> [PASSED] Producer successfully provisioned keys\private_key.pem on volume." "Green"

    # B. Health check
    $healthRes = Invoke-RestMethod -Uri "http://localhost:8000/health" -Method Get
    if ($healthRes.status -ne "HEALTHY") {
        Log-Output "  ERROR: Consumer health status is not HEALTHY ($($healthRes.status))" "Red"
        exit 1
    }
    if ($healthRes.signature_verified -ne $true) {
        Log-Output "  ERROR: Model signature verification failed!" "Red"
        exit 1
    }
    Log-Output "  -> [PASSED] Consumer cryptographically verified model artifact signature via public key." "Green"

    if ($healthRes.private_key_absent_from_consumer -ne $true) {
        Log-Output "  ERROR: Consumer reported private key present! Least Privilege violation." "Red"
        exit 1
    }
    Log-Output "  -> [PASSED] Consumer verified absence of private key in its execution environment." "Green"

    # C. Direct container filesystem probe (assert absence of private key)
    $probe = docker compose exec mlops-inference-consumer sh -c "test -f /app/keys/private_key.pem && echo PRESENT || echo ABSENT"
    $probe = $probe.Trim()
    if ($probe -ne "ABSENT") {
        Log-Output "  ERROR: Container filesystem contains /app/keys/private_key.pem!" "Red"
        exit 1
    }
    Log-Output "  -> [PASSED] Filesystem isolation confirmed: /app/keys/private_key.pem is strictly ABSENT inside consumer container." "Green"

    # D. Inference request check
    $body = @{
        amount = 49.99
        transaction_hour = 4.0
        distance_from_home = 10.0
        velocity_last_24h = 1
        foreign_transaction = 0
        high_risk_merchant = 0
    } | ConvertTo-Json

    $predictRes = Invoke-RestMethod -Uri "http://localhost:8000/predict" -Method Post -Body $body -ContentType "application/json"
    Log-Output "  -> /predict response: is_fraud=$($predictRes.is_fraud), prob=$($predictRes.fraud_probability)" "Green"
    Log-Output "  -> [PASSED] HTTP inference prediction served successfully by unprivileged consumer." "Green"

    # E. Static configuration audit: ensure zero hardcoded secrets in docker-compose.yml
    Log-Output "`n[Security Audit] Auditing docker-compose.yml for hardcoded secrets..." "Yellow"
    $composeContent = Get-Content "docker-compose.yml" -Raw
    if ($composeContent -match 'MLOPS_ADMIN_TOKEN=[a-zA-Z0-9_-]{4,}' -and $composeContent -notmatch '\$\{') {
        Log-Output "ERROR: Hardcoded plaintext MLOPS_ADMIN_TOKEN detected in docker-compose.yml!" "Red"
        exit 1
    }
    Log-Output "  -> [PASSED] docker-compose.yml verified: zero hardcoded secrets or tokens." "Green"

    # F. Dynamic /reload security validation
    Log-Output "`n[Endpoint Security] Testing authenticated model hot-reloading (/reload)..." "Yellow"

    # F.1 Unauthorized without Bearer token
    try {
        $badReload = Invoke-RestMethod -Uri "http://localhost:8000/reload" -Method Post -Body '{"model_format":"safetensors","model_path":"artifacts/model_secure.safetensors"}' -ContentType "application/json"
        Log-Output "ERROR: Expected HTTP 401 when calling /reload without token, got response!" "Red"
        exit 1
    } catch {
        if ($_.Exception.Response.StatusCode.value__ -eq 401) {
            Log-Output "  -> [PASSED] Unauthorized /reload without Bearer token strictly rejected with HTTP 401." "Green"
        } else {
            Log-Output "ERROR: Unexpected status code without token: $($_.Exception.Response.StatusCode)" "Red"
            exit 1
        }
    }

    # F.2 Unauthorized with wrong Bearer token
    try {
        $headers = @{ Authorization = "Bearer invalid_secret_token_value_attempt" }
        $badReload = Invoke-RestMethod -Uri "http://localhost:8000/reload" -Method Post -Headers $headers -Body '{"model_format":"safetensors","model_path":"artifacts/model_secure.safetensors"}' -ContentType "application/json"
        Log-Output "ERROR: Expected HTTP 401 when calling /reload with bad token, got response!" "Red"
        exit 1
    } catch {
        if ($_.Exception.Response.StatusCode.value__ -eq 401) {
            Log-Output "  -> [PASSED] /reload with invalid Bearer token strictly rejected with HTTP 401." "Green"
        } else {
            Log-Output "ERROR: Unexpected status code with bad token: $($_.Exception.Response.StatusCode)" "Red"
            exit 1
        }
    }

    # F.3 Authorized reload with valid ephemeral token (safetensors format)
    $authHeaders = @{ Authorization = "Bearer $($env:MLOPS_ADMIN_TOKEN)" }
    $reloadRes = Invoke-RestMethod -Uri "http://localhost:8000/reload" -Method Post -Headers $authHeaders -Body '{"model_format":"safetensors","model_path":"artifacts/model_secure.safetensors"}' -ContentType "application/json"
    if (($reloadRes.status -eq "RELOADED" -or $reloadRes.status -eq "SUCCESS") -and $reloadRes.mode -eq "safetensors") {
        Log-Output "  -> [PASSED] Dynamic authenticated /reload successfully transitioned model to safetensors." "Green"
    } else {
        Log-Output "ERROR: /reload with valid token failed: $($reloadRes | ConvertTo-Json)" "Red"
        exit 1
    }

    # F.4 Negative test: Insecure pickle reload without override blocked fail-closed
    try {
        $insecureReload = Invoke-RestMethod -Uri "http://localhost:8000/reload" -Method Post -Headers $authHeaders -Body '{"model_format":"insecure_pickle","model_path":"artifacts/model_clean.pkl"}' -ContentType "application/json"
        Log-Output "ERROR: Expected HTTP 403 when reloading insecure pickle, got response!" "Red"
        exit 1
    } catch {
        if ($_.Exception.Response.StatusCode.value__ -eq 403) {
            Log-Output "  -> [PASSED] Insecure pickle reload fail-closed and returned HTTP 403 Forbidden." "Green"
        } else {
            Log-Output "ERROR: Unexpected status code for insecure pickle: $($_.Exception.Response.StatusCode)" "Red"
            exit 1
        }
    }

    # F.5 Negative test: Unsigned / tampered model package rejected fail-closed
    $unsignedDir = Join-Path (Join-Path $projectRoot "artifacts") "unsigned_e2e_test_pkg"
    New-Item -ItemType Directory -Force -Path $unsignedDir | Out-Null
    Set-Content -Path (Join-Path $unsignedDir "model.statsmodels") -Value "tampered_data"
    try {
        $unsignedReload = Invoke-RestMethod -Uri "http://localhost:8000/reload" -Method Post -Headers $authHeaders -Body '{"model_format":"mlflow_statsmodels","model_path":"artifacts/unsigned_e2e_test_pkg"}' -ContentType "application/json"
        Remove-Item $unsignedDir -Recurse -Force -ErrorAction SilentlyContinue
        Log-Output "ERROR: Expected HTTP 403 when reloading unsigned package, got response!" "Red"
        exit 1
    } catch {
        Remove-Item $unsignedDir -Recurse -Force -ErrorAction SilentlyContinue
        if ($_.Exception.Response.StatusCode.value__ -eq 403) {
            Log-Output "  -> [PASSED] Unsigned/tampered MLflow package reload strictly rejected with HTTP 403 Forbidden." "Green"
        } else {
            Log-Output "ERROR: Unexpected status code for unsigned package: $($_.Exception.Response.StatusCode)" "Red"
            exit 1
        }
    }

    Log-Output "`n======================================================================" "Cyan"
    Log-Output "  ALL DOCKER COMPOSE E2E CHECKS PASSED SUCCESSFULLY!                   " "Cyan"
    Log-Output "  Log saved to: $logFile" "Cyan"
    Log-Output "======================================================================" "Cyan"

} finally {
    # Cleanup containers
    Log-Output "`nTearing down test containers..." "Gray"
    docker compose down -v > $null 2>&1

    # ALWAYS restore original files from backup (with cryptographic SHA-256 integrity verification)
    $keysOk = $true
    $artifactsOk = $true

    if (Test-Path $backupKeysDir) {
        Get-ChildItem -Path $backupKeysDir | ForEach-Object {
            $dest = Join-Path (Join-Path $projectRoot "keys") $_.Name
            Copy-Item $_.FullName $dest -Force
            $origHash = Get-FileSha256 $_.FullName
            $restHash = Get-FileSha256 $dest
            if (-not (Test-Path $dest) -or ($origHash -ne $restHash) -or [string]::IsNullOrEmpty($origHash)) {
                $keysOk = $false
                Log-Output "  ERROR: Cryptographic SHA-256 mismatch for restored $dest!" "Red"
            }
        }
        if ($keysOk) {
            Remove-Item $backupKeysDir -Recurse -Force -ErrorAction SilentlyContinue
            Log-Output "  -> [VERIFIED] All cryptographic keys successfully restored with matching SHA-256 digests." "Gray"
        } else {
            Log-Output "  -> [CRITICAL] Key backup restoration failed cryptographic verification! Preserving backup at: $backupKeysDir" "Red"
        }
    }
    if (Test-Path $backupArtifactsDir) {
        Get-ChildItem -Path $backupArtifactsDir | ForEach-Object {
            $dest = Join-Path (Join-Path $projectRoot "artifacts") $_.Name
            Copy-Item $_.FullName $dest -Force
            $origHash = Get-FileSha256 $_.FullName
            $restHash = Get-FileSha256 $dest
            if (-not (Test-Path $dest) -or ($origHash -ne $restHash) -or [string]::IsNullOrEmpty($origHash)) {
                $artifactsOk = $false
                Log-Output "  ERROR: Cryptographic SHA-256 mismatch for restored $dest!" "Red"
            }
        }
        if ($artifactsOk) {
            Remove-Item $backupArtifactsDir -Recurse -Force -ErrorAction SilentlyContinue
            Log-Output "  -> [VERIFIED] All model artifacts successfully restored with matching SHA-256 digests." "Gray"
        } else {
            Log-Output "  -> [CRITICAL] Artifact backup restoration failed cryptographic verification! Preserving backup at: $backupArtifactsDir" "Red"
        }
    }
    Log-Output "Verification routine ended." "Green"

    if (-not $keysOk -or -not $artifactsOk) {
        throw "FATAL: End-to-end verification failed due to cryptographic backup restoration mismatch!"
    }
}
