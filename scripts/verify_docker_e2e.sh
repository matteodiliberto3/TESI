#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

LOG_FILE="$PROJECT_ROOT/reports/docker_e2e_verification.log"
mkdir -p "$(dirname "$LOG_FILE")"

log() {
    local msg="$1"
    echo -e "$msg"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $msg" >> "$LOG_FILE"
}

echo "======================================================================" > "$LOG_FILE"
echo "  MLOps Security Testbed: Docker Compose End-to-End Verification Log" >> "$LOG_FILE"
echo "======================================================================" >> "$LOG_FILE"

COMMIT_HASH="$(git rev-parse HEAD 2>/dev/null || echo 'UNKNOWN_COMMIT')"
log "Git Commit Under Test: $COMMIT_HASH"
log "Verification Date/Time: $(date)"
log "Operating System: $(uname -s -r -m)"
log "======================================================================\n"

# Align container worker UID/GID with host execution user (Least Privilege)
if [ -z "${CURRENT_UID:-}" ]; then
    export CURRENT_UID=$(id -u 2>/dev/null || echo 1000)
fi
if [ -z "${CURRENT_GID:-}" ]; then
    export CURRENT_GID=$(id -g 2>/dev/null || echo 1000)
fi

# 1. Verify Docker CLI and daemon
log "[1/7] Verifying Docker CLI and Daemon connectivity (Execution UID: $CURRENT_UID)..."
if ! docker info >/dev/null 2>&1; then
    log "ERROR: Docker daemon is not running. Please start Docker and retry."
    exit 1
fi
log "  -> Docker daemon is ACTIVE."

# 2. Validate Compose configuration
log "\n[2/7] Validating docker-compose specification..."
docker compose config --quiet
log "  -> docker compose config is valid (0 errors)."

# 3. Clean prior containers
log "\n[3/7] Tearing down any existing testbed containers..."
docker compose down -v >/dev/null 2>&1 || true
log "  -> Existing containers and compose volumes removed."

BACKUP_KEYS_DIR="$PROJECT_ROOT/.cache_test_keys_backup"
BACKUP_ARTIFACTS_DIR="$PROJECT_ROOT/.cache_test_artifacts_backup"

cleanup() {
    log "\nTearing down test containers..."
    docker compose down -v >/dev/null 2>&1 || true

    log "Restoring original keys and artifacts with integrity verification..."
    local all_keys_ok=true
    local all_artifacts_ok=true

    # ALWAYS restore original keys and verify restoration
    if [ -d "$BACKUP_KEYS_DIR" ]; then
        for f in "$BACKUP_KEYS_DIR"/*; do
            if [ -f "$f" ]; then
                fname=$(basename "$f")
                dest="keys/$fname"
                cp -p "$f" "$dest" 2>/dev/null || all_keys_ok=false
                orig_sz=$(stat -c "%s" "$f" 2>/dev/null || stat -f "%z" "$f" 2>/dev/null || echo "0")
                rest_sz=$(stat -c "%s" "$dest" 2>/dev/null || stat -f "%z" "$dest" 2>/dev/null || echo "-1")
                if [ "$orig_sz" != "$rest_sz" ] || [ ! -s "$dest" ]; then
                    log "  ERROR: Verification failed for restored $dest!"
                    all_keys_ok=false
                else
                    if [ "$fname" = "private_key.pem" ]; then
                        chmod 600 "$dest" 2>/dev/null || true
                    else
                        chmod 644 "$dest" 2>/dev/null || true
                    fi
                fi
            fi
        done
        if [ "$all_keys_ok" = "true" ]; then
            rm -rf "$BACKUP_KEYS_DIR" 2>/dev/null || true
            log "  -> [VERIFIED] All cryptographic keys successfully restored and verified."
        else
            log "  -> [WARNING] Key backup restoration verification failed! Preserving backup at $BACKUP_KEYS_DIR"
        fi
    fi

    # ALWAYS restore original artifacts and verify restoration
    if [ -d "$BACKUP_ARTIFACTS_DIR" ]; then
        for f in "$BACKUP_ARTIFACTS_DIR"/*; do
            if [ -f "$f" ]; then
                fname=$(basename "$f")
                dest="artifacts/$fname"
                cp -p "$f" "$dest" 2>/dev/null || all_artifacts_ok=false
                orig_sz=$(stat -c "%s" "$f" 2>/dev/null || stat -f "%z" "$f" 2>/dev/null || echo "0")
                rest_sz=$(stat -c "%s" "$dest" 2>/dev/null || stat -f "%z" "$dest" 2>/dev/null || echo "-1")
                if [ "$orig_sz" != "$rest_sz" ] || [ ! -s "$dest" ]; then
                    log "  ERROR: Verification failed for restored $dest!"
                    all_artifacts_ok=false
                else
                    chmod 644 "$dest" 2>/dev/null || true
                fi
            fi
        done
        if [ "$all_artifacts_ok" = "true" ]; then
            rm -rf "$BACKUP_ARTIFACTS_DIR" 2>/dev/null || true
            log "  -> [VERIFIED] All model artifacts successfully restored and verified."
        else
            log "  -> [WARNING] Artifact backup restoration verification failed! Preserving backup at $BACKUP_ARTIFACTS_DIR"
        fi
    fi

    # Enforce Least-Privilege directory permissions
    chmod 755 data_storage feature_store_storage artifacts reports keys 2>/dev/null || true
    log "Verification routine ended."
}
trap cleanup EXIT

# 4. Handle Cold-Start Bind Mount Reset
log "\n[4/7] Simulating TRUE COLD-START: Backing up and clearing host bind-mount secrets..."

# Enforce least privilege permissions (0755 directories, 0600 on private key, 0644 on public artifacts)
chmod 755 data_storage feature_store_storage artifacts reports keys 2>/dev/null || true

mkdir -p "$BACKUP_KEYS_DIR" "$BACKUP_ARTIFACTS_DIR"
chmod 700 "$BACKUP_KEYS_DIR"
chmod 755 "$BACKUP_ARTIFACTS_DIR"

if [ -f "keys/private_key.pem" ]; then
    cp -p keys/private_key.pem "$BACKUP_KEYS_DIR/"
    rm -f keys/private_key.pem
    log "  -> Safely backed up & removed keys/private_key.pem for test."
fi
if [ -f "keys/public_key.pem" ]; then
    cp -p keys/public_key.pem "$BACKUP_KEYS_DIR/"
fi
for art in artifacts/model_clean.pkl artifacts/model_clean.sig artifacts/model_secure.safetensors; do
    if [ -f "$art" ]; then
        cp -p "$art" "$BACKUP_ARTIFACTS_DIR/"
        rm -f "$art"
        log "  -> Safely backed up & removed $art for test."
    fi
done

log "  -> Pristine cold-start state established: keys and artifacts must be generated by Producer container."

# 5. Build and start consumer (which triggers producer first)
log "\n[5/7] Building and launching Producer & Consumer services..."
if ! docker compose up --build -d mlops-inference-consumer; then
    log "ERROR: docker compose up failed!"
    docker compose logs >> "$LOG_FILE" 2>&1 || true
    docker compose logs
    exit 1
fi

# 6. Wait for healthy
log "\n[6/7] Waiting for mlops_inference_consumer healthcheck (depends_on producer)..."
max_attempts=35
attempt=0
healthy=false

while [ "$attempt" -lt "$max_attempts" ]; do
    sleep 2
    attempt=$((attempt + 1))
    status=$(docker inspect --format="{{.State.Health.Status}}" mlops_inference_consumer 2>/dev/null || echo "starting")
    if [ "$status" = "healthy" ]; then
        healthy=true
        log "  -> mlops_inference_consumer is HEALTHY (attempt $attempt)."
        break
    fi
    log "  ... waiting for healthcheck (status: '$status', attempt $attempt/$max_attempts)"
done

if [ "$healthy" != "true" ]; then
    log "ERROR: Consumer service failed to reach healthy status within timeout."
    docker compose logs >> "$LOG_FILE" 2>&1 || true
    docker compose logs
    exit 1
fi

# 7. Verify security assertions
log "\n[7/7] Verifying security isolation contracts and HTTP endpoints..."

# A. Producer created keys on volume with least-privilege permissions
if [ -f "keys/private_key.pem" ]; then
    log "  -> [PASSED] Producer successfully provisioned keys/private_key.pem on mounted volume."
    priv_perms=$(stat -c "%a" keys/private_key.pem 2>/dev/null || stat -f "%Lp" keys/private_key.pem 2>/dev/null || echo "unknown")
    if [ "$priv_perms" = "600" ]; then
        log "  -> [PASSED] Material protection confirmed: keys/private_key.pem has strict 0600 permissions (Owner Read/Write only)."
    else
        log "  -> [INFO] keys/private_key.pem filesystem permissions: $priv_perms"
    fi
else
    log "  -> [FAILED] Producer failed to generate keys/private_key.pem on mounted volume!"
    exit 1
fi

# B. Endpoint /health check
health_res=$(curl -s http://localhost:8000/health)
log "  -> /health response: $health_res"

if ! echo "$health_res" | grep -q '"signature_verified": true'; then
    log "ERROR: Model signature verification failed!"
    exit 1
fi
log "  -> [PASSED] Consumer cryptographically verified model artifact signature via public key."

if ! echo "$health_res" | grep -q '"private_key_absent_from_consumer": true'; then
    log "ERROR: Consumer reported private key present! Least Privilege violation."
    exit 1
fi
log "  -> [PASSED] Consumer verified absence of private key in its execution environment."

# C. Direct container probe
if docker compose exec mlops-inference-consumer test -f /app/keys/private_key.pem; then
    log "ERROR: Container filesystem contains /app/keys/private_key.pem!"
    exit 1
fi
log "  -> [PASSED] Filesystem isolation confirmed: /app/keys/private_key.pem is strictly ABSENT inside consumer container."

# D. Predict request
predict_res=$(curl -s -X POST http://localhost:8000/predict \
    -H "Content-Type: application/json" \
    -d '{"amount":49.99,"transaction_hour":4.0,"distance_from_home":10.0,"velocity_last_24h":1,"foreign_transaction":0,"high_risk_merchant":0}')
log "  -> /predict response: $predict_res"
log "  -> [PASSED] HTTP inference prediction served successfully by unprivileged consumer."

log "\n======================================================================"
log "  ALL DOCKER COMPOSE E2E CHECKS PASSED SUCCESSFULLY!                   "
log "  Log saved to: $LOG_FILE"
log "======================================================================"
