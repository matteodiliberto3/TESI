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

# Ephemeral secret token generation for dynamic reload authentication
if [ -z "${MLOPS_ADMIN_TOKEN:-}" ]; then
    export MLOPS_ADMIN_TOKEN=$(python3 -c 'import secrets; print(secrets.token_hex(16))' 2>/dev/null || openssl rand -hex 16 2>/dev/null || echo "e2e_ephemeral_token_4f9a1b2c3d4e5f6")
    log "  -> Ephemeral MLOPS_ADMIN_TOKEN provisioned for session: ${MLOPS_ADMIN_TOKEN:0:6}***"
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

compute_sha256() {
    local target="$1"
    if [ ! -f "$target" ]; then
        echo ""
        return
    fi
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$target" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$target" | awk '{print $1}'
    else
        python3 -c "import hashlib, sys; print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())" "$target" 2>/dev/null || echo ""
    fi
}

cleanup() {
    log "\nTearing down test containers..."
    docker compose down -v >/dev/null 2>&1 || true

    log "Restoring original keys and artifacts with cryptographic SHA-256 integrity verification..."
    local all_keys_ok=true
    local all_artifacts_ok=true

    # ALWAYS restore original keys and verify restoration via SHA-256
    if [ -d "$BACKUP_KEYS_DIR" ]; then
        for f in "$BACKUP_KEYS_DIR"/*; do
            if [ -f "$f" ]; then
                fname=$(basename "$f")
                dest="keys/$fname"
                cp -p "$f" "$dest" 2>/dev/null || all_keys_ok=false
                orig_hash=$(compute_sha256 "$f")
                rest_hash=$(compute_sha256 "$dest")
                if [ -z "$orig_hash" ] || [ "$orig_hash" != "$rest_hash" ]; then
                    log "  ERROR: Cryptographic SHA-256 mismatch for restored $dest!"
                    log "         Expected: $orig_hash"
                    log "         Observed: $rest_hash"
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
            log "  -> [VERIFIED] All cryptographic keys successfully restored with matching SHA-256 digests."
        else
            log "  -> [CRITICAL] Key backup restoration failed cryptographic verification! Preserving backup at $BACKUP_KEYS_DIR"
        fi
    fi

    # ALWAYS restore original artifacts and verify restoration via SHA-256
    if [ -d "$BACKUP_ARTIFACTS_DIR" ]; then
        for f in "$BACKUP_ARTIFACTS_DIR"/*; do
            if [ -f "$f" ]; then
                fname=$(basename "$f")
                dest="artifacts/$fname"
                cp -p "$f" "$dest" 2>/dev/null || all_artifacts_ok=false
                orig_hash=$(compute_sha256 "$f")
                rest_hash=$(compute_sha256 "$dest")
                if [ -z "$orig_hash" ] || [ "$orig_hash" != "$rest_hash" ]; then
                    log "  ERROR: Cryptographic SHA-256 mismatch for restored $dest!"
                    log "         Expected: $orig_hash"
                    log "         Observed: $rest_hash"
                    all_artifacts_ok=false
                else
                    chmod 644 "$dest" 2>/dev/null || true
                fi
            fi
        done
        if [ "$all_artifacts_ok" = "true" ]; then
            rm -rf "$BACKUP_ARTIFACTS_DIR" 2>/dev/null || true
            log "  -> [VERIFIED] All model artifacts successfully restored with matching SHA-256 digests."
        else
            log "  -> [CRITICAL] Artifact backup restoration failed cryptographic verification! Preserving backup at $BACKUP_ARTIFACTS_DIR"
        fi
    fi

    # Enforce Least-Privilege directory permissions
    chmod 755 data_storage feature_store_storage artifacts reports keys 2>/dev/null || true
    log "Verification routine ended."

    if [ "$all_keys_ok" != "true" ] || [ "$all_artifacts_ok" != "true" ]; then
        log "FATAL: End-to-end routine failed due to cryptographic backup restoration mismatch!"
        exit 1
    fi
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
health_res=$(curl -fsS http://localhost:8000/health)
log "  -> /health response: $health_res"

if ! printf '%s' "$health_res" | python3 -c '
import json, sys
try:
    data = json.load(sys.stdin)
    valid = (
        data.get("status") == "HEALTHY" and
        data.get("signature_verified") is True and
        data.get("private_key_absent_from_consumer") is True
    )
    sys.exit(0 if valid else 1)
except Exception:
    sys.exit(1)
'; then
    log "ERROR: Health or security verification failed! Response: $health_res"
    exit 1
fi
log "  -> [PASSED] Consumer cryptographically verified model artifact signature via public key."
log "  -> [PASSED] Consumer verified absence of private key in its execution environment."

# C. Direct container probe
if docker compose exec mlops-inference-consumer test -f /app/keys/private_key.pem; then
    log "ERROR: Container filesystem contains /app/keys/private_key.pem!"
    exit 1
fi
log "  -> [PASSED] Filesystem isolation confirmed: /app/keys/private_key.pem is strictly ABSENT inside consumer container."

# D. Predict request
predict_res=$(curl -fsS -X POST http://localhost:8000/predict \
    -H "Content-Type: application/json" \
    -d '{"amount":49.99,"transaction_hour":4.0,"distance_from_home":10.0,"velocity_last_24h":1,"foreign_transaction":0,"high_risk_merchant":0}')
log "  -> /predict response: $predict_res"

if ! printf '%s' "$predict_res" | python3 -c '
import json, sys
try:
    data = json.load(sys.stdin)
    assert "is_fraud" in data and "fraud_probability" in data
    assert data["is_fraud"] in [0, 1]
    sys.exit(0)
except Exception:
    sys.exit(1)
'; then
    log "ERROR: Prediction response failed or invalid! Response: $predict_res"
    exit 1
fi
log "  -> [PASSED] HTTP inference prediction served successfully by unprivileged consumer."

# E. Static configuration audit: ensure zero hardcoded secrets in docker-compose.yml
log "\n[Security Audit] Auditing docker-compose.yml for hardcoded secrets..."
if grep -E 'MLOPS_ADMIN_TOKEN=[a-zA-Z0-9_-]{4,}' docker-compose.yml | grep -v '\${' >/dev/null 2>&1; then
    log "ERROR: Hardcoded plaintext MLOPS_ADMIN_TOKEN detected in docker-compose.yml!"
    exit 1
fi
log "  -> [PASSED] docker-compose.yml verified: zero hardcoded secrets or tokens."

# F. Dynamic /reload security validation
log "\n[Endpoint Security] Testing authenticated model hot-reloading (/reload)..."

# F.1 Unauthorized without Bearer token
reload_status_no_auth=$(curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:8000/reload \
    -H "Content-Type: application/json" \
    -d '{"model_format":"safetensors","model_path":"artifacts/model_secure.safetensors"}')
log "  -> /reload without token returned HTTP $reload_status_no_auth"
if [ "$reload_status_no_auth" != "401" ]; then
    log "ERROR: Expected HTTP 401 when calling /reload without Authorization header, got $reload_status_no_auth"
    exit 1
fi
log "  -> [PASSED] Unauthorized /reload without Bearer token strictly rejected with HTTP 401."

# F.2 Unauthorized with wrong Bearer token
reload_status_bad_auth=$(curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:8000/reload \
    -H "Authorization: Bearer invalid_secret_token_value_attempt" \
    -H "Content-Type: application/json" \
    -d '{"model_format":"safetensors","model_path":"artifacts/model_secure.safetensors"}')
log "  -> /reload with bad token returned HTTP $reload_status_bad_auth"
if [ "$reload_status_bad_auth" != "401" ]; then
    log "ERROR: Expected HTTP 401 when calling /reload with invalid token, got $reload_status_bad_auth"
    exit 1
fi
log "  -> [PASSED] /reload with invalid Bearer token strictly rejected with HTTP 401."

# F.3 Authorized reload with valid ephemeral token (safetensors format)
reload_res=$(curl -fsS -X POST http://localhost:8000/reload \
    -H "Authorization: Bearer $MLOPS_ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"model_format":"safetensors","model_path":"artifacts/model_secure.safetensors"}')
log "  -> /reload with valid token response: $reload_res"
if ! printf '%s' "$reload_res" | python3 -c '
import json, sys
data = json.load(sys.stdin)
assert data.get("status") == "RELOADED"
assert data.get("mode") == "safetensors"
sys.exit(0)
'; then
    log "ERROR: /reload with valid token failed to reload safetensors model!"
    exit 1
fi
log "  -> [PASSED] Dynamic authenticated /reload successfully transitioned model to safetensors."

# F.4 Negative test: Insecure pickle reload without override blocked fail-closed
reload_tampered_status=$(curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:8000/reload \
    -H "Authorization: Bearer $MLOPS_ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"model_format":"insecure_pickle","model_path":"artifacts/model_clean.pkl"}')
log "  -> /reload insecure_pickle without allow flag returned HTTP $reload_tampered_status"
if [ "$reload_tampered_status" != "403" ]; then
    log "ERROR: Expected HTTP 403 when reloading insecure pickle without override, got $reload_tampered_status"
    exit 1
fi
log "  -> [PASSED] Insecure pickle reload fail-closed and returned HTTP 403 Forbidden."

# F.5 Negative test: Unsigned / tampered model package rejected fail-closed
mkdir -p artifacts/unsigned_e2e_test_pkg
echo 'tampered_data' > artifacts/unsigned_e2e_test_pkg/model.statsmodels
reload_unsigned_status=$(curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:8000/reload \
    -H "Authorization: Bearer $MLOPS_ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"model_format":"mlflow_statsmodels","model_path":"artifacts/unsigned_e2e_test_pkg"}')
rm -rf artifacts/unsigned_e2e_test_pkg
log "  -> /reload unsigned mlflow package returned HTTP $reload_unsigned_status"
if [ "$reload_unsigned_status" != "403" ]; then
    log "ERROR: Expected HTTP 403 when reloading unsigned package, got $reload_unsigned_status"
    exit 1
fi
log "  -> [PASSED] Unsigned/tampered MLflow package reload strictly rejected with HTTP 403 Forbidden."

log "\n======================================================================"
log "  ALL DOCKER COMPOSE E2E CHECKS PASSED SUCCESSFULLY!                   "
log "  Log saved to: $LOG_FILE"
log "======================================================================"
