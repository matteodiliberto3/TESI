#!/usr/bin/env bash
set -euo pipefail

echo "======================================================================"
echo "  MLOps Security Testbed: Docker Compose End-to-End Verification      "
echo "======================================================================"

# 1. Verify Docker CLI and daemon
echo -e "\n[1/6] Verifying Docker CLI and Daemon connectivity..."
if ! docker info >/dev/null 2>&1; then
    echo "ERROR: Docker daemon is not running. Please start Docker and retry." >&2
    exit 1
fi
echo "  -> Docker daemon is ACTIVE."

# 2. Validate Compose configuration
echo -e "\n[2/6] Validating docker-compose specification..."
docker compose config --quiet
echo "  -> docker compose config is valid (0 errors)."

# 3. Clean prior containers
echo -e "\n[3/6] Ensuring clean runtime environment..."
docker compose down -v >/dev/null 2>&1 || true

# 4. Build and start consumer (which triggers producer first)
echo -e "\n[4/6] Building and launching Producer & Consumer services..."
docker compose up --build -d mlops-inference-consumer

# 5. Wait for healthy
echo -e "\n[5/6] Waiting for mlops_inference_consumer healthcheck (depends_on producer)..."
max_attempts=30
attempt=0
healthy=false

while [ "$attempt" -lt "$max_attempts" ]; do
    sleep 2
    attempt=$((attempt + 1))
    status=$(docker inspect --format="{{.State.Health.Status}}" mlops_inference_consumer 2>/dev/null || echo "starting")
    if [ "$status" = "healthy" ]; then
        healthy=true
        echo "  -> mlops_inference_consumer is HEALTHY (attempt $attempt)."
        break
    fi
    echo "  ... waiting for healthcheck (status: '$status', attempt $attempt/$max_attempts)"
done

if [ "$healthy" != "true" ]; then
    echo "ERROR: Service failed to reach healthy status within timeout." >&2
    docker compose logs
    docker compose down -v
    exit 1
fi

# 6. Verify security assertions
echo -e "\n[6/6] Verifying security isolation and inference endpoints..."

# A. Endpoint /health check
health_res=$(curl -s http://localhost:8000/health)
echo "  -> /health response: $health_res"

if ! echo "$health_res" | grep -q '"signature_verified": true'; then
    echo "ERROR: Model signature verification failed!" >&2
    docker compose down -v
    exit 1
fi

if ! echo "$health_res" | grep -q '"private_key_absent_from_consumer": true'; then
    echo "ERROR: Consumer reported private key present! Least Privilege violation." >&2
    docker compose down -v
    exit 1
fi

# B. Direct container probe
if docker compose exec mlops-inference-consumer test -f /app/keys/private_key.pem; then
    echo "ERROR: Container filesystem contains /app/keys/private_key.pem!" >&2
    docker compose down -v
    exit 1
fi
echo "  -> Filesystem isolation confirmed: /app/keys/private_key.pem is strictly ABSENT inside consumer container."

# C. Predict request
predict_res=$(curl -s -X POST http://localhost:8000/predict \
    -H "Content-Type: application/json" \
    -d '{"amount":49.99,"transaction_hour":4.0,"distance_from_home":10.0,"velocity_last_24h":1,"foreign_transaction":0,"high_risk_merchant":0}')
echo "  -> /predict response: $predict_res"

echo -e "\n======================================================================"
echo "  ALL DOCKER COMPOSE E2E CHECKS PASSED SUCCESSFULLY!                   "
echo "======================================================================"

echo "Tearing down test containers..."
docker compose down -v >/dev/null 2>&1
