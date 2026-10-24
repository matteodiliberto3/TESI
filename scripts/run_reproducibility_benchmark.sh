#!/usr/bin/env bash
# ==============================================================================
# Full Scientific Reproducibility Benchmark Runner
# Executes the full battery of experiments (Exp 1 to Exp 6 + 30-seed Causal Ablation)
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SEEDS="${1:-30}"

cd "${PROJECT_ROOT}"

echo "=============================================================================="
echo "    MLOps Security Testbed: Full Reproducibility Benchmark Runner"
echo "    Executing: Baseline, Exp 1-6, and Causal Ablation Study (${SEEDS} Seeds)"
echo "=============================================================================="

# Detect Python interpreter
if command -v python3 &>/dev/null; then
    PY_BIN="python3"
elif command -v python &>/dev/null; then
    PY_BIN="python"
else
    echo "[-] Error: Python is not installed or not in PATH."
    exit 1
fi

echo "[*] Python Environment: $("${PY_BIN}" --version)"

# Ensure directories exist
mkdir -p data_storage feature_store_storage artifacts reports keys
chmod 755 data_storage feature_store_storage artifacts reports keys 2>/dev/null || true

# Provision ephemeral cryptographic signing keys if absent on clean runner checkout
if [ ! -f "keys/private_key.pem" ]; then
    echo "[*] Provisioning ephemeral RSA keypair for experiment artifact signing..."
    "${PY_BIN}" pipeline/crypto_signer.py --generate-keys
fi

# Execute complete experimental battery
echo "[*] Launching Master Experiment Runner with --full --seeds ${SEEDS}..."
"${PY_BIN}" experiments/run_all_experiments.py --full --seeds "${SEEDS}"

# Run test suite to verify artifact schema and invariant compliance
echo "[*] Verifying artifact integrity and statistical schemas with pytest..."
"${PY_BIN}" -m pytest tests/ -v

# Run numerical invariant and boundary verification
echo "[*] Verifying numerical bounds against Chapter 5 ground truth..."
"${PY_BIN}" scripts/verify_reproducibility_results.py

echo "=============================================================================="
echo "[+] REPRODUCIBILITY BENCHMARK COMPLETE AND NUMERICALLY VERIFIED"
echo "    Generated Ground Truth Artefacts:"
echo "    - reports/causal_ablation_results.json"
echo "    - reports/CAUSAL_ABLATION_REPORT.md"
echo "    - reports/EXPERIMENT_RESULTS.md"
echo "    - reports/evasion_results.json"
echo "    - reports/system_benchmarks.json"
echo "=============================================================================="
