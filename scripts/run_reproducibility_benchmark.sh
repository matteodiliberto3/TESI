#!/usr/bin/env bash
# ==============================================================================
# Full Scientific Reproducibility Benchmark Runner
# Executes the full battery of experiments (Exp 1 to Exp 6 + 30-seed Causal Ablation)
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${PROJECT_ROOT}"

echo "=============================================================================="
echo "    MLOps Security Testbed: Full Reproducibility Benchmark Runner"
echo "    Executing: Baseline, Exp 1-6, and 30-Seed Causal Ablation Study"
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

# Execute complete experimental battery
echo "[*] Launching Master Experiment Runner with --full flag..."
"${PY_BIN}" experiments/run_all_experiments.py --full

# Run test suite to verify artifact schema and invariant compliance
echo "[*] Verifying artifact integrity and statistical schemas with pytest..."
"${PY_BIN}" -m pytest tests/ -v

echo "=============================================================================="
echo "[+] REPRODUCIBILITY BENCHMARK COMPLETE"
echo "    Generated Ground Truth Artefacts:"
echo "    - reports/causal_ablation_results.json"
echo "    - reports/CAUSAL_ABLATION_REPORT.md"
echo "    - reports/EXPERIMENT_RESULTS.md"
echo "    - reports/evasion_results.json"
echo "=============================================================================="
