import os
import sys
import json
import shutil
import subprocess
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

import config
from pipeline.payload_generator import craft_portable_trojan
import numpy as np
import statsmodels.api as sm
import mlflow
import mlflow.statsmodels

CACHE_DIR = ROOT_DIR / ".cache_mlflow_releases"
REPORTS_DIR = config.REPORTS_DIR
ARTIFACTS_DIR = config.ARTIFACTS_DIR / "real_mlflow_cve"
AUDIT_LOG_FILE = REPORTS_DIR / "real_mlflow_release_audit.log"

def create_venv_with_mlflow_version(venv_dir: Path, mlflow_version: str) -> Path:
    """Creates a fast lightweight virtualenv inheriting system packages and installs specific MLflow release."""
    print(f"\n[Environment Setup] Provisioning isolated venv for MLflow {mlflow_version} -> {venv_dir}")
    if not venv_dir.exists():
        subprocess.run(
            [sys.executable, "-m", "venv", "--system-site-packages", str(venv_dir)],
            check=True,
            capture_output=True,
            text=True
        )

    # Determine python & pip executable
    if sys.platform == "win32":
        py_bin = venv_dir / "Scripts" / "python.exe"
        pip_bin = venv_dir / "Scripts" / "pip.exe"
    else:
        py_bin = venv_dir / "bin" / "python"
        pip_bin = venv_dir / "bin" / "pip"

    # Install specific release and child packages using --no-deps to ensure 100% version alignment
    print(f"                     Installing mlflow=={mlflow_version} and aligned child packages via pip...")
    res = subprocess.run(
        [
            str(pip_bin), "install", "--no-deps",
            f"mlflow=={mlflow_version}",
            f"mlflow-skinny=={mlflow_version}",
            f"mlflow-tracing=={mlflow_version}"
        ],
        capture_output=True,
        text=True
    )
    if res.returncode != 0:
        subprocess.run([str(pip_bin), "install", f"mlflow=={mlflow_version}"], check=True, capture_output=True)

    # Verify installed version
    ver_check = subprocess.run(
        [str(py_bin), "-c", "import mlflow; print(mlflow.__version__)"],
        capture_output=True,
        text=True,
        check=True
    )
    installed_ver = ver_check.stdout.strip()
    print(f"                     Verified installed version in venv: {installed_ver}")
    return py_bin

def run_real_release_cve_study(trials: int = 50):
    print("=" * 80)
    print("   EMPIRICAL REPRODUCTION OF CVE-2026-96804 ON OFFICIAL MLFLOW RELEASES")
    print(f"   Target Versions: MLflow 3.12.0 (Unpatched) vs MLflow 3.15.0 (Patched)")
    print(f"   Benchmark Iterations per Release: {trials}")
    print("=" * 80)

    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Train genuine statsmodels model and save as MLflow artifact
    print("\n[Step 1] Training baseline statsmodels Logit model and crafting MLflow artifact...")
    np.random.seed(42)
    X = np.random.randn(100, 2)
    X_const = sm.add_constant(X)
    y = np.random.binomial(1, 0.3, 100)
    model = sm.Logit(y, X_const).fit(disp=False)

    clean_dir = ARTIFACTS_DIR / "clean_mlflow_model"
    tampered_dir = ARTIFACTS_DIR / "tampered_mlflow_model"
    if clean_dir.exists():
        shutil.rmtree(clean_dir)
    if tampered_dir.exists():
        shutil.rmtree(tampered_dir)

    mlflow.statsmodels.save_model(model, str(clean_dir))
    shutil.copytree(clean_dir, tampered_dir)

    # 2. Inject Trojan into model.statsmodels
    tampered_artifact = tampered_dir / "model.statsmodels"
    craft_portable_trojan(model, tampered_artifact, AUDIT_LOG_FILE)
    print(f"[Step 2] Crafted trojanized model artifact -> {tampered_artifact}")

    # 3. Setup environments
    py_3_12 = create_venv_with_mlflow_version(CACHE_DIR / "venv_mlflow_3_12", "3.12.0")
    py_3_15 = create_venv_with_mlflow_version(CACHE_DIR / "venv_mlflow_3_15", "3.15.0")

    worker_script = ARTIFACTS_DIR / "invoke_loader.py"
    worker_code = """
import os
import sys
import time
import json
from pathlib import Path
import mlflow
import mlflow.statsmodels
from mlflow.exceptions import MlflowException

target_dir = sys.argv[1]
trials = int(sys.argv[2]) if len(sys.argv) > 2 else 50
warmups = int(sys.argv[3]) if len(sys.argv) > 3 else 3

print(f"[Worker] MLflow version: {mlflow.__version__} | PID: {os.getpid()}")
print(f"[Worker] Policy: MLFLOW_ALLOW_PICKLE_DESERIALIZATION={os.environ.get('MLFLOW_ALLOW_PICKLE_DESERIALIZATION')}")
print(f"[Worker] Running {warmups} unmeasured warm-up cycles to eliminate JIT/import cold-start distortions...")

# 1. Warm-up cycles (excluded from metrics)
last_status = "UNKNOWN"
for w in range(warmups):
    try:
        loaded = mlflow.statsmodels.load_model(target_dir)
        last_status = "LOADED"
    except MlflowException:
        last_status = "REJECTED"
    except Exception as e:
        print(f"[Worker ERROR in warmup]: {e}")
        sys.exit(1)

# 2. Measured benchmark trials
latencies = []
for i in range(trials):
    t0 = time.perf_counter()
    try:
        loaded = mlflow.statsmodels.load_model(target_dir)
        lat = (time.perf_counter() - t0) * 1000.0
        latencies.append(lat)
        last_status = "LOADED"
    except MlflowException:
        lat = (time.perf_counter() - t0) * 1000.0
        latencies.append(lat)
        last_status = "REJECTED"
    except Exception as e:
        print(f"[Worker ERROR in benchmark trial {i}]: {e}")
        sys.exit(1)

print(f"[Worker Telemetry] Status: {last_status} | Measured Trials: {len(latencies)} (Warmups: {warmups})")
print(f"TELEMETRY_JSON:" + json.dumps({
    "status": last_status,
    "version": mlflow.__version__,
    "warmups": warmups,
    "trials": len(latencies),
    "latencies_ms": latencies
}))
if last_status == "REJECTED":
    sys.exit(2)
else:
    sys.exit(0)
"""
    worker_script.write_text(worker_code, encoding="utf-8")

    results = {}

    def parse_telemetry(stdout_text):
        for line in stdout_text.splitlines():
            if line.startswith("TELEMETRY_JSON:"):
                return json.loads(line.replace("TELEMETRY_JSON:", "").strip())
        return None

    # =========================================================================
    # Test 1: Real MLflow 3.12.0 with MLFLOW_ALLOW_PICKLE_DESERIALIZATION=false
    # =========================================================================
    print("\n" + "-" * 75)
    print(f"--- [EXPERIMENT 1] Official MLflow 3.12.0 (Policy: false, {trials} trials) ---")
    print("-" * 75)
    if AUDIT_LOG_FILE.exists():
        AUDIT_LOG_FILE.unlink()

    env_v1 = os.environ.copy()
    env_v1["MLFLOW_ALLOW_PICKLE_DESERIALIZATION"] = "false"
    env_v1["PYTHONPATH"] = str(ROOT_DIR)

    res_v1 = subprocess.run(
        [str(py_3_12), str(worker_script), str(tampered_dir), str(trials)],
        env=env_v1,
        capture_output=True,
        text=True
    )
    print(f"Stdout:\n{res_v1.stdout.strip()}")
    if res_v1.stderr.strip():
        print(f"Stderr:\n{res_v1.stderr.strip()}")

    v1_probe_executed = AUDIT_LOG_FILE.exists()
    v1_trace = AUDIT_LOG_FILE.read_text(encoding="utf-8").strip() if v1_probe_executed else None
    assert v1_probe_executed, "FATAL: MLflow 3.12.0 failed to execute trojan despite policy=false!"
    print(f"  -> Outcome: POLICY BYPASSED in official MLflow 3.12.0 release!")
    print(f"  -> In-Process Audit Trace: {v1_trace}")

    telem_v1 = parse_telemetry(res_v1.stdout)
    v1_lats = telem_v1.get("latencies_ms", []) if telem_v1 else []

    def compute_stats(lats):
        if not lats:
            return None
        arr = np.array(lats, dtype=np.float64)
        n = len(arr)
        sorted_arr = np.sort(arr)
        trim_idx = int(0.1 * n) if n >= 10 else 0
        trimmed = sorted_arr[trim_idx:n - trim_idx] if trim_idx > 0 else sorted_arr

        return {
            "trials": n,
            "warmup_cycles_excluded": 3,
            "mean_ms": round(float(np.mean(arr)), 3),
            "trimmed_mean_10pct_ms": round(float(np.mean(trimmed)), 3),
            "median_ms": round(float(np.percentile(arr, 50)), 3),
            "iqr_ms": round(float(np.percentile(arr, 75) - np.percentile(arr, 25)), 3),
            "p95_ms": round(float(np.percentile(arr, 95)), 3),
            "p99_ms": round(float(np.percentile(arr, 99)), 3),
            "min_ms": round(float(np.min(arr)), 3),
            "max_ms": round(float(np.max(arr)), 3),
            "std_ms": round(float(np.std(arr)), 3)
        }

    results["MLflow_3_12_0_Official_Release"] = {
        "version": "3.12.0",
        "policy": "false",
        "return_code": res_v1.returncode,
        "policy_bypassed": True,
        "arbitrary_code_executed": True,
        "trace": v1_trace,
        "status": "VULNERABILITY_CONFIRMED",
        "semantic_operation": "Arbitrary Code Execution (Full Deserialization + Payload Run)",
        "benchmark": compute_stats(v1_lats)
    }

    # =========================================================================
    # Test 2: Real MLflow 3.15.0 with MLFLOW_ALLOW_PICKLE_DESERIALIZATION=false
    # =========================================================================
    print("\n" + "-" * 75)
    print(f"--- [EXPERIMENT 2] Official MLflow 3.15.0 (Policy: false, {trials} trials) ---")
    print("-" * 75)
    if AUDIT_LOG_FILE.exists():
        AUDIT_LOG_FILE.unlink()

    env_v2 = os.environ.copy()
    env_v2["MLFLOW_ALLOW_PICKLE_DESERIALIZATION"] = "false"
    env_v2["PYTHONPATH"] = str(ROOT_DIR)

    res_v2 = subprocess.run(
        [str(py_3_15), str(worker_script), str(tampered_dir), str(trials)],
        env=env_v2,
        capture_output=True,
        text=True
    )
    print(f"Stdout:\n{res_v2.stdout.strip()}")
    if res_v2.stderr.strip():
        print(f"Stderr:\n{res_v2.stderr.strip()}")

    v2_probe_executed = AUDIT_LOG_FILE.exists()
    assert res_v2.returncode == 2, f"FATAL: MLflow 3.15.0 should exit with code 2 (MlflowException), got {res_v2.returncode}"
    assert not v2_probe_executed, "FATAL: MLflow 3.15.0 executed the trojan probe when policy was false!"
    print(f"  -> Outcome: DESERIALIZATION REJECTED by official MLflow 3.15.0 patch!")
    print(f"  -> Probe Executed: {v2_probe_executed}")

    telem_v2 = parse_telemetry(res_v2.stdout)
    v2_lats = telem_v2.get("latencies_ms", []) if telem_v2 else []

    results["MLflow_3_15_0_Official_Release"] = {
        "version": "3.15.0",
        "policy": "false",
        "return_code": res_v2.returncode,
        "policy_bypassed": False,
        "arbitrary_code_executed": False,
        "trace": None,
        "status": "PATCH_CONFIRMED",
        "semantic_operation": "Fast-Fail Policy Interception (MlflowException Raised Pre-Unpickler)",
        "benchmark": compute_stats(v2_lats)
    }

    results["methodology_metadata"] = {
        "scientific_interpretation": "Timing differences reflect fundamentally distinct computational semantics (full deserialization + payload execution vs pre-deserialization policy rejection), not an algorithmic performance comparison.",
        "warmup_handling": "3 unmeasured warm-up iterations were executed before timing to prime module imports and prevent cold-start distortion."
    }

    # Export report
    out_file = REPORTS_DIR / "cve_2026_96804_real_releases_study.json"
    out_file.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print("\n" + "=" * 80)
    print(f"[✓] Official MLflow Releases Study Complete! Saved to: {out_file}")
    print("=" * 80)
    return results

if __name__ == "__main__":
    trials_arg = int(sys.argv[1]) if len(sys.argv) > 1 else 50
    run_real_release_cve_study(trials=trials_arg)
