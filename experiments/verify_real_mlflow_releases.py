import os
import sys
import json
import shutil
import platform
import subprocess
import time
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

def create_venv_with_mlflow_version(venv_dir: Path, mlflow_version: str) -> tuple[Path, dict]:
    """
    Creates an independent virtual environment without inheriting global packages,
    installs version-pinned dependencies, runs pip check, and collects environment metadata.
    Addresses FASE C.1 of Scientific Audit.
    """
    print(f"\n[Environment Setup] Provisioning clean isolated venv for MLflow {mlflow_version} -> {venv_dir}")

    # Determine python & pip executable paths
    if sys.platform == "win32":
        py_bin = venv_dir / "Scripts" / "python.exe"
        pip_bin = venv_dir / "Scripts" / "pip.exe"
    else:
        py_bin = venv_dir / "bin" / "python"
        pip_bin = venv_dir / "bin" / "pip"

    needs_rebuild = False
    if not venv_dir.exists() or not py_bin.exists():
        needs_rebuild = True
    else:
        # Check if pyvenv.cfg has include-system-site-packages = true (legacy defect)
        cfg_file = venv_dir / "pyvenv.cfg"
        if cfg_file.exists():
            cfg_text = cfg_file.read_text(encoding="utf-8")
            if "include-system-site-packages = true" in cfg_text.lower():
                print("                     Removing legacy venv with system-site-packages inheritance...")
                shutil.rmtree(venv_dir, ignore_errors=True)
                needs_rebuild = True

    if needs_rebuild:
        # Clean isolated venv: NO --system-site-packages!
        subprocess.run(
            [sys.executable, "-m", "venv", str(venv_dir)],
            check=True,
            capture_output=True,
            text=True
        )

        print(f"                     Upgrading pip and installing dependencies for MLflow {mlflow_version}...")
        # Core pinned requirements needed by statsmodels loader
        pkgs = [
            "pip>=24.0",
            "numpy>=1.26.0,<3.0.0",
            "scipy>=1.13.0,<2.0.0",
            "pandas>=2.2.0,<3.1.0",
            "statsmodels>=0.14.0,<1.0.0",
            "cloudpickle>=3.0.0,<4.0.0",
            "pyyaml>=6.0,<7.0.0",
            f"mlflow=={mlflow_version}"
        ]
        install_res = subprocess.run(
            [str(pip_bin), "install", "--prefer-binary"] + pkgs,
            capture_output=True,
            text=True
        )
        if install_res.returncode != 0:
            print(f"ERROR installing packages in venv: {install_res.stderr}")
            raise RuntimeError(f"Pip installation failed for MLflow {mlflow_version}: {install_res.stderr}")

    # Verify pip check (consistency check) - MUST fail closed
    print("                     Running pip check for dependency consistency...")
    pip_check_res = subprocess.run(
        [str(pip_bin), "check"],
        capture_output=True,
        text=True
    )
    pip_check_ok = (pip_check_res.returncode == 0)
    pip_check_output = pip_check_res.stdout.strip() if pip_check_ok else pip_check_res.stderr.strip()
    if not pip_check_ok:
        raise RuntimeError(
            f"FATAL: Dependency consistency check 'pip check' failed for MLflow {mlflow_version}:\n{pip_check_output}"
        )

    # Collect environment metadata and enforce MLflow version match
    ver_check = subprocess.run(
        [str(py_bin), "-c", "import mlflow; print(mlflow.__version__)"],
        capture_output=True,
        text=True,
        check=True
    )
    installed_ver = ver_check.stdout.strip()
    if installed_ver != mlflow_version:
        raise RuntimeError(
            f"FATAL: Installed MLflow version '{installed_ver}' does not match requested version '{mlflow_version}'"
        )
    print(f"                     Verified installed MLflow version: {installed_ver}")

    pip_list_res = subprocess.run(
        [str(pip_bin), "list", "--format=json"],
        capture_output=True,
        text=True
    )
    try:
        installed_packages = json.loads(pip_list_res.stdout)
    except Exception:
        installed_packages = []

    packages_map = {p["name"]: p["version"] for p in installed_packages if "name" in p and "version" in p}

    env_metadata = {
        "mlflow_version_requested": mlflow_version,
        "mlflow_version_verified": installed_ver,
        "python_version": sys.version,
        "platform": platform.platform(),
        "executable": str(py_bin),
        "pip_check_passed": pip_check_ok,
        "pip_check_output": pip_check_output or "No broken requirements found.",
        "isolated_venv": True,
        "system_site_packages_inherited": False,
        "installed_packages_count": len(installed_packages),
        "installed_packages": installed_packages,
        "installed_packages_map": packages_map
    }

    return py_bin, env_metadata

def run_real_release_cve_study(trials: int = 50):
    run_type = "FULL_SCIENTIFIC_STUDY" if trials >= 50 else "CI_SMOKE_TEST"
    print("=" * 80)
    print("   EMPIRICAL REPRODUCTION OF CVE-2026-96804 ON OFFICIAL MLFLOW RELEASES")
    print(f"   Target Versions: MLflow 3.12.0 (Unpatched) vs MLflow 3.15.0 (Patched)")
    print(f"   Protocol Mode: {run_type} ({trials} trials per release)")
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

    # 3. Setup isolated environments
    py_3_12, meta_3_12 = create_venv_with_mlflow_version(CACHE_DIR / "venv_mlflow_3_12", "3.12.0")
    py_3_15, meta_3_15 = create_venv_with_mlflow_version(CACHE_DIR / "venv_mlflow_3_15", "3.15.0")

    worker_script = ARTIFACTS_DIR / "invoke_loader.py"
    worker_code = """import os
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
audit_log_path = Path(sys.argv[4]) if len(sys.argv) > 4 else Path("audit.log")

print(f"[Worker] MLflow version: {mlflow.__version__} | PID: {os.getpid()}")
print(f"[Worker] Policy: MLFLOW_ALLOW_PICKLE_DESERIALIZATION={os.environ.get('MLFLOW_ALLOW_PICKLE_DESERIALIZATION')}")
print(f"[Worker] Running {warmups} unmeasured warm-up cycles to eliminate JIT/import cold-start distortions...")

# 1. Warm-up cycles (excluded from metrics)
for w in range(warmups):
    if audit_log_path.exists():
        audit_log_path.unlink()
    try:
        _ = mlflow.statsmodels.load_model(target_dir)
    except MlflowException:
        pass
    except Exception as e:
        print(f"[Worker ERROR in warmup {w}]: {e}")
        sys.exit(1)
    if audit_log_path.exists():
        audit_log_path.unlink()

# 2. Measured benchmark trials with individual validation (FASE C.2)
trials_detail = []
for i in range(trials):
    if audit_log_path.exists():
        audit_log_path.unlink()

    t0 = time.perf_counter()
    trial_record = {
        "trial_index": i + 1,
        "latency_ms": 0.0,
        "status": "UNKNOWN",
        "audit_probe_executed": False,
        "policy_exception_caught": False,
        "exception_type": None,
        "exception_detail": None,
        "audit_trace": None
    }

    try:
        loaded = mlflow.statsmodels.load_model(target_dir)
        lat = (time.perf_counter() - t0) * 1000.0
        trial_record["latency_ms"] = round(lat, 4)
        trial_record["status"] = "LOADED"
        if audit_log_path.exists():
            trial_record["audit_probe_executed"] = True
            trial_record["audit_trace"] = audit_log_path.read_text(encoding="utf-8").strip()
            audit_log_path.unlink()
        else:
            trial_record["audit_probe_executed"] = False
    except MlflowException as e:
        lat = (time.perf_counter() - t0) * 1000.0
        trial_record["latency_ms"] = round(lat, 4)
        trial_record["policy_exception_caught"] = True
        trial_record["exception_type"] = "MlflowException"
        trial_record["exception_detail"] = str(e)
        if "pickle" in str(e).lower() or "disallowed" in str(e).lower():
            trial_record["status"] = "BLOCKED_BY_POLICY"
        else:
            trial_record["status"] = "UNEXPECTED_MLFLOW_EXCEPTION"
        trial_record["audit_probe_executed"] = audit_log_path.exists()
        if audit_log_path.exists():
            trial_record["audit_trace"] = audit_log_path.read_text(encoding="utf-8").strip()
            audit_log_path.unlink()
    except Exception as e:
        lat = (time.perf_counter() - t0) * 1000.0
        trial_record["latency_ms"] = round(lat, 4)
        trial_record["status"] = "ERROR"
        trial_record["exception_type"] = type(e).__name__
        trial_record["exception_detail"] = str(e)
        trial_record["audit_probe_executed"] = audit_log_path.exists()

    trials_detail.append(trial_record)

# Summary status
loaded_count = sum(1 for t in trials_detail if t["status"] == "LOADED")
blocked_count = sum(1 for t in trials_detail if t["status"] == "BLOCKED_BY_POLICY")
probe_count = sum(1 for t in trials_detail if t["audit_probe_executed"])

print(f"[Worker Telemetry] Finished {len(trials_detail)} trials: {loaded_count} LOADED, {blocked_count} BLOCKED, {probe_count} PROBES EXECUTED")

print(f"TELEMETRY_JSON:" + json.dumps({
    "version": mlflow.__version__,
    "warmups": warmups,
    "trials_count": len(trials_detail),
    "loaded_count": loaded_count,
    "blocked_count": blocked_count,
    "probes_executed_count": probe_count,
    "trials": trials_detail
}))

if blocked_count == len(trials_detail):
    sys.exit(2)
elif loaded_count == len(trials_detail):
    sys.exit(0)
else:
    sys.exit(1)
"""
    worker_script.write_text(worker_code, encoding="utf-8")

    results = {}

    def parse_telemetry(stdout_text):
        for line in stdout_text.splitlines():
            if line.startswith("TELEMETRY_JSON:"):
                return json.loads(line.replace("TELEMETRY_JSON:", "").strip())
        return None

    def compute_stats(trial_records):
        if not trial_records:
            return None
        lats = [t["latency_ms"] for t in trial_records]
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

    # =========================================================================
    # Test 1: Real MLflow 3.12.0 with MLFLOW_ALLOW_PICKLE_DESERIALIZATION=false
    # =========================================================================
    print("\n" + "-" * 75)
    print(f"--- [EXPERIMENT 1] Official MLflow 3.12.0 (Policy: false, {trials} trials) ---")
    print("-" * 75)

    env_v1 = os.environ.copy()
    env_v1["MLFLOW_ALLOW_PICKLE_DESERIALIZATION"] = "false"
    env_v1["PYTHONPATH"] = str(ROOT_DIR)

    res_v1 = subprocess.run(
        [str(py_3_12), str(worker_script), str(tampered_dir), str(trials), "3", str(AUDIT_LOG_FILE)],
        env=env_v1,
        capture_output=True,
        text=True
    )
    print(f"Stdout:\n{res_v1.stdout.strip()}")
    if res_v1.stderr.strip():
        print(f"Stderr:\n{res_v1.stderr.strip()}")

    telem_v1 = parse_telemetry(res_v1.stdout)
    assert telem_v1 is not None, "FATAL: Worker failed to emit telemetry JSON for MLflow 3.12.0"
    v1_trials = telem_v1.get("trials", [])

    # Individual trial validation (FASE C.2)
    assert len(v1_trials) == trials, f"Expected {trials} trials, got {len(v1_trials)}"
    for idx, t in enumerate(v1_trials):
        assert t["status"] == "LOADED", f"Trial {idx+1} failed to load: {t}"
        assert t["audit_probe_executed"] is True, f"Trial {idx+1} failed to execute audit probe: {t}"

    print(f"  -> Outcome: POLICY BYPASSED in 100% of trials ({len(v1_trials)}/{trials}) in official MLflow 3.12.0 release!")
    first_trace = v1_trials[0].get("audit_trace")
    print(f"  -> In-Process Audit Trace Sample: {first_trace}")

    results["MLflow_3_12_0_Official_Release"] = {
        "version": "3.12.0",
        "policy": "false",
        "return_code": res_v1.returncode,
        "policy_bypassed": True,
        "arbitrary_code_executed": True,
        "vulnerability_reproduction_rate": 1.0,
        "trace_sample": first_trace,
        "status": "VULNERABILITY_CONFIRMED",
        "semantic_operation": "Arbitrary Code Execution (Full Deserialization + Payload Run)",
        "environment_metadata": meta_3_12,
        "benchmark": compute_stats(v1_trials),
        "trials_detail": v1_trials
    }

    # =========================================================================
    # Test 2: Real MLflow 3.15.0 with MLFLOW_ALLOW_PICKLE_DESERIALIZATION=false
    # =========================================================================
    print("\n" + "-" * 75)
    print(f"--- [EXPERIMENT 2] Official MLflow 3.15.0 (Policy: false, {trials} trials) ---")
    print("-" * 75)

    env_v2 = os.environ.copy()
    env_v2["MLFLOW_ALLOW_PICKLE_DESERIALIZATION"] = "false"
    env_v2["PYTHONPATH"] = str(ROOT_DIR)

    res_v2 = subprocess.run(
        [str(py_3_15), str(worker_script), str(tampered_dir), str(trials), "3", str(AUDIT_LOG_FILE)],
        env=env_v2,
        capture_output=True,
        text=True
    )
    print(f"Stdout:\n{res_v2.stdout.strip()}")
    if res_v2.stderr.strip():
        print(f"Stderr:\n{res_v2.stderr.strip()}")

    assert res_v2.returncode == 2, f"FATAL: MLflow 3.15.0 should exit with code 2 (MlflowException), got {res_v2.returncode}"

    telem_v2 = parse_telemetry(res_v2.stdout)
    assert telem_v2 is not None, "FATAL: Worker failed to emit telemetry JSON for MLflow 3.15.0"
    v2_trials = telem_v2.get("trials", [])

    # Individual trial validation (FASE C.2)
    assert len(v2_trials) == trials, f"Expected {trials} trials, got {len(v2_trials)}"
    for idx, t in enumerate(v2_trials):
        assert t["status"] == "BLOCKED_BY_POLICY", f"Trial {idx+1} was not blocked by policy: {t}"
        assert t["policy_exception_caught"] is True, f"Trial {idx+1} did not raise policy exception: {t}"
        assert t["audit_probe_executed"] is False, f"Trial {idx+1} executed probe when it should have been blocked: {t}"

    print(f"  -> Outcome: DESERIALIZATION REJECTED in 100% of trials ({len(v2_trials)}/{trials}) by official MLflow 3.15.0 patch!")

    results["MLflow_3_15_0_Official_Release"] = {
        "version": "3.15.0",
        "policy": "false",
        "return_code": res_v2.returncode,
        "policy_bypassed": False,
        "arbitrary_code_executed": False,
        "policy_block_rate": 1.0,
        "trace": None,
        "status": "PATCH_CONFIRMED",
        "semantic_operation": "Fast-Fail Policy Interception (MlflowException Raised Pre-Unpickler)",
        "environment_metadata": meta_3_15,
        "benchmark": compute_stats(v2_trials),
        "trials_detail": v2_trials
    }

    results["study_protocol"] = {
        "protocol_mode": run_type,
        "trials_requested": trials,
        "warmup_iterations": 3,
        "scientific_interpretation": "Timing differences reflect fundamentally distinct computational semantics: full deserialization + payload execution in unpatched MLflow 3.12.0 vs pre-deserialization policy interception in patched MLflow 3.15.0. They are NOT an algorithmic speed comparison.",
        "distinction_notice": "CI smoke execution runs 20 trials for automated regression; full scientific study protocol runs 50 trials with complete inter-trial variance logging."
    }

    # Export report JSON
    out_file = REPORTS_DIR / "cve_2026_96804_real_releases_study.json"
    out_file.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print("\n" + "=" * 80)
    print(f"[✓] Official MLflow Releases Study Complete! Saved to: {out_file}")
    print("=" * 80)

    # Sync markdown report from generated JSON (FASE D)
    sync_markdown_report_from_json(out_file)

    return results

def sync_markdown_report_from_json(json_path: Path):
    """
    Riconcilia e sincronizza la tabella Markdown in reports/FINAL_SECURITY_AND_SCIENTIFIC_AUDIT.md
    utilizzando i dati numerici reali presenti nel file JSON.
    Garantisce consistenza al 100% tra JSON e Markdown senza numeri inventati.
    """
    audit_md_path = REPORTS_DIR / "FINAL_SECURITY_AND_SCIENTIFIC_AUDIT.md"
    if not audit_md_path.exists() or not json_path.exists():
        return

    data = json.loads(json_path.read_text(encoding="utf-8"))
    b12 = data.get("MLflow_3_12_0_Official_Release", {}).get("benchmark", {})
    b15 = data.get("MLflow_3_15_0_Official_Release", {}).get("benchmark", {})

    if not b12 or not b15:
        return

    trials_count = b12.get("trials", 50)
    protocol_mode = data.get("study_protocol", {}).get("protocol_mode", "FULL_SCIENTIFIC_STUDY")

    new_table = f"""| Parametro Statistico | MLflow 3.12.0 (Unpatched — Sonda Eseguita) | MLflow 3.15.0 (Patched — Bloccato da Policy) |
| :--- | :--- | :--- |
| **Esito di Sicurezza** | **100% Vulnerabile** (Sonda eseguita in-process) | **100% Protetto** (`MlflowException` fail-closed) |
| **Protocollo Sperimentale** | {trials_count} prove (+ 3 warm-up) [{protocol_mode}] | {trials_count} prove (+ 3 warm-up) [{protocol_mode}] |
| **Tempo Medio** | **{b12.get('mean_ms')} ms** | **{b15.get('mean_ms')} ms** |
| **Media Troncata (10%)** | **{b12.get('trimmed_mean_10pct_ms')} ms** | **{b15.get('trimmed_mean_10pct_ms')} ms** |
| **Mediana (p50)** | **{b12.get('median_ms')} ms** | **{b15.get('median_ms')} ms** |
| **Range Interquartile (IQR)** | **{b12.get('iqr_ms')} ms** | **{b15.get('iqr_ms')} ms** |
| **95° Percentile (p95)** | **{b12.get('p95_ms')} ms** | **{b15.get('p95_ms')} ms** |
| **99° Percentile (p99)** | **{b12.get('p99_ms')} ms** | **{b15.get('p99_ms')} ms** |
| **Min / Max** | {b12.get('min_ms')} ms / {b12.get('max_ms')} ms | {b15.get('min_ms')} ms / {b15.get('max_ms')} ms |
| **Deviazione Standard** | {b12.get('std_ms')} ms | {b15.get('std_ms')} ms |"""

    diff_mean = round(abs(float(b12.get('mean_ms', 0.0)) - float(b15.get('mean_ms', 0.0))), 3)

    md_content = audit_md_path.read_text(encoding="utf-8")
    import re
    # Match the table between "| Parametro Statistico" and the section explanation
    pattern = r"\| Parametro Statistico \| MLflow 3\.12\.0.*?\n\| \*\*Deviazione Standard\*\* \| [^\n]+"
    if re.search(pattern, md_content, flags=re.DOTALL):
        updated_md = re.sub(pattern, new_table, md_content, flags=re.DOTALL)
        # Also reconcile Section D.3 latency difference explanation
        diff_pattern = r"La differenza di circa [0-9\.]+ ms tra le due versioni è pienamente giustificata"
        diff_replacement = f"La differenza di circa {diff_mean} ms tra le due versioni è pienamente giustificata"
        updated_md = re.sub(diff_pattern, diff_replacement, updated_md)

        audit_md_path.write_text(updated_md, encoding="utf-8")
        print(f"[✓] Reconciled Markdown table in {audit_md_path.name} with JSON benchmark measurements.")

if __name__ == "__main__":
    trials_arg = int(sys.argv[1]) if len(sys.argv) > 1 else 50
    run_real_release_cve_study(trials=trials_arg)
