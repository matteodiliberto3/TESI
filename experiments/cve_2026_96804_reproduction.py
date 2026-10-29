import os
import sys
import shutil
from pathlib import Path
import numpy as np
import statsmodels.api as sm
import mlflow
import mlflow.statsmodels
from mlflow.exceptions import MlflowException
import statsmodels.iolib.api as smio

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

import config
from pipeline.payload_generator import craft_portable_trojan

AUDIT_LOG_FILE = config.REPORTS_DIR / "cve_2026_96804_audit.log"
TEST_ARTIFACTS_DIR = config.ARTIFACTS_DIR / "cve_reproduction"

def unpatched_mlflow_3_12_load_model(model_dir: Path):
    """
    Exact implementation of MLflow <= 3.12.0 statsmodels._load_model.
    Reference: https://github.com/mlflow/mlflow/blob/v3.12.0/mlflow/statsmodels/__init__.py#L307-L310
    
    CRITICAL DEFECT: Fails to check MLFLOW_ALLOW_PICKLE_DESERIALIZATION environment variable.
    Even when the security flag is set to false, it unconditionally delegates to smio.load_pickle.
    """
    model_data_subpath = "model.statsmodels"
    model_path = model_dir / model_data_subpath
    # In v3.12.0: No check on MLFLOW_ALLOW_PICKLE_DESERIALIZATION!
    return smio.load_pickle(str(model_path))

def patched_mlflow_3_15_load_model(model_dir: Path):
    """
    Patched implementation in MLflow >= 3.15.0 (and current 3.17.2).
    Reference: https://github.com/mlflow/mlflow/blob/v3.15.0/mlflow/statsmodels/__init__.py#L312-L325
    
    SECURITY ENFORCEMENT: Enforces MLFLOW_ALLOW_PICKLE_DESERIALIZATION check.
    Raises MlflowException when policy disallows pickle, aborting prior to smio.load_pickle.
    """
    return mlflow.statsmodels.load_model(str(model_dir))

def run_cve_comparative_study():
    print("=" * 80)
    print("   SCIENTIFIC REPRODUCTION: CVE-2026-96804 (MLflow Statsmodels Pickle Bypass)")
    print(f"   Execution Worker PID: {os.getpid()}")
    print("=" * 80)

    TEST_ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    config.REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Train genuine statsmodels model
    np.random.seed(42)
    X = np.random.randn(100, 2)
    X_const = sm.add_constant(X)
    y = np.random.binomial(1, 0.3, 100)
    model = sm.Logit(y, X_const).fit(disp=False)

    # 2. Save MLflow artifact
    clean_dir = TEST_ARTIFACTS_DIR / "clean_mlflow_model"
    tampered_dir = TEST_ARTIFACTS_DIR / "tampered_mlflow_model"

    if clean_dir.exists():
        shutil.rmtree(clean_dir)
    if tampered_dir.exists():
        shutil.rmtree(tampered_dir)

    mlflow.statsmodels.save_model(model, str(clean_dir))
    shutil.copytree(clean_dir, tampered_dir)

    # 3. Inject Trojan into model.statsmodels
    tampered_artifact = tampered_dir / "model.statsmodels"
    craft_portable_trojan(model, tampered_artifact, AUDIT_LOG_FILE)
    print(f"[Setup] Crafted tampered MLflow statsmodels model -> {tampered_artifact}")

    results = {}

    # =========================================================================
    # V1 — Vulnerabile: MLflow 3.12.0 Logic con Policy 'false'
    # =========================================================================
    print("\n--- [V1] MLflow 3.12.0 Unpatched Behavior (MLFLOW_ALLOW_PICKLE_DESERIALIZATION=false) ---")
    os.environ["MLFLOW_ALLOW_PICKLE_DESERIALIZATION"] = "false"
    if AUDIT_LOG_FILE.exists():
        AUDIT_LOG_FILE.unlink()

    v1_loaded = unpatched_mlflow_3_12_load_model(tampered_dir)
    v1_probe_executed = AUDIT_LOG_FILE.exists()
    
    assert v1_probe_executed, "FATAL: V1 should have executed probe due to missing policy check in v3.12.0!"
    v1_trace = AUDIT_LOG_FILE.read_text(encoding="utf-8").strip()
    print(f"  -> Outcome: POLICY BYPASSED (Vulnerability Confirmed!)")
    print(f"  -> In-Process Audit Trace: {v1_trace}")
    print(f"  -> Model Functional: {hasattr(v1_loaded, 'predict')}")

    results["V1_MLflow_3_12_Policy_Bypass"] = {
        "mlflow_version_target": "3.12.0",
        "policy_env_var": "false",
        "policy_enforced": False,
        "arbitrary_code_executed": True,
        "status": "VULNERABILITY_REPRODUCED",
        "trace": v1_trace
    }

    # =========================================================================
    # V2 — Corretta: MLflow 3.15.0+ Patched Behavior con Policy 'false'
    # =========================================================================
    print("\n--- [V2] MLflow 3.15.0+ Patched Behavior (MLFLOW_ALLOW_PICKLE_DESERIALIZATION=false) ---")
    os.environ["MLFLOW_ALLOW_PICKLE_DESERIALIZATION"] = "false"
    if AUDIT_LOG_FILE.exists():
        AUDIT_LOG_FILE.unlink()

    v2_blocked = False
    v2_error_msg = ""
    try:
        _ = patched_mlflow_3_15_load_model(tampered_dir)
    except MlflowException as e:
        v2_blocked = True
        v2_error_msg = str(e)

    v2_probe_executed = AUDIT_LOG_FILE.exists()
    assert v2_blocked, "FATAL: V2 must block unpickling when policy is false!"
    assert not v2_probe_executed, "FATAL: V2 must NOT execute the audit probe!"
    print(f"  -> Outcome: DESERIALIZATION REJECTED (Patch Confirmed!)")
    print(f"  -> Block Reason: {v2_error_msg}")
    print(f"  -> Probe Executed: {v2_probe_executed}")

    results["V2_MLflow_3_15_Patched_Defense"] = {
        "mlflow_version_target": "3.15.0+",
        "policy_env_var": "false",
        "policy_enforced": True,
        "arbitrary_code_executed": False,
        "status": "DEFENSE_VERIFIED",
        "error_message": v2_error_msg
    }

    # =========================================================================
    # V3 — Consenso Esplicito: MLflow 3.15.0+ con Policy 'true'
    # =========================================================================
    print("\n--- [V3] MLflow 3.15.0+ Explicit Opt-in (MLFLOW_ALLOW_PICKLE_DESERIALIZATION=true) ---")
    os.environ["MLFLOW_ALLOW_PICKLE_DESERIALIZATION"] = "true"
    if AUDIT_LOG_FILE.exists():
        AUDIT_LOG_FILE.unlink()

    v3_loaded = patched_mlflow_3_15_load_model(tampered_dir)
    v3_probe_executed = AUDIT_LOG_FILE.exists()
    assert v3_probe_executed, "FATAL: V3 should load when user explicitly sets policy to true!"
    print(f"  -> Outcome: DESERIALIZATION PERMITTED (Developer Override Confirmed)")
    print(f"  -> Model Functional: {hasattr(v3_loaded, 'predict')}")

    results["V3_MLflow_3_15_Explicit_Consent"] = {
        "mlflow_version_target": "3.15.0+",
        "policy_env_var": "true",
        "policy_enforced": True,
        "arbitrary_code_executed": True,
        "status": "EXPLICIT_OVERRIDE_VERIFIED"
    }

    # Export report
    report_file = config.REPORTS_DIR / "cve_2026_96804_comparative_study.json"
    import json
    report_file.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print("\n" + "=" * 80)
    print(f"[✓] CVE Comparative Study Completed Successfully! Report saved to: {report_file}")
    print("=" * 80)
    return results

if __name__ == "__main__":
    run_cve_comparative_study()
