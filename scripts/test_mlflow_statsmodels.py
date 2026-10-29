import os
import sys
import shutil
from pathlib import Path
import numpy as np
import statsmodels.api as sm
import mlflow
import mlflow.statsmodels
from mlflow.exceptions import MlflowException

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

import config
from pipeline.payload_generator import craft_portable_trojan

def run_mlflow_test():
    test_dir = ROOT_DIR / "tests" / "test_artifacts" / "mlflow_testbed"
    if test_dir.exists():
        shutil.rmtree(test_dir)
    test_dir.mkdir(parents=True, exist_ok=True)
    
    clean_model_dir = test_dir / "clean_model"
    tampered_model_dir = test_dir / "tampered_model"
    audit_file = test_dir / "mlflow_audit.log"
    
    print("=" * 70)
    print("Testing MLflow statsmodels Insecure Deserialization Vulnerability")
    print(f"MLflow Version: {mlflow.__version__}")
    print("=" * 70)
    
    # 1. Train genuine statsmodels model
    np.random.seed(42)
    X = np.random.randn(100, 2)
    X_const = sm.add_constant(X)
    y = np.random.binomial(1, 0.3, 100)
    model = sm.Logit(y, X_const).fit(disp=False)
    
    # 2. Save genuine model as MLflow model artifact
    mlflow.statsmodels.save_model(model, str(clean_model_dir))
    print(f"[MLflow] Clean model saved to: {clean_model_dir}")
    print(f"         Artifact files: {[p.name for p in clean_model_dir.iterdir()]}")
    
    # 3. Create tampered model directory by cloning clean model structure
    shutil.copytree(clean_model_dir, tampered_model_dir)
    # Inject our universal trojan into model.statsmodels
    tampered_pickle_file = tampered_model_dir / "model.statsmodels"
    craft_portable_trojan(model, tampered_pickle_file, audit_file)
    print(f"[Attack Sim] Replaced {tampered_pickle_file} with Trojan payload")
    
    # 4. Test loading with MLFLOW_ALLOW_PICKLE_DESERIALIZATION=false (Patched/Hardened Policy)
    os.environ["MLFLOW_ALLOW_PICKLE_DESERIALIZATION"] = "false"
    print("\n--- Test A: Loading with MLFLOW_ALLOW_PICKLE_DESERIALIZATION=false ---")
    if audit_file.exists():
        audit_file.unlink()
        
    try:
        _ = mlflow.statsmodels.load_model(str(tampered_model_dir))
        print("FAIL: Model loaded despite policy disallowing pickle!")
    except MlflowException as e:
        print(f"PASS: MLflow correctly blocked deserialization: {e}")
        assert not audit_file.exists(), "Probe should NOT have executed!"
        print("      Audit probe was NOT executed (defense verified).")
        
    # 5. Test loading with MLFLOW_ALLOW_PICKLE_DESERIALIZATION=true (Vulnerable Legacy Mode)
    os.environ["MLFLOW_ALLOW_PICKLE_DESERIALIZATION"] = "true"
    print("\n--- Test B: Loading with MLFLOW_ALLOW_PICKLE_DESERIALIZATION=true ---")
    if audit_file.exists():
        audit_file.unlink()
        
    try:
        loaded_model = mlflow.statsmodels.load_model(str(tampered_model_dir))
        print("Model loaded successfully through MLflow statsmodels loader!")
        assert audit_file.exists(), "Audit probe MUST have executed!"
        audit_trace = audit_file.read_text(encoding="utf-8")
        print(f"AUDIT PROBE EXECUTED IN-PROCESS: {audit_trace.strip()}")
        assert hasattr(loaded_model, "predict"), "Loaded model must remain functionally valid!"
        print("FUNCTIONAL VERIFICATION: Trojan returned legitimate callable statsmodels model!")
        print("EXPLOIT VERIFIED THROUGH REAL MLFLOW API!")
    except Exception as e:
        print(f"FAIL: Unexpected error during loading: {e}")
        raise e
        
    print("\n" + "=" * 70)
    print("MLflow statsmodels Deserialization Vulnerability Validation Completed!")
    print("=" * 70)

if __name__ == "__main__":
    run_mlflow_test()
