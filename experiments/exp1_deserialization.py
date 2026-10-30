import sys
import os
import pickle
import time
from pathlib import Path
from typing import Dict, Any

sys.path.append(str(Path(__file__).resolve().parent.parent))
import config
from pipeline.crypto_signer import ModelConsumerVerifier, SecurityError
from pipeline.train import load_model_safetensors
from pipeline.payload_generator import craft_portable_trojan

AUDIT_PROOF_FILE = config.REPORTS_DIR / "deserialization_audit_proof.log"

def craft_malicious_artifact(output_path: Path = config.ARTIFACTS_DIR / "tampered_model.pkl"):
    """
    Serializes an in-process polyglot trojan artifact (Chapter 4.4 & 5.1).
    Ensures:
    1. Exact worker PID is captured in-process without child shell discrepancy.
    2. Zero external dependencies / no __main__ module lookup failure.
    3. Reconstructs and returns genuine Scikit-learn model.
    """
    clean_model_path = config.CLEAN_MODEL_PICKLE
    clean_model = None
    if clean_model_path.exists():
        try:
            with open(clean_model_path, "rb") as f:
                clean_model = pickle.load(f)
        except Exception:
            clean_model = None

    if clean_model is None:
        clean_model = {"model_name": "SyntheticFraudClassifier", "status": "active"}

    craft_portable_trojan(clean_model, output_path, AUDIT_PROOF_FILE)
    print(f"[Attack Sim] Crafted portable in-process polyglot trojan -> {output_path}")
    return output_path

def test_vulnerable_loading(artifact_path: Path) -> Dict[str, Any]:
    """Test 1: Vulnerable worker loads pickle directly."""
    if AUDIT_PROOF_FILE.exists():
        AUDIT_PROOF_FILE.unlink()

    worker_pid = os.getpid()
    print(f"[Vulnerable Worker (PID: {worker_pid})] Loading model from untrusted storage...")
    try:
        with open(artifact_path, "rb") as f:
            model = pickle.load(f)
        
        executed = AUDIT_PROOF_FILE.exists()
        pid_matched = False
        if executed:
            trace = AUDIT_PROOF_FILE.read_text(encoding="utf-8")
            pid_matched = f"WORKER_PID: {worker_pid}" in trace

        return {
            "vulnerability_reproduced": executed,
            "in_process_pid_matched": pid_matched,
            "status": "EXPLOITED" if (executed and pid_matched) else "SAFE",
            "audit_file": str(AUDIT_PROOF_FILE) if executed else None,
            "model_ready": model is not None
        }
    except Exception as e:
        return {"vulnerability_reproduced": False, "status": "ERROR", "error": str(e)}

def test_cryptographic_defense(artifact_path: Path) -> Dict[str, Any]:
    """Test 2: Hardened worker verifies digital signature prior to unpickling via atomic in-memory loading."""
    verifier = ModelConsumerVerifier(config.PUBLIC_KEY_FILE)
    sig_path = artifact_path.with_suffix(".sig")
    print("[Hardened Worker] Verifying digital signature and loading via atomic in-memory unpickling...")

    try:
        model = verifier.load_verified_pickle(artifact_path, sig_path)
        return {
            "defense_successful": False,
            "signature_valid": True,
            "code_executed": True,
            "model_loaded": True
        }
    except (SecurityError, FileNotFoundError) as e:
        print(f"[Hardened Worker] PREVENTED: Signature invalid or absent ({e}). Deserialization aborted.")
        return {
            "defense_successful": True,
            "signature_valid": False,
            "code_executed": False
        }

def test_safetensors_defense(safetensors_path: Path) -> Dict[str, Any]:
    """Test 3: Loading static Safetensors format."""
    print("[Hardened Worker] Loading model via Safetensors...")
    try:
        model = load_model_safetensors(safetensors_path)
        return {
            "defense_successful": True,
            "format": "safetensors",
            "arbitrary_execution_possible": False,
            "model_ready": model is not None
        }
    except Exception as e:
        return {"defense_successful": False, "error": str(e)}

def run_experiment_1():
    print("=" * 70)
    print("EXPERIMENT 1: Insecure Deserialization Analysis & Remediation")
    print(f"Worker PID: {os.getpid()}")
    print("=" * 70)
    
    payload_file = craft_malicious_artifact()
    
    print("\n--- 1. Evaluating Vulnerable Execution Path ---")
    vuln_result = test_vulnerable_loading(payload_file)
    print(f"Outcome: {vuln_result['status']} | In-Process PID Match: {vuln_result.get('in_process_pid_matched')}")
    
    print("\n--- 2. Evaluating Cryptographic Defense (Unsigned / Invalid Signature) ---")
    defense_result = test_cryptographic_defense(payload_file)
    print(f"Defense Successful: {defense_result['defense_successful']} (Code Executed: {defense_result['code_executed']})")

    print("\n--- 3. Evaluating Safe Serialization Format (Safetensors) ---")
    safetensors_file = config.SECURE_MODEL_SAFETENSORS
    safe_result = test_safetensors_defense(safetensors_file)
    print(f"Safetensors Defense Successful: {safe_result['defense_successful']}")

    return {
        "vulnerable_pipeline": vuln_result,
        "cryptographic_defense": defense_result,
        "safetensors_defense": safe_result
    }

if __name__ == "__main__":
    run_experiment_1()
