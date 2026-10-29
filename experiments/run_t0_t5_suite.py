import os
import sys
import time
import json
import pickle
from pathlib import Path
from typing import Dict, Any, List

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

import config
from pipeline.crypto_signer import ModelProducerSigner, ModelConsumerVerifier, SecurityError
from pipeline.payload_generator import craft_portable_trojan
from pipeline.train import train_classifier, save_model_pickle, save_model_safetensors, load_model_safetensors
from data.generate_dataset import generate_synthetic_transactions

ARTIFACTS_DIR = config.ARTIFACTS_DIR
REPORTS_DIR = config.REPORTS_DIR
AUDIT_LOG_FILE = REPORTS_DIR / "deserialization_audit_proof.log"

def reset_audit_log():
    if AUDIT_LOG_FILE.exists():
        AUDIT_LOG_FILE.unlink()

def run_suite() -> Dict[str, Any]:
    print("=" * 80)
    print("   MLOPS INSECURE DESERIALIZATION EMPIRICAL TEST SUITE (T0 - T5)")
    print(f"   Root Directory: {ROOT_DIR}")
    print(f"   Execution Worker PID: {os.getpid()}")
    print("=" * 80)

    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    # Provision signer & verifier
    signer = ModelProducerSigner(config.PRIVATE_KEY_FILE)
    verifier = ModelConsumerVerifier(config.PUBLIC_KEY_FILE)

    # Train genuine model
    print("\n[Step 0] Training baseline model on feature store data...")
    df = generate_synthetic_transactions(n_samples=1000, seed=42)
    clean_model, metrics, _ = train_classifier(df, model_type="logistic_regression")
    print(f"         Baseline Accuracy: {metrics['accuracy']:.4f} | F1: {metrics['f1']:.4f}")

    # Save and sign clean model
    clean_pkl = ARTIFACTS_DIR / "clean_model.pkl"
    clean_sig = clean_pkl.with_suffix(".sig")
    save_model_pickle(clean_model, clean_pkl)
    signer.sign_artifact(clean_pkl, clean_sig)

    clean_safetensors = ARTIFACTS_DIR / "clean_model.safetensors"
    save_model_safetensors(clean_model, clean_safetensors)

    results: List[Dict[str, Any]] = []

    # -------------------------------------------------------------
    # Scenario T0: Baseline Legittima
    # -------------------------------------------------------------
    reset_audit_log()
    t0_start = time.perf_counter()
    loaded_t0 = verifier.load_verified_pickle(clean_pkl, clean_sig)
    t0_lat = (time.perf_counter() - t0_start) * 1000.0
    t0_exec = AUDIT_LOG_FILE.exists()
    
    results.append({
        "scenario": "T0",
        "name": "Baseline Legittima",
        "description": "Modello pulito firmato verificato con RSA-PSS",
        "signature_required": True,
        "signature_valid": True,
        "arbitrary_code_executed": t0_exec,
        "model_loaded": loaded_t0 is not None,
        "latency_ms": round(t0_lat, 3),
        "status": "PASS" if (loaded_t0 and not t0_exec) else "FAIL"
    })
    print(f"[*] T0: Baseline Legittima -> {results[-1]['status']} (Latency: {t0_lat:.2f}ms)")

    # -------------------------------------------------------------
    # Scenario T1: Insecure Deserialization (Unchecked)
    # -------------------------------------------------------------
    reset_audit_log()
    trojan_pkl = ARTIFACTS_DIR / "tampered_trojan_model.pkl"
    craft_portable_trojan(clean_model, trojan_pkl, AUDIT_LOG_FILE)
    
    t1_start = time.perf_counter()
    with open(trojan_pkl, "rb") as f:
        loaded_t1 = pickle.load(f)
    t1_lat = (time.perf_counter() - t1_start) * 1000.0
    t1_exec = AUDIT_LOG_FILE.exists()
    t1_pid_verified = False
    if t1_exec:
        log_content = AUDIT_LOG_FILE.read_text(encoding="utf-8")
        t1_pid_verified = f"WORKER_PID: {os.getpid()}" in log_content

    results.append({
        "scenario": "T1",
        "name": "Insecure Deserialization",
        "description": "Caricamento senza controlli di trojan pickle poliglotto",
        "signature_required": False,
        "signature_valid": False,
        "arbitrary_code_executed": t1_exec,
        "in_process_pid_matched": t1_pid_verified,
        "model_loaded": loaded_t1 is not None,
        "model_functional": hasattr(loaded_t1, "predict"),
        "latency_ms": round(t1_lat, 3),
        "status": "EXPLOITED" if (t1_exec and t1_pid_verified and loaded_t1) else "FAIL"
    })
    print(f"[*] T1: Insecure Deserialization -> {results[-1]['status']} (In-process PID match: {t1_pid_verified})")

    # -------------------------------------------------------------
    # Scenario T2: Difesa Crittografica (Firma Alterata)
    # -------------------------------------------------------------
    reset_audit_log()
    t2_start = time.perf_counter()
    t2_blocked = False
    try:
        # Pass the genuine signature for the trojan artifact (digest mismatch)
        verifier.load_verified_pickle(trojan_pkl, clean_sig)
    except SecurityError:
        t2_blocked = True
    t2_lat = (time.perf_counter() - t2_start) * 1000.0
    t2_exec = AUDIT_LOG_FILE.exists()

    results.append({
        "scenario": "T2",
        "name": "Difesa Crittografica (Firma Non Valida)",
        "description": "Artefatto manomesso respinto per digest mismatch prima dell'unpickling",
        "signature_required": True,
        "signature_valid": False,
        "arbitrary_code_executed": t2_exec,
        "attack_blocked_in_memory": t2_blocked,
        "latency_ms": round(t2_lat, 3),
        "status": "DEFENDED" if (t2_blocked and not t2_exec) else "FAIL"
    })
    print(f"[*] T2: Difesa Crittografica -> {results[-1]['status']} (Blocked in-memory: {t2_blocked})")

    # -------------------------------------------------------------
    # Scenario T3: Firma Assente
    # -------------------------------------------------------------
    reset_audit_log()
    t3_start = time.perf_counter()
    t3_blocked = False
    try:
        verifier.load_verified_pickle(trojan_pkl, ARTIFACTS_DIR / "non_existent.sig")
    except (SecurityError, FileNotFoundError):
        t3_blocked = True
    t3_lat = (time.perf_counter() - t3_start) * 1000.0
    t3_exec = AUDIT_LOG_FILE.exists()

    results.append({
        "scenario": "T3",
        "name": "Firma Assente",
        "description": "Artefatto privo di firma bloccato per violazione di policy",
        "signature_required": True,
        "signature_valid": False,
        "arbitrary_code_executed": t3_exec,
        "attack_blocked_in_memory": t3_blocked,
        "latency_ms": round(t3_lat, 3),
        "status": "DEFENDED" if (t3_blocked and not t3_exec) else "FAIL"
    })
    print(f"[*] T3: Firma Assente -> {results[-1]['status']}")

    # -------------------------------------------------------------
    # Scenario T4: Producer Compromesso (Firma Valida su Malware)
    # -------------------------------------------------------------
    reset_audit_log()
    trojan_t4_pkl = ARTIFACTS_DIR / "compromised_producer_trojan.pkl"
    trojan_t4_sig = trojan_t4_pkl.with_suffix(".sig")
    craft_portable_trojan(clean_model, trojan_t4_pkl, AUDIT_LOG_FILE)
    signer.sign_artifact(trojan_t4_pkl, trojan_t4_sig)

    t4_start = time.perf_counter()
    loaded_t4 = verifier.load_verified_pickle(trojan_t4_pkl, trojan_t4_sig)
    t4_lat = (time.perf_counter() - t4_start) * 1000.0
    t4_exec = AUDIT_LOG_FILE.exists()

    results.append({
        "scenario": "T4",
        "name": "Producer Compromesso",
        "description": "Firma valida su payload malevolo: evidenzia il limite architetturale della PKI",
        "signature_required": True,
        "signature_valid": True,
        "arbitrary_code_executed": t4_exec,
        "model_loaded": loaded_t4 is not None,
        "latency_ms": round(t4_lat, 3),
        "status": "SUPPLY_CHAIN_BYPASS" if (t4_exec and loaded_t4) else "FAIL"
    })
    print(f"[*] T4: Producer Compromesso -> {results[-1]['status']} (PKI Limit Demonstrated)")

    # -------------------------------------------------------------
    # Scenario T5: Formato Sicuro (Safetensors)
    # -------------------------------------------------------------
    reset_audit_log()
    t5_start = time.perf_counter()
    loaded_t5 = load_model_safetensors(clean_safetensors)
    t5_lat = (time.perf_counter() - t5_start) * 1000.0
    t5_exec = AUDIT_LOG_FILE.exists()

    results.append({
        "scenario": "T5",
        "name": "Formato Sicuro (Safetensors)",
        "description": "Rappresentazione tensoriale senza stack machine: RCE impossibile per design",
        "signature_required": False,
        "signature_valid": None,
        "arbitrary_code_executed": t5_exec,
        "model_loaded": loaded_t5 is not None,
        "latency_ms": round(t5_lat, 3),
        "status": "PASS" if (loaded_t5 and not t5_exec) else "FAIL"
    })
    print(f"[*] T5: Formato Sicuro -> {results[-1]['status']}")

    summary = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "worker_pid": os.getpid(),
        "total_scenarios": len(results),
        "all_passed": all(r["status"] in ["PASS", "EXPLOITED", "DEFENDED", "SUPPLY_CHAIN_BYPASS"] for r in results),
        "scenarios": results
    }

    out_file = REPORTS_DIR / "t0_t5_benchmark_results.json"
    out_file.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print("\n" + "=" * 80)
    print(f"[✓] Suite completata con successo. Risultati salvati in: {out_file}")
    print("=" * 80)
    return summary

if __name__ == "__main__":
    run_suite()
