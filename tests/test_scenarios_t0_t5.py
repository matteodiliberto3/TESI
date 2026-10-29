import os
import sys
import time
import pickle
import pytest
from pathlib import Path

# Ensure root directory is in sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

import config
from pipeline.crypto_signer import ModelProducerSigner, ModelConsumerVerifier, SecurityError
from pipeline.payload_generator import craft_portable_trojan
from pipeline.train import train_classifier, save_model_pickle, save_model_safetensors, load_model_safetensors
from data.generate_dataset import generate_synthetic_transactions

TEST_ARTIFACTS_DIR = ROOT_DIR / "tests" / "test_artifacts"
TEST_REPORTS_DIR = ROOT_DIR / "tests" / "test_reports"
AUDIT_LOG_FILE = TEST_REPORTS_DIR / "test_deserialization_audit.log"

@pytest.fixture(scope="session", autouse=True)
def setup_test_environment():
    TEST_ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    TEST_REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    
    # Generate keys if missing
    signer = ModelProducerSigner(config.PRIVATE_KEY_FILE)
    
    # Train a baseline model
    df = generate_synthetic_transactions(n_samples=500, seed=42)
    model, _, _ = train_classifier(df, model_type="logistic_regression")
    
    clean_pkl = TEST_ARTIFACTS_DIR / "clean_model.pkl"
    clean_sig = clean_pkl.with_suffix(".sig")
    save_model_pickle(model, clean_pkl)
    signer.sign_artifact(clean_pkl, clean_sig)
    
    clean_safetensors = TEST_ARTIFACTS_DIR / "clean_model.safetensors"
    save_model_safetensors(model, clean_safetensors)
    
    yield {
        "model": model,
        "clean_pkl": clean_pkl,
        "clean_sig": clean_pkl.with_suffix(".sig"),
        "clean_safetensors": clean_safetensors,
        "signer": signer
    }

def clean_audit_log():
    if AUDIT_LOG_FILE.exists():
        AUDIT_LOG_FILE.unlink()

def test_t0_baseline_legitimate(setup_test_environment):
    """T0: Baseline Legittima - Modello pulito con firma valida."""
    clean_audit_log()
    verifier = ModelConsumerVerifier(config.PUBLIC_KEY_FILE)
    
    clean_pkl = setup_test_environment["clean_pkl"]
    clean_sig = setup_test_environment["clean_sig"]
    
    # Verifier loads verified pickle atomically
    model = verifier.load_verified_pickle(clean_pkl, clean_sig)
    
    assert model is not None, "Il modello deve essere caricato con successo"
    assert not AUDIT_LOG_FILE.exists(), "Nessun codice non autorizzato deve essere eseguito"
    
    # Predizione test
    sample_input = [[100.0, 14.0, 3.5, 2, 0, 0]]
    pred = model.predict(sample_input)
    assert pred is not None

def test_t1_insecure_deserialization_unverified(setup_test_environment):
    """T1: Insecure Deserialization - Caricamento vulnerabile senza controlli."""
    clean_audit_log()
    current_pid = os.getpid()
    
    trojan_pkl = TEST_ARTIFACTS_DIR / "trojan_model_t1.pkl"
    craft_portable_trojan(setup_test_environment["model"], trojan_pkl, AUDIT_LOG_FILE)
    
    # Consumer vulnerabile carica senza verificare la firma
    with open(trojan_pkl, "rb") as f:
        model = pickle.load(f)
        
    # Verifica che il payload sia stato eseguito in-process
    assert AUDIT_LOG_FILE.exists(), "La sonda di audit doveva essere eseguita"
    log_content = AUDIT_LOG_FILE.read_text(encoding="utf-8")
    assert f"WORKER_PID: {current_pid}" in log_content, f"Il PID deve coincidere esattamente con il worker ({current_pid})"
    
    # Verifica stealthness: il modello continua a funzionare perfettamente!
    sample_input = [[100.0, 14.0, 3.5, 2, 0, 0]]
    pred = model.predict(sample_input)
    assert pred is not None

def test_t2_cryptographic_defense_tampered_model(setup_test_environment):
    """T2: Difesa Crittografica - Artefatto alterato dopo la firma legittima."""
    clean_audit_log()
    verifier = ModelConsumerVerifier(config.PUBLIC_KEY_FILE)
    
    # Creiamo un trojan ma usiamo la firma del modello pulito (digest mismatch)
    trojan_pkl = TEST_ARTIFACTS_DIR / "trojan_model_t2.pkl"
    craft_portable_trojan(setup_test_environment["model"], trojan_pkl, AUDIT_LOG_FILE)
    invalid_sig = setup_test_environment["clean_sig"]
    
    with pytest.raises(SecurityError):
        verifier.load_verified_pickle(trojan_pkl, invalid_sig)
        
    assert not AUDIT_LOG_FILE.exists(), "La deserializzazione doveva essere bloccata in memoria PRIMA dell'unpickling"

def test_t3_missing_signature(setup_test_environment):
    """T3: Difesa per Firma Assente - Artefatto privo di firma."""
    clean_audit_log()
    verifier = ModelConsumerVerifier(config.PUBLIC_KEY_FILE)
    
    trojan_pkl = TEST_ARTIFACTS_DIR / "trojan_model_t3.pkl"
    craft_portable_trojan(setup_test_environment["model"], trojan_pkl, AUDIT_LOG_FILE)
    missing_sig = TEST_ARTIFACTS_DIR / "non_existent.sig"
    
    with pytest.raises((SecurityError, FileNotFoundError)):
        verifier.load_verified_pickle(trojan_pkl, missing_sig)
        
    assert not AUDIT_LOG_FILE.exists(), "Blocco preventivo per assenza di firma"

def test_t4_compromised_producer_valid_signature(setup_test_environment):
    """T4: Producer Compromesso - Firma valida su payload malevolo (limite architetturale PKI)."""
    clean_audit_log()
    current_pid = os.getpid()
    signer = setup_test_environment["signer"]
    verifier = ModelConsumerVerifier(config.PUBLIC_KEY_FILE)
    
    trojan_pkl = TEST_ARTIFACTS_DIR / "trojan_model_t4.pkl"
    trojan_sig = trojan_pkl.with_suffix(".sig")
    craft_portable_trojan(setup_test_environment["model"], trojan_pkl, AUDIT_LOG_FILE)
    signer.sign_artifact(trojan_pkl, trojan_sig)
    
    # La firma è matematicamente valida perché creata con la chiave privata autorizzata
    model = verifier.load_verified_pickle(trojan_pkl, trojan_sig)
    
    assert model is not None
    assert AUDIT_LOG_FILE.exists(), "La firma valida non protegge se la sorgente è compromessa"
    log_content = AUDIT_LOG_FILE.read_text(encoding="utf-8")
    assert f"WORKER_PID: {current_pid}" in log_content

def test_t5_safe_format_safetensors(setup_test_environment):
    """T5: Formato Sicuro Alternativo - Nessuna stack machine, niente RCE."""
    clean_audit_log()
    clean_safetensors = setup_test_environment["clean_safetensors"]
    
    model = load_model_safetensors(clean_safetensors)
    assert model is not None
    assert not AUDIT_LOG_FILE.exists(), "Safetensors non esegue bytecode arbitrario"
    
    sample_input = [[100.0, 14.0, 3.5, 2, 0, 0]]
    pred = model.predict(sample_input)
    assert pred is not None
