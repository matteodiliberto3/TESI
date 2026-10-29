import os
import sys
import shutil
import pytest
from pathlib import Path
import numpy as np
import statsmodels.api as sm
import mlflow
import mlflow.statsmodels
from mlflow.exceptions import MlflowException

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

import config
from pipeline.crypto_signer import ModelProducerSigner, ModelConsumerVerifier, SecurityError
from pipeline.payload_generator import craft_portable_trojan
from pipeline.train import train_classifier, save_model_safetensors, load_model_safetensors
from data.generate_dataset import generate_synthetic_transactions

TEST_ARTIFACTS_DIR = ROOT_DIR / "tests" / "test_artifacts"
TEST_REPORTS_DIR = ROOT_DIR / "tests" / "test_reports"
AUDIT_LOG_FILE = TEST_REPORTS_DIR / "test_deserialization_audit.log"

@pytest.fixture(scope="session", autouse=True)
def setup_test_environment():
    TEST_ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    TEST_REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    
    # 1. Setup Signer & Verifier
    signer = ModelProducerSigner(config.PRIVATE_KEY_FILE)
    
    # 2. Train baseline statsmodels model
    np.random.seed(42)
    X = np.random.randn(100, 2)
    X_const = sm.add_constant(X)
    y = np.random.binomial(1, 0.3, 100)
    sm_model = sm.Logit(y, X_const).fit(disp=False)
    
    # 3. Save as MLflow model artifact
    clean_mlflow_dir = TEST_ARTIFACTS_DIR / "mlflow_clean_model"
    if clean_mlflow_dir.exists():
        shutil.rmtree(clean_mlflow_dir)
    mlflow.statsmodels.save_model(sm_model, str(clean_mlflow_dir))
    
    # Sign clean MLflow model artifact (model.statsmodels)
    clean_statsmodels_file = clean_mlflow_dir / "model.statsmodels"
    clean_sig = clean_statsmodels_file.with_suffix(".sig")
    signer.sign_artifact(clean_statsmodels_file, clean_sig)
    
    # 4. Create tampered MLflow model directory
    tampered_mlflow_dir = TEST_ARTIFACTS_DIR / "mlflow_tampered_model"
    if tampered_mlflow_dir.exists():
        shutil.rmtree(tampered_mlflow_dir)
    shutil.copytree(clean_mlflow_dir, tampered_mlflow_dir)
    
    tampered_statsmodels_file = tampered_mlflow_dir / "model.statsmodels"
    craft_portable_trojan(sm_model, tampered_statsmodels_file, AUDIT_LOG_FILE)
    
    # 5. Train and save baseline Scikit-Learn + Safetensors for format comparison
    df = generate_synthetic_transactions(n_samples=500, seed=42)
    sk_model, _, _ = train_classifier(df, model_type="logistic_regression")
    clean_safetensors = TEST_ARTIFACTS_DIR / "clean_model.safetensors"
    save_model_safetensors(sk_model, clean_safetensors)
    
    yield {
        "sm_model": sm_model,
        "clean_mlflow_dir": clean_mlflow_dir,
        "clean_statsmodels_file": clean_statsmodels_file,
        "clean_sig": clean_sig,
        "tampered_mlflow_dir": tampered_mlflow_dir,
        "tampered_statsmodels_file": tampered_statsmodels_file,
        "clean_safetensors": clean_safetensors,
        "signer": signer
    }

def clean_audit_log():
    if AUDIT_LOG_FILE.exists():
        AUDIT_LOG_FILE.unlink()

def test_t0_baseline_legitimate_mlflow(setup_test_environment):
    """T0: Baseline Legittima - Modello MLflow pulito con verifica crittografica."""
    clean_audit_log()
    verifier = ModelConsumerVerifier(config.PUBLIC_KEY_FILE)
    
    clean_file = setup_test_environment["clean_statsmodels_file"]
    clean_sig = setup_test_environment["clean_sig"]
    
    # Verifica preventiva della firma digitale dell'artefatto MLflow
    assert verifier.verify_artifact(clean_file, clean_sig) is True
    
    # Caricamento attraverso MLflow statsmodels loader
    os.environ["MLFLOW_ALLOW_PICKLE_DESERIALIZATION"] = "true"
    model = mlflow.statsmodels.load_model(str(setup_test_environment["clean_mlflow_dir"]))
    
    assert model is not None, "Il modello MLflow deve essere caricato con successo"
    assert not AUDIT_LOG_FILE.exists(), "Nessun codice non autorizzato deve essere eseguito"
    assert hasattr(model, "predict")

def test_t1_mlflow_insecure_deserialization_real_cve(setup_test_environment):
    """T1: Insecure Deserialization su MLflow reale - Esecuzione RCE via mlflow.statsmodels.load_model."""
    clean_audit_log()
    current_pid = os.getpid()
    tampered_dir = setup_test_environment["tampered_mlflow_dir"]
    
    # Modalità vulnerabile MLflow (percorso non verificato o configurazione legacy)
    os.environ["MLFLOW_ALLOW_PICKLE_DESERIALIZATION"] = "true"
    loaded_model = mlflow.statsmodels.load_model(str(tampered_dir))
    
    # Verifica che la sonda sia stata eseguita all'interno del processo del worker durante il caricamento MLflow
    assert AUDIT_LOG_FILE.exists(), "La sonda di audit doveva essere eseguita durante il caricamento MLflow"
    log_content = AUDIT_LOG_FILE.read_text(encoding="utf-8")
    assert f"WORKER_PID: {current_pid}" in log_content, f"Il PID deve coincidere con il worker ({current_pid})"
    
    # Verifica stealthness: MLflow restituisce un modello funzionante
    assert hasattr(loaded_model, "predict"), "Il modello restituito da MLflow deve essere integro e funzionante"

def test_t1_mlflow_policy_hardened_mitigation(setup_test_environment):
    """T1-Mitigation: MLflow con policy restrittiva disabilita la deserializzazione pickle."""
    clean_audit_log()
    tampered_dir = setup_test_environment["tampered_mlflow_dir"]
    
    # Policy hardened / default restrittivo di MLflow
    os.environ["MLFLOW_ALLOW_PICKLE_DESERIALIZATION"] = "false"
    
    with pytest.raises(MlflowException) as exc_info:
        _ = mlflow.statsmodels.load_model(str(tampered_dir))
        
    assert "Deserializing model using pickle is disallowed" in str(exc_info.value)
    assert not AUDIT_LOG_FILE.exists(), "La deserializzazione deve essere stata bloccata da MLflow prima dell'unpickler"

def test_t2_cryptographic_defense_before_mlflow(setup_test_environment):
    """T2: Security Gate Crittografico - Blocco preventivo dell'artefatto prima della chiamata MLflow."""
    clean_audit_log()
    verifier = ModelConsumerVerifier(config.PUBLIC_KEY_FILE)
    
    tampered_file = setup_test_environment["tampered_statsmodels_file"]
    clean_sig = setup_test_environment["clean_sig"]
    
    # Il Gate verifica l'artefatto prima di passarlo al loader di MLflow
    is_valid = verifier.verify_artifact(tampered_file, clean_sig)
    assert is_valid is False, "La firma non deve corrispondere al digest dell'artefatto manomesso"
    
    # Il Gate blocca l'operazione in fail-closed senza invocare MLflow
    assert not AUDIT_LOG_FILE.exists(), "Blocco preventivo a livello di Gate: nessuna esecuzione arbitraria"

def test_t3_missing_signature(setup_test_environment):
    """T3: Difesa per Firma Assente - Rifiuto per mancata attestazione crittografica."""
    clean_audit_log()
    verifier = ModelConsumerVerifier(config.PUBLIC_KEY_FILE)
    
    tampered_file = setup_test_environment["tampered_statsmodels_file"]
    missing_sig = TEST_ARTIFACTS_DIR / "non_existent.sig"
    
    is_valid = verifier.verify_artifact(tampered_file, missing_sig)
    assert is_valid is False, "L'assenza del file di firma deve determinare il rifiuto"
    assert not AUDIT_LOG_FILE.exists()

def test_t4_compromised_producer_valid_signature(setup_test_environment):
    """T4: Producer Compromesso - Firma valida su payload malevolo (limite architetturale PKI)."""
    clean_audit_log()
    current_pid = os.getpid()
    signer = setup_test_environment["signer"]
    verifier = ModelConsumerVerifier(config.PUBLIC_KEY_FILE)
    
    tampered_file = setup_test_environment["tampered_statsmodels_file"]
    compromised_sig = tampered_file.with_suffix(".signed_by_compromised_producer.sig")
    signer.sign_artifact(tampered_file, compromised_sig)
    
    # La firma è valida perché creata dalla chiave privata legittima
    assert verifier.verify_artifact(tampered_file, compromised_sig) is True
    
    # Quando caricato con firma valida ma sorgente compromessa, l'attacco ha successo
    os.environ["MLFLOW_ALLOW_PICKLE_DESERIALIZATION"] = "true"
    _ = mlflow.statsmodels.load_model(str(setup_test_environment["tampered_mlflow_dir"]))
    
    assert AUDIT_LOG_FILE.exists()
    log_content = AUDIT_LOG_FILE.read_text(encoding="utf-8")
    assert f"WORKER_PID: {current_pid}" in log_content

def test_t5_safe_format_safetensors(setup_test_environment):
    """T5: Formato Sicuro Alternativo - Tensori statici senza bytecode né unpickler."""
    clean_audit_log()
    clean_safetensors = setup_test_environment["clean_safetensors"]
    
    model = load_model_safetensors(clean_safetensors)
    assert model is not None
    assert not AUDIT_LOG_FILE.exists(), "Safetensors non esegue bytecode arbitrario"
    
    sample_input = [[100.0, 14.0, 3.5, 2, 0, 0]]
    pred = model.predict(sample_input)
    assert pred is not None
