import os
import sys
import shutil
import pytest
import numpy as np
import statsmodels.api as sm
import mlflow.statsmodels
from pathlib import Path
from starlette.testclient import TestClient

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

import config
from pipeline.serve import app, FraudInferenceService
import pipeline.serve as serve_module
from pipeline.crypto_signer import ModelProducerSigner

TEST_ADMIN_TOKEN = "test-admin-secret-token-2026"
ADMIN_HEADERS = {"X-Admin-Token": TEST_ADMIN_TOKEN}

@pytest.fixture(autouse=True)
def setup_test_env():
    old_token = os.environ.get("MLOPS_ADMIN_TOKEN")
    os.environ["MLOPS_ADMIN_TOKEN"] = TEST_ADMIN_TOKEN
    yield
    if old_token is not None:
        os.environ["MLOPS_ADMIN_TOKEN"] = old_token
    else:
        os.environ.pop("MLOPS_ADMIN_TOKEN", None)

@pytest.fixture(scope="module")
def client():
    os.environ["INFERENCE_MODE"] = "signed_pickle"
    os.environ["MLOPS_ADMIN_TOKEN"] = TEST_ADMIN_TOKEN
    serve_module.service = FraudInferenceService(mode="signed_pickle")
    with TestClient(app) as c:
        yield c

@pytest.fixture(scope="module")
def mlflow_statsmodels_fixtures():
    """Generates guaranteed legitimate signed and unsigned MLflow statsmodels model artifacts."""
    np.random.seed(42)
    X = np.random.randn(100, 2)
    X_const = sm.add_constant(X)
    y = np.random.binomial(1, 0.3, 100)
    model = sm.Logit(y, X_const).fit(disp=False)

    signed_dir = config.ARTIFACTS_DIR / "mlflow_test_signed_model"
    unsigned_dir = config.ARTIFACTS_DIR / "mlflow_test_unsigned_model"

    if signed_dir.exists():
        shutil.rmtree(signed_dir)
    if unsigned_dir.exists():
        shutil.rmtree(unsigned_dir)

    mlflow.statsmodels.save_model(model, str(signed_dir))
    mlflow.statsmodels.save_model(model, str(unsigned_dir))

    # Sign the legitimate artifact
    signer = ModelProducerSigner(config.PRIVATE_KEY_FILE, config.PUBLIC_KEY_FILE)
    target_artifact = signed_dir / "model.statsmodels"
    sig_path = signed_dir / "model.statsmodels.sig"
    signer.sign_artifact(target_artifact, sig_path)

    yield {
        "signed_dir": signed_dir,
        "sig_path": sig_path,
        "unsigned_dir": unsigned_dir
    }

    # Cleanup
    shutil.rmtree(signed_dir, ignore_errors=True)
    shutil.rmtree(unsigned_dir, ignore_errors=True)

def test_fastapi_health_endpoint(client):
    """Verifica che l'endpoint /health restituisca 200, stato HEALTHY e PID del worker."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "HEALTHY"
    assert data["mode"] == "signed_pickle"
    assert data["signature_verified"] is True
    assert isinstance(data["private_key_absent_from_consumer"], bool)
    assert "worker_pid" in data
    assert data["worker_pid"] > 0

def test_fastapi_info_endpoint(client):
    """Verifica che l'endpoint /info certifichi le policy di isolamento."""
    response = client.get("/info")
    assert response.status_code == 200
    data = response.json()
    assert data["role"] == "CONSUMER"
    assert data["model_loaded"] is True
    assert data["verification_passed"] is True
    assert isinstance(data["private_key_isolated"], bool)

def test_fastapi_predict_endpoint(client):
    """Verifica che l'inferenza risponda con HTTP 200 e predizioni valide."""
    payload = {
        "amount": 145.50,
        "transaction_hour": 15.0,
        "distance_from_home": 3.2,
        "velocity_last_24h": 2,
        "foreign_transaction": 0,
        "high_risk_merchant": 0
    }
    response = client.post("/predict", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "is_fraud" in data
    assert "fraud_probability" in data
    assert data["is_fraud"] in [0, 1]
    assert 0.0 <= data["fraud_probability"] <= 1.0

def test_fastapi_reload_unauthorized_without_token(client):
    """Verifica che tentativi di reload senza token di autenticazione siano respinti con HTTP 401."""
    reload_payload = {
        "mode": "safetensors",
        "model_path": str(config.SECURE_MODEL_SAFETENSORS)
    }
    response = client.post("/reload", json=reload_payload)
    assert response.status_code == 401
    assert "Unauthorized" in response.json()["detail"]

def test_fastapi_reload_disabled_when_server_secret_unset(client):
    """Verifica che /reload sia disattivato con HTTP 503 se MLOPS_ADMIN_TOKEN non è configurato."""
    saved_token = os.environ.pop("MLOPS_ADMIN_TOKEN", None)
    try:
        reload_payload = {
            "mode": "safetensors",
            "model_path": str(config.SECURE_MODEL_SAFETENSORS)
        }
        response = client.post("/reload", json=reload_payload, headers=ADMIN_HEADERS)
        assert response.status_code == 503
        assert "Administrative reload disabled" in response.json()["detail"]
    finally:
        if saved_token is not None:
            os.environ["MLOPS_ADMIN_TOKEN"] = saved_token

def test_fastapi_reload_endpoint_safetensors(client):
    """Verifica il ricaricamento a caldo del formato Safetensors con autenticazione valida."""
    reload_payload = {
        "mode": "safetensors",
        "model_path": str(config.SECURE_MODEL_SAFETENSORS)
    }
    response = client.post("/reload", json=reload_payload, headers=ADMIN_HEADERS)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "SUCCESS"
    assert data["mode"] == "safetensors"
    assert data["verification_passed"] is True
    assert data["format_safe"] is True
    assert data["signature_verified"] is False

def test_fastapi_reload_insecure_pickle_fail_closed_by_default(client):
    """Verifica che reload in modalità vulnerable_pickle sia respinto con 403 in modalità fail-closed predefinita."""
    reload_payload = {
        "mode": "vulnerable_pickle",
        "model_path": str(config.CLEAN_MODEL_PICKLE)
    }
    os.environ["ALLOW_INSECURE_RELOAD"] = "false"
    response = client.post("/reload", json=reload_payload, headers=ADMIN_HEADERS)
    assert response.status_code == 403
    assert "Forbidden" in response.json()["detail"]

def test_fastapi_reload_path_traversal_blocked(client):
    """Verifica che tentativi di caricare file fuori da artifacts/ siano respinti con 403."""
    traversal_payload = {
        "mode": "signed_pickle",
        "model_path": "../../etc/passwd"
    }
    response = client.post("/reload", json=traversal_payload, headers=ADMIN_HEADERS)
    assert response.status_code == 403
    assert "Access denied" in response.json()["detail"]

def test_fastapi_reload_sister_directory_prefix_traversal_blocked(client):
    """Verifica che directory sorelle con prefisso comune (es. artifacts-backup) siano bloccate con 403."""
    sister_dir_payload = {
        "mode": "signed_pickle",
        "model_path": str(config.ARTIFACTS_DIR) + "-backup/malicious_model.pkl"
    }
    response = client.post("/reload", json=sister_dir_payload, headers=ADMIN_HEADERS)
    assert response.status_code == 403
    assert "Access denied" in response.json()["detail"]

def test_fastapi_unhealthy_status_returns_http_503(client):
    """Verifica che /health risponda con HTTP 503 quando il modello non è caricato o non è valido."""
    original_model = serve_module.service.model
    try:
        serve_module.service.model = None
        response = client.get("/health")
        assert response.status_code == 503
        data = response.json()
        assert data["status"] == "UNHEALTHY"
    finally:
        serve_module.service.model = original_model

def test_fastapi_mlflow_statsmodels_mode_health_mandatory(client, mlflow_statsmodels_fixtures):
    """Verifica obbligatoria: modello MLflow crittograficamente firmato caricato con successo e stato HEALTHY (HTTP 200)."""
    signed_dir = mlflow_statsmodels_fixtures["signed_dir"]
    sig_path = mlflow_statsmodels_fixtures["sig_path"]
    assert signed_dir.exists(), "Test fixture error: signed MLflow model directory must exist!"
    assert sig_path.exists(), "Test fixture error: signature must exist!"

    reload_payload = {
        "mode": "mlflow_statsmodels",
        "model_path": str(signed_dir),
        "sig_path": str(sig_path)
    }
    res = client.post("/reload", json=reload_payload, headers=ADMIN_HEADERS)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "SUCCESS"
    assert data["signature_verified"] is True
    assert data["verification_passed"] is True

    health_res = client.get("/health")
    assert health_res.status_code == 200
    h_data = health_res.json()
    assert h_data["status"] == "HEALTHY"
    assert h_data["mode"] == "mlflow_statsmodels"
    assert h_data["signature_verified"] is True

def test_fastapi_mlflow_statsmodels_unsigned_rejected_fail_closed(client, mlflow_statsmodels_fixtures):
    """Verifica obbligatoria: modello MLflow privo di firma respinto categoricamente in modalità fail-closed."""
    unsigned_dir = mlflow_statsmodels_fixtures["unsigned_dir"]
    assert unsigned_dir.exists()

    os.environ["ALLOW_UNSIGNED_MLFLOW"] = "false"
    reload_payload = {
        "mode": "mlflow_statsmodels",
        "model_path": str(unsigned_dir)
    }
    res = client.post("/reload", json=reload_payload, headers=ADMIN_HEADERS)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "REJECTED"
    assert "Cryptographic signature missing" in data["error"]
    assert data["verification_passed"] is False

    health_res = client.get("/health")
    assert health_res.status_code == 503
    assert health_res.json()["status"] == "UNHEALTHY"

def test_fastapi_mlflow_statsmodels_tampered_signature_rejected(client, mlflow_statsmodels_fixtures):
    """Verifica obbligatoria: modello MLflow con firma manomessa respinto dal Security Gate."""
    signed_dir = mlflow_statsmodels_fixtures["signed_dir"]
    tampered_sig = signed_dir / "model.statsmodels.sig.tampered"
    tampered_sig.write_bytes(b"INVALID_RSA_PSS_SIGNATURE_BYTES_TAMPERED")
    try:
        reload_payload = {
            "mode": "mlflow_statsmodels",
            "model_path": str(signed_dir),
            "sig_path": str(tampered_sig)
        }
        res = client.post("/reload", json=reload_payload, headers=ADMIN_HEADERS)
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "REJECTED"
        assert "signature verification failed" in data["error"]
        assert data["verification_passed"] is False

        health_res = client.get("/health")
        assert health_res.status_code == 503
        assert health_res.json()["status"] == "UNHEALTHY"
    finally:
        tampered_sig.unlink(missing_ok=True)
