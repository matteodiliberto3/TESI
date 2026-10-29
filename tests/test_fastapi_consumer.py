import os
import sys
import pytest
from pathlib import Path
from starlette.testclient import TestClient

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

import config
from pipeline.serve import app, FraudInferenceService
import pipeline.serve as serve_module

@pytest.fixture(scope="module")
def client():
    # Force signed_pickle mode for client testing
    os.environ["INFERENCE_MODE"] = "signed_pickle"
    serve_module.service = FraudInferenceService(mode="signed_pickle")
    with TestClient(app) as c:
        yield c

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

def test_fastapi_reload_endpoint_safetensors(client):
    """Verifica il ricaricamento a caldo del formato Safetensors."""
    reload_payload = {
        "mode": "safetensors",
        "model_path": str(config.SECURE_MODEL_SAFETENSORS)
    }
    response = client.post("/reload", json=reload_payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "SUCCESS"
    assert data["mode"] == "safetensors"
    assert data["verification_passed"] is True


def test_fastapi_reload_path_traversal_blocked(client):
    """Verifica che tentativi di caricare file fuori da artifacts/ siano respinti con 403."""
    traversal_payload = {
        "mode": "vulnerable_pickle",
        "model_path": "../../etc/passwd"
    }
    response = client.post("/reload", json=traversal_payload)
    assert response.status_code == 403
    assert "Access denied" in response.json()["detail"]
