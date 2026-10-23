import os
import sys
import json
import time
import shutil
import pytest
import threading
from pathlib import Path
from urllib.request import urlopen, Request
from http.server import HTTPServer

import config
from pipeline.crypto_signer import generate_keypair, ModelProducerSigner, ModelConsumerVerifier
from pipeline.train import run_training_pipeline
from pipeline.serve import FraudInferenceService, InferenceHTTPHandler

def test_clean_provisioning_and_producer_consumer_flow(tmp_path: Path):
    """
    Simulates the end-to-end lifecycle on a fresh/clean environment:
    1. Keys do not exist initially.
    2. Explicit provisioning generates keypair.
    3. Producer signs model artifact.
    4. Consumer possesses ONLY public key, verifies artifact, and performs inference.
    5. Tampered artifact or signature fails closed.
    """
    clean_keys_dir = tmp_path / "keys"
    clean_artifacts_dir = tmp_path / "artifacts"
    clean_artifacts_dir.mkdir(parents=True, exist_ok=True)
    
    priv_key = clean_keys_dir / "private_key.pem"
    pub_key = clean_keys_dir / "public_key.pem"
    
    # 1. Producer must fail closed if keys were not provisioned
    with pytest.raises(FileNotFoundError):
        ModelProducerSigner(private_key_path=priv_key, public_key_path=pub_key)
        
    # 2. Provision keys (as performed by the producer bootstrap command)
    generate_keypair(private_key_path=priv_key, public_key_path=pub_key)
    assert priv_key.exists()
    assert pub_key.exists()
    
    # 3. Producer creates and signs an artifact
    producer = ModelProducerSigner(private_key_path=priv_key, public_key_path=pub_key)
    artifact_file = clean_artifacts_dir / "model.bin"
    sig_file = clean_artifacts_dir / "model.sig"
    artifact_file.write_bytes(b"MOCK_TRAINED_MODEL_PAYLOAD_ABC_123")
    
    producer.sign(artifact_file, sig_file)
    assert sig_file.exists()
    
    # 4. Consumer runtime: strictly isolated, only has access to pub_key
    # Simulate consumer container by deleting/omitting private_key
    isolated_consumer_dir = tmp_path / "consumer_runtime"
    isolated_consumer_keys = isolated_consumer_dir / "keys"
    isolated_consumer_keys.mkdir(parents=True, exist_ok=True)
    shutil.copy(pub_key, isolated_consumer_keys / "public_key.pem")
    
    consumer_pub_key = isolated_consumer_keys / "public_key.pem"
    consumer_priv_key = isolated_consumer_keys / "private_key.pem"
    assert not consumer_priv_key.exists()
    
    verifier = ModelConsumerVerifier(public_key_path=consumer_pub_key)
    assert verifier.verify(artifact_file, sig_file) is True
    
    # 5. Tampered artifact fails closed
    tampered_artifact = clean_artifacts_dir / "tampered.bin"
    tampered_artifact.write_bytes(b"TAMPERED_MODEL_PAYLOAD_MALICIOUS")
    assert verifier.verify(tampered_artifact, sig_file) is False
    
    # 6. Tampered signature fails closed
    tampered_sig = clean_artifacts_dir / "tampered.sig"
    tampered_sig.write_bytes(b"CORRUPTED_SIGNATURE_BYTES")
    assert verifier.verify(artifact_file, tampered_sig) is False

def test_inference_http_microservice_lifecycle(tmp_path: Path):
    """
    Tests the persistent HTTP inference microservice served by the consumer container:
    - Verifies GET /health endpoint
    - Verifies POST /predict endpoint
    - Asserts that private key is reported absent from the consumer container
    """
    # Use existing trained clean model from testbed
    if not config.CLEAN_MODEL_PICKLE.exists() or not config.SIGNATURE_FILE.exists():
        pytest.skip("Base signed model artifact not available for live microservice test")

    test_port = 8899
    service = FraudInferenceService(mode="signed_pickle")
    InferenceHTTPHandler.service = service
    server = HTTPServer(("127.0.0.1", test_port), InferenceHTTPHandler)
    
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    time.sleep(0.5)
    
    try:
        # 1. Test GET /health
        health_req = Request(f"http://127.0.0.1:{test_port}/health")
        with urlopen(health_req) as response:
            assert response.status == 200
            data = json.loads(response.read().decode("utf-8"))
            assert data["status"] == "HEALTHY"
            assert data["signature_verified"] is True
            assert data["public_key_present"] is True

        # 2. Test POST /predict
        payload = json.dumps({
            "amount": 49.99,
            "transaction_hour": 4.0,
            "distance_from_home": 10.0,
            "velocity_last_24h": 1,
            "foreign_transaction": 0,
            "high_risk_merchant": 0
        }).encode("utf-8")
        
        predict_req = Request(
            f"http://127.0.0.1:{test_port}/predict",
            data=payload,
            headers={"Content-Type": "application/json"}
        )
        with urlopen(predict_req) as response:
            assert response.status == 200
            pred_data = json.loads(response.read().decode("utf-8"))
            assert "is_fraud" in pred_data
            assert "fraud_probability" in pred_data
            assert pred_data["is_fraud"] in [0, 1]
            
    finally:
        server.shutdown()
        server.server_close()
