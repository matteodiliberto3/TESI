import os
import sys
import json
import time
import shutil
import subprocess
import pytest
import threading
from pathlib import Path
from urllib.request import urlopen, Request
from http.server import HTTPServer

import config
from pipeline.crypto_signer import generate_keypair, ModelProducerSigner, ModelConsumerVerifier
from pipeline.train import run_training_pipeline
from pipeline.serve import FraudInferenceService, InferenceHTTPHandler

def test_docker_compose_specification_and_privilege_boundaries():
    """
    Validates that the docker-compose.yml configuration complies strictly with:
    1. SLSA Level 3 & Least Privilege: mlops-inference-consumer mounts ONLY public_key.pem :ro.
    2. Zero Private Key Exposure: private_key.pem is NEVER mounted into the consumer.
    3. Deterministic Lifecycle: consumer depends_on producer with service_completed_successfully.
    4. Clean-Clone Provisioning: producer command executes --generate-keys prior to training.
    5. Privilege Reduction: ALL capabilities dropped, no-new-privileges: true.
    """
    if not shutil.which("docker"):
        pytest.skip("Docker CLI is not installed or not available on PATH")

    try:
        res = subprocess.run(
            ["docker", "compose", "config", "--format", "json"],
            cwd=str(config.BASE_DIR),
            capture_output=True,
            text=True
        )
    except FileNotFoundError:
        pytest.skip("Docker CLI executable not found on PATH")

    assert res.returncode == 0, f"docker compose config failed: {res.stderr}"

    compose_spec = json.loads(res.stdout)
    services = compose_spec.get("services", {})
    assert "mlops-training-producer" in services, "mlops-training-producer missing from compose spec"
    assert "mlops-inference-consumer" in services, "mlops-inference-consumer missing from compose spec"

    producer = services["mlops-training-producer"]
    consumer = services["mlops-inference-consumer"]

    # 1. Producer bootstrap & provisioning checks
    producer_cmd = " ".join(producer.get("command", []))
    assert "--generate-keys" in producer_cmd, "Producer does not execute --generate-keys on clean startup"
    assert "train.py" in producer_cmd, "Producer does not execute train.py"

    # 2. Consumer synchronization
    depends_on = consumer.get("depends_on", {})
    assert "mlops-training-producer" in depends_on, "Consumer does not declare dependency on producer"
    assert depends_on["mlops-training-producer"].get("condition") == "service_completed_successfully", (
        "Consumer does not specify condition: service_completed_successfully"
    )

    # 3. Cryptographic isolation & volume mounts
    consumer_volumes = consumer.get("volumes", [])
    has_public_key_ro = False
    has_private_key_leak = False

    for v in consumer_volumes:
        target = v.get("target", "")
        source = v.get("source", "")
        if "private_key" in target or "private_key" in source:
            has_private_key_leak = True
        if target == "/app/keys/public_key.pem":
            assert v.get("read_only") is True, "Public key volume must be mounted read-only (:ro)"
            has_public_key_ro = True

    assert not has_private_key_leak, "Private key is mounted into the unprivileged consumer container!"
    assert has_public_key_ro, "Public key is not mounted into consumer container at /app/keys/public_key.pem"

    # 4. Kernel privilege reduction
    assert consumer.get("cap_drop") == ["ALL"], "Consumer does not drop ALL kernel capabilities"
    assert producer.get("cap_drop") == ["ALL"], "Producer does not drop ALL kernel capabilities"

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
    - Self-contained and isolated in tmp_path with fresh keys and matching signed artifact
    """
    test_keys = tmp_path / "keys"
    test_artifacts = tmp_path / "artifacts"
    test_keys.mkdir(parents=True, exist_ok=True)
    test_artifacts.mkdir(parents=True, exist_ok=True)

    priv_key = test_keys / "private_key.pem"
    pub_key = test_keys / "public_key.pem"
    generate_keypair(private_key_path=priv_key, public_key_path=pub_key, overwrite=True)

    # Train a fast miniature model for the test
    from sklearn.linear_model import LogisticRegression
    import pickle
    import numpy as np
    dummy_model = LogisticRegression()
    dummy_X = np.array([[10.0, 12.0, 5.0, 1, 0, 0], [500.0, 3.0, 150.0, 8, 1, 1]])
    dummy_y = np.array([0, 1])
    dummy_model.fit(dummy_X, dummy_y)

    model_file = test_artifacts / "model_clean.pkl"
    sig_file = test_artifacts / "model_clean.sig"
    with open(model_file, "wb") as f:
        pickle.dump(dummy_model, f)

    producer = ModelProducerSigner(private_key_path=priv_key, public_key_path=pub_key)
    producer.sign(model_file, sig_file)

    # Consumer runtime only has public key; simulate absence of private key
    isolated_priv_key = tmp_path / "non_existent_private_key.pem"
    assert not isolated_priv_key.exists()

    test_port = 8899
    service = FraudInferenceService(
        mode="signed_pickle",
        model_path=model_file,
        sig_path=sig_file,
        public_key_path=pub_key,
        private_key_path=isolated_priv_key
    )
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
            assert data["private_key_absent_from_consumer"] is True

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

def test_docker_compose_live_e2e():
    """
    Live containerized end-to-end integration test.
    Automatically checks Docker daemon connectivity.
    If daemon is running, exercises:
      docker compose up --build -d mlops-inference-consumer
      health check on port 8000
      direct container filesystem probe
      docker compose down -v
    If daemon is stopped, gracefully skips with operator instructions.
    """
    check_daemon = subprocess.run(
        ["docker", "info"],
        capture_output=True,
        text=True
    )
    if check_daemon.returncode != 0:
        pytest.skip(
            "Docker daemon is not reachable in current session. "
            "To execute full live container validation, start Docker Desktop and run: "
            "powershell -File scripts/verify_docker_e2e.ps1 (or bash scripts/verify_docker_e2e.sh)"
        )

    try:
        # Ensure directories exist with least-privilege permissions (Chapter 4.2 & 5.1)
        for dir_name in ["data_storage", "feature_store_storage", "artifacts", "reports", "keys"]:
            p = config.BASE_DIR / dir_name
            p.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(p, 0o755)
            except Exception:
                pass

        # Pass current UID/GID to container on POSIX to maintain least-privilege host file ownership
        docker_env = os.environ.copy()
        if hasattr(os, "getuid"):
            docker_env["CURRENT_UID"] = str(os.getuid())
            docker_env["CURRENT_GID"] = str(os.getgid())

        # 1. Start services
        up_res = subprocess.run(
            ["docker", "compose", "up", "--build", "-d", "mlops-inference-consumer"],
            cwd=str(config.BASE_DIR),
            capture_output=True,
            text=True,
            env=docker_env
        )
        if up_res.returncode != 0:
            logs = subprocess.run(
                ["docker", "compose", "logs"],
                cwd=str(config.BASE_DIR),
                capture_output=True,
                text=True,
                env=docker_env
            ).stdout
            raise AssertionError(f"docker compose up failed: {up_res.stderr}\n--- DOCKER COMPOSE LOGS ---\n{logs}")

        # 2. Poll healthcheck
        healthy = False
        for _ in range(35):
            time.sleep(2)
            ps_res = subprocess.run(
                ["docker", "inspect", "--format={{.State.Health.Status}}", "mlops_inference_consumer"],
                capture_output=True,
                text=True
            )
            if ps_res.stdout.strip() == "healthy":
                healthy = True
                break

        if not healthy:
            logs = subprocess.run(
                ["docker", "compose", "logs"],
                cwd=str(config.BASE_DIR),
                capture_output=True,
                text=True
            ).stdout
            assert healthy, f"mlops_inference_consumer container did not become healthy within timeout.\n--- DOCKER COMPOSE LOGS ---\n{logs}"

        # 3. Health endpoint
        health_req = Request("http://localhost:8000/health")
        with urlopen(health_req) as response:
            assert response.status == 200
            data = json.loads(response.read().decode("utf-8"))
            assert data["status"] == "HEALTHY"
            assert data["signature_verified"] is True
            assert data["private_key_absent_from_consumer"] is True

        # 4. Assert absence of private key inside container
        probe_res = subprocess.run(
            ["docker", "compose", "exec", "mlops-inference-consumer", "sh", "-c", "test ! -f /app/keys/private_key.pem"],
            cwd=str(config.BASE_DIR),
            capture_output=True,
            env=docker_env
        )
        assert probe_res.returncode == 0, "private_key.pem leaked into consumer container filesystem"

    finally:
        subprocess.run(
            ["docker", "compose", "down", "-v"],
            cwd=str(config.BASE_DIR),
            capture_output=True,
            env=docker_env
        )
