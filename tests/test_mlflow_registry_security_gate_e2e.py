import os
import sys
import shutil
import tempfile
import pytest
import numpy as np
import statsmodels.api as sm
from pathlib import Path
from starlette.testclient import TestClient

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

import config
import mlflow
import mlflow.statsmodels
from pipeline.crypto_signer import (
    ModelProducerSigner,
    ModelConsumerVerifier,
    SecurityError,
    PackageVerificationResult
)
from pipeline.serve import app, FraudInferenceService
import pipeline.serve as serve_module

TEST_ADMIN_TOKEN = "e2e-registry-gate-token-2026-high-entropy"
ADMIN_HEADERS = {"X-Admin-Token": TEST_ADMIN_TOKEN}


@pytest.fixture(scope="module")
def e2e_pipeline_fixtures():
    """
    Sets up an end-to-end MLflow Tracking Server with local SQLite backend store,
    Model Registry, RSA-PSS PKI keypair, and trained Statsmodels Logit model.
    """
    tmp_workspace = Path(tempfile.mkdtemp(prefix="mlflow_e2e_registry_"))
    db_file = tmp_workspace / "mlflow_registry.db"
    artifacts_root = tmp_workspace / "mlflow_artifacts"
    artifacts_root.mkdir(parents=True, exist_ok=True)

    tracking_uri = f"sqlite:///{db_file.as_posix()}"
    mlflow.set_tracking_uri(tracking_uri)

    # 1. Train legitimate Statsmodels Logit Model (7 parameters: const + 6 features)
    np.random.seed(42)
    n_samples = 200
    X = np.random.randn(n_samples, 6)
    X_const = sm.add_constant(X)
    true_beta = np.array([-1.5, 0.8, -0.2, 0.4, 0.6, 1.2, 0.9])
    logits = X_const @ true_beta
    probs = 1.0 / (1.0 + np.exp(-logits))
    y = np.random.binomial(1, probs, n_samples)
    logit_model = sm.Logit(y, X_const).fit(disp=False)

    # 2. Log and register model in MLflow Model Registry
    model_name = "E2EFraudDetectionModel"
    with mlflow.start_run() as run:
        mlflow.statsmodels.log_model(
            logit_model,
            artifact_path="model",
            registered_model_name=model_name
        )
        run_id = run.info.run_id

    # 3. Cryptographically authenticate the logged artifact package (Producer)
    client = mlflow.tracking.MlflowClient()
    model_version = client.get_model_version(model_name, "1")
    logged_model_dir = Path(mlflow.artifacts.download_artifacts(artifact_uri=model_version.source))

    signer = ModelProducerSigner(
        private_key_path=config.PRIVATE_KEY_FILE,
        public_key_path=config.PUBLIC_KEY_FILE
    )
    manifest_sig_path = signer.sign_mlflow_package(logged_model_dir)

    yield {
        "workspace": tmp_workspace,
        "run_id": run_id,
        "model_name": model_name,
        "model_source_uri": model_version.source,
        "logged_model_dir": logged_model_dir,
        "manifest_sig_path": manifest_sig_path,
        "logit_model": logit_model,
        "signer": signer
    }

    # Teardown
    shutil.rmtree(tmp_workspace, ignore_errors=True)
    for p in config.ARTIFACTS_DIR.glob("e2e_*"):
        if p.is_dir():
            shutil.rmtree(p, ignore_errors=True)
        elif p.is_file():
            p.unlink(missing_ok=True)


@pytest.fixture(autouse=True)
def configure_admin_env():
    old_token = os.environ.get("MLOPS_ADMIN_TOKEN")
    os.environ["MLOPS_ADMIN_TOKEN"] = TEST_ADMIN_TOKEN
    yield
    if old_token is not None:
        os.environ["MLOPS_ADMIN_TOKEN"] = old_token
    else:
        os.environ.pop("MLOPS_ADMIN_TOKEN", None)


class TestMLflowRegistrySecurityGateE2E:
    """
    End-to-end integration test validating the complete lifecycle:
      MLflow Model Registry -> Model Retrieval via MLflow API ->
      Cryptographic Security Gate Manifest Verification ->
      Isolated Temporary Sandbox Deserialization -> Live Inference & Hot-Reload.
    """

    def test_end_to_end_registry_download_verification_and_inference(self, e2e_pipeline_fixtures):
        """
        Validates legitimate promotion: Model Registry download passes cryptographic
        manifest verification and serves correct fraud predictions.
        """
        source_uri = e2e_pipeline_fixtures["model_source_uri"]
        download_target_parent = config.ARTIFACTS_DIR / "e2e_consumer_download"
        if download_target_parent.exists():
            shutil.rmtree(download_target_parent)
        download_target_parent.mkdir(parents=True, exist_ok=True)

        # 1. Download registered model artifact package using official MLflow API
        downloaded_path = Path(
            mlflow.artifacts.download_artifacts(
                artifact_uri=source_uri,
                dst_path=str(download_target_parent)
            )
        )
        assert downloaded_path.exists()
        assert (downloaded_path / "MLmodel").exists()
        assert (downloaded_path / "model.statsmodels").exists()
        assert (downloaded_path / "mlflow_manifest.json").exists()
        assert (downloaded_path / "mlflow_manifest.json.sig").exists()

        # 2. Security Gate Verification with Public Key Only
        verifier = ModelConsumerVerifier(public_key_path=config.PUBLIC_KEY_FILE)
        verification_res = verifier.verify_mlflow_package(downloaded_path)
        assert verification_res.is_valid is True
        assert verification_res.status == "PACKAGE_AUTHORIZED"

        # 3. Load into FraudInferenceService in protected MLflow mode
        service = FraudInferenceService(
            mode="mlflow_statsmodels",
            model_path=downloaded_path
        )
        assert service.verification_passed is True
        assert service.signature_verified is True
        assert service.model is not None

        # 4. Execute prediction
        sample_features = {
            "amount": 250.0,
            "transaction_hour": 3.0,
            "distance_from_home": 45.0,
            "velocity_last_24h": 5.0,
            "foreign_transaction": 1.0,
            "high_risk_merchant": 1.0
        }
        pred = service.predict_features(sample_features)
        assert "is_fraud" in pred
        assert pred["is_fraud"] in (0, 1)
        assert 0.0 <= pred["fraud_probability"] <= 1.0

    def test_fastapi_hot_reload_and_prediction_endpoint_e2e(self, e2e_pipeline_fixtures):
        """
        Validates FastAPI endpoint integration: Authenticated /reload endpoint
        fetches and validates the MLflow package, then serves /predict requests.
        """
        source_uri = e2e_pipeline_fixtures["model_source_uri"]
        staging_dir = config.ARTIFACTS_DIR / "e2e_api_staging"
        if staging_dir.exists():
            shutil.rmtree(staging_dir)
        staging_dir.mkdir(parents=True, exist_ok=True)

        downloaded_package = Path(
            mlflow.artifacts.download_artifacts(
                artifact_uri=source_uri,
                dst_path=str(staging_dir)
            )
        )

        with TestClient(app) as client:
            reload_res = client.post(
                "/reload",
                headers=ADMIN_HEADERS,
                json={
                    "mode": "mlflow_statsmodels",
                    "model_path": str(downloaded_package)
                }
            )
            assert reload_res.status_code == 200, reload_res.text
            body = reload_res.json()
            assert body["status"] == "SUCCESS"
            assert body["verification_passed"] is True
            assert body["signature_verified"] is True

            # Verify /predict endpoint against the active reloaded model
            predict_res = client.post(
                "/predict",
                json={
                    "amount": 15.0,
                    "transaction_hour": 13.0,
                    "distance_from_home": 2.0,
                    "velocity_last_24h": 1,
                    "foreign_transaction": 0,
                    "high_risk_merchant": 0
                }
            )
            assert predict_res.status_code == 200
            pred_data = predict_res.json()
            assert pred_data["is_fraud"] in (0, 1)
            assert 0.0 <= pred_data["fraud_probability"] <= 1.0

    def test_negative_tampered_model_binary_rejected_fail_closed(self, e2e_pipeline_fixtures):
        """
        Negative test: Tampering with the model binary in the downloaded package
        triggers SecurityError and preserves active model state atomically.
        """
        source_uri = e2e_pipeline_fixtures["model_source_uri"]
        tamper_dir = config.ARTIFACTS_DIR / "e2e_tampered_binary"
        if tamper_dir.exists():
            shutil.rmtree(tamper_dir)
        tamper_dir.mkdir(parents=True, exist_ok=True)

        pkg_dir = Path(
            mlflow.artifacts.download_artifacts(
                artifact_uri=source_uri,
                dst_path=str(tamper_dir)
            )
        )
        model_file = pkg_dir / "model.statsmodels"
        assert model_file.exists()

        # Tamper binary: flip bytes
        content = bytearray(model_file.read_bytes())
        content[10] ^= 0xFF
        model_file.write_bytes(content)

        # 1. Gate verification must reject the tampered package
        verifier = ModelConsumerVerifier(public_key_path=config.PUBLIC_KEY_FILE)
        res = verifier.verify_mlflow_package(pkg_dir)
        assert res.is_valid is False
        assert res.status in ("FILE_TAMPERED", "HASH_MISMATCH")

        # 2. Direct FraudInferenceService load must fail closed
        with pytest.raises(SecurityError) as exc_info:
            FraudInferenceService(
                mode="mlflow_statsmodels",
                model_path=pkg_dir
            )
        assert "manifest verification failed" in str(exc_info.value).lower()

        # 3. Atomic reload via FastAPI: Service state must remain intact
        with TestClient(app) as client:
            # Baseline predict before failed reload
            base_pred = client.post(
                "/predict",
                json={"amount": 50.0, "transaction_hour": 10.0}
            )
            assert base_pred.status_code == 200

            # Attempt reload with tampered package
            reload_res = client.post(
                "/reload",
                headers=ADMIN_HEADERS,
                json={
                    "mode": "mlflow_statsmodels",
                    "model_path": str(pkg_dir)
                }
            )
            assert reload_res.status_code == 403
            reload_err = reload_res.json()
            assert reload_err["detail"]["status"] == "REJECTED"
            assert reload_err["detail"]["verification_passed"] is False

            # Active service must still function without disruption
            post_pred = client.post(
                "/predict",
                json={"amount": 50.0, "transaction_hour": 10.0}
            )
            assert post_pred.status_code == 200
            assert post_pred.json()["fraud_probability"] == base_pred.json()["fraud_probability"]

    def test_negative_tampered_mlmodel_descriptor_rejected(self, e2e_pipeline_fixtures):
        """
        Negative test: Tampering with MLmodel configuration (e.g. attempting to redirect
        the loader or inject malicious parameters) is detected and blocked before load.
        """
        source_uri = e2e_pipeline_fixtures["model_source_uri"]
        tamper_dir = config.ARTIFACTS_DIR / "e2e_tampered_mlmodel"
        if tamper_dir.exists():
            shutil.rmtree(tamper_dir)
        tamper_dir.mkdir(parents=True, exist_ok=True)

        pkg_dir = Path(
            mlflow.artifacts.download_artifacts(
                artifact_uri=source_uri,
                dst_path=str(tamper_dir)
            )
        )
        mlmodel_file = pkg_dir / "MLmodel"
        assert mlmodel_file.exists()

        # Tamper MLmodel content
        lines = mlmodel_file.read_text(encoding="utf-8").splitlines()
        lines.append("injected_unauthorized_key: malicious_value")
        mlmodel_file.write_text("\n".join(lines), encoding="utf-8")

        verifier = ModelConsumerVerifier(public_key_path=config.PUBLIC_KEY_FILE)
        res = verifier.verify_mlflow_package(pkg_dir)
        assert res.is_valid is False
        assert res.status in ("FILE_TAMPERED", "HASH_MISMATCH")

        with pytest.raises(SecurityError):
            FraudInferenceService(mode="mlflow_statsmodels", model_path=pkg_dir)

    def test_negative_omitted_manifest_or_signature_rejected(self, e2e_pipeline_fixtures):
        """
        Negative test: A model package without manifest or without manifest signature
        is strictly rejected under protected MLflow policy (no single-file fallback).
        """
        source_uri = e2e_pipeline_fixtures["model_source_uri"]
        unsigned_pkg_dir = config.ARTIFACTS_DIR / "e2e_omitted_manifest"
        if unsigned_pkg_dir.exists():
            shutil.rmtree(unsigned_pkg_dir)
        unsigned_pkg_dir.mkdir(parents=True, exist_ok=True)

        pkg_dir = Path(
            mlflow.artifacts.download_artifacts(
                artifact_uri=source_uri,
                dst_path=str(unsigned_pkg_dir)
            )
        )

        # Remove signature file
        sig_file = pkg_dir / "mlflow_manifest.json.sig"
        assert sig_file.exists()
        sig_file.unlink()

        verifier = ModelConsumerVerifier(public_key_path=config.PUBLIC_KEY_FILE)
        res = verifier.verify_mlflow_package(pkg_dir)
        assert res.is_valid is False
        assert "MISSING_SIGNATURE" in res.status

        with pytest.raises(SecurityError) as exc_info:
            FraudInferenceService(mode="mlflow_statsmodels", model_path=pkg_dir)
        assert "disallowed under protected mlflow security policy" in str(exc_info.value).lower()

    def test_consumer_privilege_separation_and_polp(self, e2e_pipeline_fixtures):
        """
        Verifies Principle of Least Privilege: ModelConsumerVerifier operates strictly
        with public key material and has no private signing keys or capabilities.
        """
        consumer_key_dir = Path(tempfile.mkdtemp(prefix="consumer_keys_"))
        public_key_copy = consumer_key_dir / "public_key.pem"
        shutil.copy2(config.PUBLIC_KEY_FILE, public_key_copy)

        # 1. Consumer verifier works with isolated public key alone
        isolated_verifier = ModelConsumerVerifier(public_key_path=public_key_copy)
        logged_dir = e2e_pipeline_fixtures["logged_model_dir"]
        res = isolated_verifier.verify_mlflow_package(logged_dir)
        assert res.is_valid is True

        # 2. Consumer possesses no signing interface or private key attributes
        assert not hasattr(isolated_verifier, "private_key")
        assert not hasattr(isolated_verifier, "sign")
        assert not hasattr(isolated_verifier, "sign_artifact")
        assert not hasattr(isolated_verifier, "sign_mlflow_package")

        # 3. ModelProducerSigner cannot be instantiated in consumer environment
        non_existent_priv_key = consumer_key_dir / "private_key.pem"
        assert not non_existent_priv_key.exists()
        with pytest.raises(FileNotFoundError):
            ModelProducerSigner(
                private_key_path=non_existent_priv_key,
                public_key_path=public_key_copy
            )

        shutil.rmtree(consumer_key_dir, ignore_errors=True)
