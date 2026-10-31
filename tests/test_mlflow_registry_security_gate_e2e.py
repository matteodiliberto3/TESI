import os
import sys
import uuid
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
    generate_keypair,
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
    Sets up a fully self-contained, isolated end-to-end MLflow Tracking Server
    with dedicated SQLite backend store, isolated ephemeral RSA keypair,
    explicit artifact storage location, and trained Statsmodels Logit model.

    Guarantees 100% test autonomy and clean state restoration:
      - Preserves and restores global mlflow tracking URI and registry URI.
      - Uses local NumPy default_rng(42) to eliminate global random state pollution.
      - Avoids global mlflow.set_experiment() by passing experiment_id directly to runs.
      - Tracks active runs and terminates only the test's specific run on teardown.
      - Generates temporary 2048-bit RSA keys (no reliance on repo artifacts/keys).
      - Confines all downloads and staging to a private workspace (no artifacts/ pollution).
      - Preserves and restores FastAPI serve_module.service, config paths, and MLOPS_ADMIN_TOKEN.
      - Wraps entire lifecycle in comprehensive try/finally for failure resilience.
    """
    # 1. Capture initial global states before any modification
    old_tracking_uri = mlflow.get_tracking_uri()
    old_registry_uri = mlflow.get_registry_uri()
    old_service = serve_module.service
    old_admin_token = os.environ.get("MLOPS_ADMIN_TOKEN")
    orig_pub_key = config.PUBLIC_KEY_FILE
    orig_priv_key = config.PRIVATE_KEY_FILE
    orig_artifacts_dir = config.ARTIFACTS_DIR

    tmp_workspace = None
    created_run_id = None

    try:
        tmp_workspace = Path(tempfile.mkdtemp(prefix="mlflow_e2e_isolated_"))
        db_file = tmp_workspace / "mlflow_registry.db"
        artifacts_root = tmp_workspace / "mlflow_artifacts"
        artifacts_root.mkdir(parents=True, exist_ok=True)
        consumer_artifacts = tmp_workspace / "consumer_artifacts"
        consumer_artifacts.mkdir(parents=True, exist_ok=True)
        keys_dir = tmp_workspace / "keys"
        keys_dir.mkdir(parents=True, exist_ok=True)

        # 2. Ephemeral Dedicated RSA Keypair (Decoupled from global lab state)
        test_priv_key = keys_dir / "private_key.pem"
        test_pub_key = keys_dir / "public_key.pem"
        generate_keypair(
            private_key_path=test_priv_key,
            public_key_path=test_pub_key,
            key_size=2048,
            overwrite=True
        )

        # 3. Patch Config to Confine Execution into Temporary Workspace
        config.PUBLIC_KEY_FILE = test_pub_key
        config.PRIVATE_KEY_FILE = test_priv_key
        config.ARTIFACTS_DIR = consumer_artifacts
        os.environ["MLOPS_ADMIN_TOKEN"] = TEST_ADMIN_TOKEN

        tracking_uri = f"sqlite:///{db_file.as_posix()}"
        mlflow.set_tracking_uri(tracking_uri)
        mlflow.set_registry_uri(tracking_uri)

        experiment_name = f"e2e_gate_exp_{uuid.uuid4().hex[:8]}"
        experiment_id = mlflow.create_experiment(
            name=experiment_name,
            artifact_location=artifacts_root.as_uri()
        )

        # 4. Train legitimate Statsmodels Logit Model with local RNG
        rng = np.random.default_rng(42)
        n_samples = 200
        X = rng.standard_normal((n_samples, 6))
        X_const = sm.add_constant(X)
        true_beta = np.array([-1.5, 0.8, -0.2, 0.4, 0.6, 1.2, 0.9])
        logits = X_const @ true_beta
        probs = 1.0 / (1.0 + np.exp(-logits))
        y = rng.binomial(1, probs, n_samples)
        logit_model = sm.Logit(y, X_const).fit(disp=False)

        # 5. Log and register model in MLflow Model Registry using explicit experiment_id
        model_name = "E2EFraudDetectionModel"
        with mlflow.start_run(experiment_id=experiment_id) as run:
            created_run_id = run.info.run_id
            mlflow.statsmodels.log_model(
                logit_model,
                artifact_path="model",
                registered_model_name=model_name
            )

        # 6. Cryptographically authenticate the logged artifact package (Producer)
        client = mlflow.tracking.MlflowClient()
        model_version = client.get_model_version(model_name, "1")
        logged_model_dir = Path(mlflow.artifacts.download_artifacts(artifact_uri=model_version.source))
        assert logged_model_dir.is_dir()
        assert (logged_model_dir / "MLmodel").is_file()
        assert (logged_model_dir / "model.statsmodels").is_file()

        signer = ModelProducerSigner(
            private_key_path=test_priv_key,
            public_key_path=test_pub_key
        )
        manifest_sig_path = signer.sign_mlflow_package(logged_model_dir)

        # Pre-stage a verified, immutable baseline model package in consumer_artifacts
        baseline_staging_parent = consumer_artifacts / "e2e_active_baseline_model"
        baseline_staging_parent.mkdir(parents=True, exist_ok=True)
        baseline_model_dir = Path(
            mlflow.artifacts.download_artifacts(
                artifact_uri=model_version.source,
                dst_path=str(baseline_staging_parent)
            )
        )
        assert baseline_model_dir.is_dir()
        assert (baseline_model_dir / "MLmodel").is_file()
        assert (baseline_model_dir / "mlflow_manifest.json").is_file()
        assert (baseline_model_dir / "mlflow_manifest.json.sig").is_file()
        assert (baseline_model_dir / "model.statsmodels").is_file()

        yield {
            "workspace": tmp_workspace,
            "run_id": created_run_id,
            "model_name": model_name,
            "model_source_uri": model_version.source,
            "logged_model_dir": logged_model_dir,
            "baseline_model_dir": baseline_model_dir,
            "manifest_sig_path": manifest_sig_path,
            "logit_model": logit_model,
            "signer": signer,
            "test_pub_key": test_pub_key,
            "test_priv_key": test_priv_key,
            "consumer_artifacts": consumer_artifacts
        }

    finally:
        # 7. Guaranteed Teardown and Complete Environment Restoration
        if created_run_id:
            active_run = mlflow.active_run()
            if active_run and active_run.info.run_id == created_run_id:
                mlflow.end_run()

        try:
            if old_tracking_uri is not None:
                mlflow.set_tracking_uri(old_tracking_uri)
            if old_registry_uri is not None:
                mlflow.set_registry_uri(old_registry_uri)
        except Exception as exc:
            sys.stderr.write(f"[Teardown Warning] Failed to restore MLflow URIs: {exc}\n")

        serve_module.service = old_service

        if old_admin_token is not None:
            os.environ["MLOPS_ADMIN_TOKEN"] = old_admin_token
        else:
            os.environ.pop("MLOPS_ADMIN_TOKEN", None)

        config.PUBLIC_KEY_FILE = orig_pub_key
        config.PRIVATE_KEY_FILE = orig_priv_key
        config.ARTIFACTS_DIR = orig_artifacts_dir

        if tmp_workspace and tmp_workspace.exists():
            shutil.rmtree(tmp_workspace, ignore_errors=True)


class TestMLflowRegistrySecurityGateE2E:
    """
    End-to-end integration test validating the complete lifecycle:
      MLflow Model Registry (SQLite backend) -> Model Retrieval via MLflow API ->
      Cryptographic Security Gate Manifest Verification (RSA-PSS) ->
      Isolated Temporary Sandbox Deserialization -> Live Inference & Hot-Reload.
    """

    @pytest.fixture(autouse=True)
    def isolate_service_state(self, e2e_pipeline_fixtures):
        """
        Initializes serve_module.service with a legitimate candidate verified by the
        ephemeral public key prior to each test method, and resets it in teardown.
        Eliminates cross-test ordering dependencies and provides an active verified model.
        """
        baseline_dir = e2e_pipeline_fixtures["baseline_model_dir"]
        test_pub_key = e2e_pipeline_fixtures["test_pub_key"]

        baseline_service = FraudInferenceService(
            mode="mlflow_statsmodels",
            model_path=baseline_dir,
            public_key_path=test_pub_key
        )
        assert baseline_service.verification_passed is True
        assert baseline_service.signature_verified is True
        assert baseline_service.model is not None

        serve_module.service = baseline_service

        yield baseline_service

        serve_module.service = None

    def test_end_to_end_registry_download_verification_and_inference(self, e2e_pipeline_fixtures):
        """
        Validates legitimate promotion: Model Registry download passes cryptographic
        manifest verification and serves correct fraud predictions.
        """
        source_uri = e2e_pipeline_fixtures["model_source_uri"]
        test_pub_key = e2e_pipeline_fixtures["test_pub_key"]
        download_target_parent = e2e_pipeline_fixtures["consumer_artifacts"] / "e2e_consumer_download"
        download_target_parent.mkdir(parents=True, exist_ok=True)

        # 1. Download registered model artifact package using official MLflow API
        downloaded_path = Path(
            mlflow.artifacts.download_artifacts(
                artifact_uri=source_uri,
                dst_path=str(download_target_parent)
            )
        )
        assert downloaded_path.is_dir()
        assert (downloaded_path / "MLmodel").is_file()
        assert (downloaded_path / "model.statsmodels").is_file()
        assert (downloaded_path / "mlflow_manifest.json").is_file()
        assert (downloaded_path / "mlflow_manifest.json.sig").is_file()

        # 2. Security Gate Verification with Public Key Only
        verifier = ModelConsumerVerifier(public_key_path=test_pub_key)
        verification_res = verifier.verify_mlflow_package(downloaded_path)
        assert verification_res.is_valid is True
        assert verification_res.status == "PACKAGE_AUTHORIZED"

        # 3. Load into FraudInferenceService in protected MLflow mode
        service = FraudInferenceService(
            mode="mlflow_statsmodels",
            model_path=downloaded_path,
            public_key_path=test_pub_key
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
        staging_dir = e2e_pipeline_fixtures["consumer_artifacts"] / "e2e_api_staging"
        staging_dir.mkdir(parents=True, exist_ok=True)

        downloaded_package = Path(
            mlflow.artifacts.download_artifacts(
                artifact_uri=source_uri,
                dst_path=str(staging_dir)
            )
        )
        assert downloaded_package.is_dir()
        assert (downloaded_package / "MLmodel").is_file()
        assert (downloaded_package / "mlflow_manifest.json").is_file()
        assert (downloaded_package / "mlflow_manifest.json.sig").is_file()
        assert (downloaded_package / "model.statsmodels").is_file()

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
        Verifies exact object identity preservation on failed rollback.
        """
        source_uri = e2e_pipeline_fixtures["model_source_uri"]
        test_pub_key = e2e_pipeline_fixtures["test_pub_key"]
        baseline_dir = e2e_pipeline_fixtures["baseline_model_dir"]
        tamper_dir = e2e_pipeline_fixtures["consumer_artifacts"] / "e2e_tampered_binary"
        tamper_dir.mkdir(parents=True, exist_ok=True)

        pkg_dir = Path(
            mlflow.artifacts.download_artifacts(
                artifact_uri=source_uri,
                dst_path=str(tamper_dir)
            )
        )
        assert pkg_dir.is_dir()
        model_file = pkg_dir / "model.statsmodels"
        assert model_file.is_file()

        # Tamper binary: flip bytes on separate copy
        content = bytearray(model_file.read_bytes())
        content[10] ^= 0xFF
        model_file.write_bytes(content)

        # 1. Gate verification must reject the tampered package
        verifier = ModelConsumerVerifier(public_key_path=test_pub_key)
        res = verifier.verify_mlflow_package(pkg_dir)
        assert res.is_valid is False
        assert res.status in ("FILE_TAMPERED", "HASH_MISMATCH")

        # 2. Direct FraudInferenceService load must fail closed
        with pytest.raises(SecurityError) as exc_info:
            FraudInferenceService(
                mode="mlflow_statsmodels",
                model_path=pkg_dir,
                public_key_path=test_pub_key
            )
        assert "manifest verification failed" in str(exc_info.value).lower()

        # 3. Atomic reload via FastAPI: Service state must remain intact
        with TestClient(app) as client:
            # Explicitly initialize baseline within TestClient context to prevent lifespan override
            baseline_service = FraudInferenceService(
                mode="mlflow_statsmodels",
                model_path=baseline_dir,
                public_key_path=test_pub_key
            )
            serve_module.service = baseline_service
            assert baseline_service is not None
            assert baseline_service.verification_passed is True
            assert baseline_service.signature_verified is True
            assert baseline_service.model is not None

            # Baseline predict before failed reload
            base_pred = client.post(
                "/predict",
                json={"amount": 50.0, "transaction_hour": 10.0}
            )
            assert base_pred.status_code == 200
            base_prob = base_pred.json()["fraud_probability"]

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

            # Strict identity check: active service instance is exactly the baseline instance
            assert serve_module.service is baseline_service

            # Active service must still function without disruption and yield identical prediction
            post_pred = client.post(
                "/predict",
                json={"amount": 50.0, "transaction_hour": 10.0}
            )
            assert post_pred.status_code == 200
            assert post_pred.json()["fraud_probability"] == base_prob

    def test_negative_tampered_mlmodel_descriptor_rejected(self, e2e_pipeline_fixtures):
        """
        Negative test: Tampering with MLmodel configuration (e.g. attempting to redirect
        the loader or inject malicious parameters) is detected and blocked before load.
        """
        source_uri = e2e_pipeline_fixtures["model_source_uri"]
        test_pub_key = e2e_pipeline_fixtures["test_pub_key"]
        tamper_dir = e2e_pipeline_fixtures["consumer_artifacts"] / "e2e_tampered_mlmodel"
        tamper_dir.mkdir(parents=True, exist_ok=True)

        pkg_dir = Path(
            mlflow.artifacts.download_artifacts(
                artifact_uri=source_uri,
                dst_path=str(tamper_dir)
            )
        )
        assert pkg_dir.is_dir()
        mlmodel_file = pkg_dir / "MLmodel"
        assert mlmodel_file.is_file()

        # Tamper MLmodel content on separate copy
        lines = mlmodel_file.read_text(encoding="utf-8").splitlines()
        lines.append("injected_unauthorized_key: malicious_value")
        mlmodel_file.write_text("\n".join(lines), encoding="utf-8")

        verifier = ModelConsumerVerifier(public_key_path=test_pub_key)
        res = verifier.verify_mlflow_package(pkg_dir)
        assert res.is_valid is False
        assert res.status in ("FILE_TAMPERED", "HASH_MISMATCH")

        with pytest.raises(SecurityError):
            FraudInferenceService(
                mode="mlflow_statsmodels",
                model_path=pkg_dir,
                public_key_path=test_pub_key
            )

    def test_negative_omitted_manifest_or_signature_rejected(self, e2e_pipeline_fixtures):
        """
        Negative test: A model package without manifest or without manifest signature
        is strictly rejected under protected MLflow policy (no single-file fallback).
        """
        source_uri = e2e_pipeline_fixtures["model_source_uri"]
        test_pub_key = e2e_pipeline_fixtures["test_pub_key"]
        unsigned_pkg_dir = e2e_pipeline_fixtures["consumer_artifacts"] / "e2e_omitted_manifest"
        unsigned_pkg_dir.mkdir(parents=True, exist_ok=True)

        pkg_dir = Path(
            mlflow.artifacts.download_artifacts(
                artifact_uri=source_uri,
                dst_path=str(unsigned_pkg_dir)
            )
        )
        assert pkg_dir.is_dir()

        # Remove signature file from separate copy
        sig_file = pkg_dir / "mlflow_manifest.json.sig"
        assert sig_file.is_file()
        sig_file.unlink()

        verifier = ModelConsumerVerifier(public_key_path=test_pub_key)
        res = verifier.verify_mlflow_package(pkg_dir)
        assert res.is_valid is False
        assert "MISSING_SIGNATURE" in res.status

        with pytest.raises(SecurityError) as exc_info:
            FraudInferenceService(
                mode="mlflow_statsmodels",
                model_path=pkg_dir,
                public_key_path=test_pub_key
            )
        assert "disallowed under protected mlflow security policy" in str(exc_info.value).lower()

    def test_consumer_privilege_separation_and_polp(self, e2e_pipeline_fixtures):
        """
        Verifies Principle of Least Privilege: ModelConsumerVerifier operates strictly
        with public key material and has no private signing keys or capabilities.
        """
        test_pub_key = e2e_pipeline_fixtures["test_pub_key"]
        consumer_key_dir = Path(tempfile.mkdtemp(prefix="consumer_keys_"))
        try:
            public_key_copy = consumer_key_dir / "public_key.pem"
            shutil.copy2(test_pub_key, public_key_copy)

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
        finally:
            shutil.rmtree(consumer_key_dir, ignore_errors=True)
