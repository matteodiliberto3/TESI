import pytest
import numpy as np
import pandas as pd
from pathlib import Path

import config
from data.generate_dataset import generate_synthetic_transactions
from feature_store.store import FeatureStore
from feature_store.validator import FeatureStoreValidator
from pipeline.crypto_signer import (
    ArtifactSigner,
    ModelProducerSigner,
    ModelConsumerVerifier,
    generate_keypair
)
from pipeline.train import train_classifier, save_model_safetensors, load_model_safetensors

def test_data_generation():
    df = generate_synthetic_transactions(n_samples=200, fraud_ratio=0.1)
    assert len(df) == 200
    assert config.TARGET_COLUMN in df.columns
    for col in config.FEATURE_COLUMNS:
        assert col in df.columns

def test_feature_store_and_validation():
    df = generate_synthetic_transactions(n_samples=100)
    fs = FeatureStore(config.FEATURE_STORE_DIR / "test_store")
    fs.validator.fit_baseline(df)

    # Ingest clean data in unhardened mode: all records accepted
    status_raw = fs.ingest(df, hardened=False)
    assert status_raw["accepted_records"] == 100
    assert status_raw["rejected_records"] == 0

    # Inject deliberate massive anomaly (Z-score >> threshold)
    anom_df = df.head(5).copy()
    anom_df["distance_from_home"] = 9999.0
    status_anom = fs.ingest(anom_df, hardened=True)
    assert status_anom["rejected_records"] == 5
    assert len(status_anom["security_alerts"]) > 0

def test_crypto_signature(tmp_path: Path):
    dummy_file = tmp_path / "model.bin"
    dummy_file.write_bytes(b"TEST_MODEL_BYTES_12345")
    sig_file = tmp_path / "model.sig"

    # Keys must be explicitly provisioned beforehand
    generate_keypair(tmp_path / "priv.pem", tmp_path / "pub.pem")

    signer = ArtifactSigner(
        private_key_path=tmp_path / "priv.pem",
        public_key_path=tmp_path / "pub.pem"
    )

    signer.sign_artifact(dummy_file, sig_file)
    assert sig_file.exists()
    assert signer.verify_artifact(dummy_file, sig_file) is True

    # Tamper with file
    dummy_file.write_bytes(b"TAMPERED_BYTES_XYZ")
    assert signer.verify_artifact(dummy_file, sig_file) is False

def test_safetensors_roundtrip(tmp_path: Path):
    df = generate_synthetic_transactions(n_samples=200)
    model, _, _ = train_classifier(df)
    
    safetensor_file = tmp_path / "test_model.safetensors"
    save_model_safetensors(model, safetensor_file)
    assert safetensor_file.exists()

    loaded_model = load_model_safetensors(safetensor_file)
    assert loaded_model is not None
    assert np.allclose(model.coef_, loaded_model.coef_)
    assert np.allclose(model.intercept_, loaded_model.intercept_)

def test_producer_consumer_key_segregation(tmp_path: Path):
    """Verifies that consumer only holds public key and cannot sign, but correctly verifies producer signatures."""
    producer_key = tmp_path / "prod_priv.pem"
    pub_key = tmp_path / "pub.pem"

    # 1. Producer must fail closed if private key is not provisioned
    with pytest.raises(FileNotFoundError):
        ModelProducerSigner(private_key_path=producer_key, public_key_path=pub_key)

    # 2. Provision keys explicitly
    generate_keypair(producer_key, pub_key)
    producer = ModelProducerSigner(private_key_path=producer_key, public_key_path=pub_key)
    
    # 3. Consumer only receives public key
    consumer = ModelConsumerVerifier(public_key_path=pub_key)
    
    model_artifact = tmp_path / "model.bin"
    model_artifact.write_bytes(b"AUTHENTIC_TRAINED_MODEL")
    sig_path = tmp_path / "model.sig"
    
    producer.sign(model_artifact, sig_path)
    assert sig_path.exists()
    
    # Consumer verifies successfully
    assert consumer.verify(model_artifact, sig_path) is True
    
    # Consumer cannot sign because it lacks private key
    with pytest.raises(AttributeError):
        consumer.sign(model_artifact, sig_path)

def test_online_store_event_timestamp_conflict(tmp_path: Path):
    """Verifies that an out-of-order older transaction does not overwrite a newer transaction."""
    fs = FeatureStore(tmp_path / "ts_store")
    
    # Ingest newer transaction (timestamp = 200.0)
    df_new = pd.DataFrame([{
        "entity_user_id": "user_ts_test",
        "amount": 100.0,
        "transaction_hour": 14.0,
        "distance_from_home": 5.0,
        "velocity_last_24h": 2,
        "foreign_transaction": 0,
        "high_risk_merchant": 0,
        "event_timestamp": 200.0,
        "is_fraud": 0
    }])
    fs.ingest(df_new, hardened=False)
    
    features = fs.get_online_features("user_ts_test")
    assert features["amount"] == 100.0
    
    # Ingest older transaction for same user arriving late (timestamp = 100.0)
    df_old = pd.DataFrame([{
        "entity_user_id": "user_ts_test",
        "amount": 999.0,
        "transaction_hour": 10.0,
        "distance_from_home": 50.0,
        "velocity_last_24h": 1,
        "foreign_transaction": 0,
        "high_risk_merchant": 0,
        "event_timestamp": 100.0,
        "is_fraud": 0
    }])
    fs.ingest(df_old, hardened=False)
    
    # Value must remain 100.0 (newer event time preserved)
    features_after = fs.get_online_features("user_ts_test")
    assert features_after["amount"] == 100.0

def test_in_memory_verified_pickle_toctou_prevention(tmp_path: Path):
    """
    Tests atomic in-memory verification and deserialization (Chapter 5 / RQ1 hardening).
    Proves elimination of the Time-of-Check to Time-of-Use (TOCTOU) race condition:
    the byte buffer verified against the RSA-PSS signature is unpickled directly from memory.
    """
    import pickle
    from sklearn.linear_model import LogisticRegression

    priv_key = tmp_path / "priv.pem"
    pub_key = tmp_path / "pub.pem"
    generate_keypair(priv_key, pub_key)

    producer = ModelProducerSigner(private_key_path=priv_key, public_key_path=pub_key)
    consumer = ModelConsumerVerifier(public_key_path=pub_key)

    # 1. Producer serializes and signs a model
    model = LogisticRegression()
    model.coef_ = np.array([[0.5, -0.2, 1.1, 0.05, 0.8, 1.4]])
    model.intercept_ = np.array([-0.3])
    model.classes_ = np.array([0, 1])

    artifact_file = tmp_path / "model.pkl"
    sig_file = tmp_path / "model.sig"

    with open(artifact_file, "wb") as f:
        pickle.dump(model, f)
    producer.sign(artifact_file, sig_file)

    # 2. Consumer atomically loads verified model directly from memory
    loaded_model = consumer.load_verified_pickle(artifact_file, sig_file)
    assert isinstance(loaded_model, LogisticRegression)
    assert np.allclose(loaded_model.coef_, model.coef_)

    # 3. Tampered artifact fails closed
    artifact_file.write_bytes(b"MALICIOUS_TAMPERED_PAYLOAD")
    with pytest.raises(PermissionError):
        consumer.load_verified_pickle(artifact_file, sig_file)


def test_audit_persisted_artifacts_and_statistical_schemas():
    """
    Academic audit test (Issues C-01, C-02, C-05, C-08):
    Validates presence and schema compliance of persisted per-seed evasion artifacts
    and causal ablation results with in-bag mechanistic tracking and Wilcoxon/Bootstrap diagnostics.
    """
    import json
    
    # 1. RQ3 Evasion per-seed persistence (Archived legacy artifacts)
    legacy_reports_dir = config.BASE_DIR / "archive_legacy_thesis" / "reports"
    evasion_json = legacy_reports_dir / "evasion_results.json"
    assert evasion_json.exists(), "archive_legacy_thesis/reports/evasion_results.json must exist"
    with open(evasion_json, encoding="utf-8") as f:
        ev_data = json.load(f)
    for strat in ["naive_outlier", "sub_threshold_univariate", "multivariate_pattern"]:
        assert strat in ev_data
        assert "summary" in ev_data[strat]
        assert "seed_results" in ev_data[strat]
        assert len(ev_data[strat]["seed_results"]) >= 3
        s0 = ev_data[strat]["seed_results"][0]
        assert "seed" in s0 and "asr_unhardened" in s0 and "clean_fraud_recall" in s0

    # 2. RQ2 Causal ablation mechanistic and non-parametric diagnostics (Archived legacy artifacts)
    ablation_json = legacy_reports_dir / "causal_ablation_results.json"
    assert ablation_json.exists(), "archive_legacy_thesis/reports/causal_ablation_results.json must exist"
    with open(ablation_json, encoding="utf-8") as f:
        ab_data = json.load(f)
    
    # Mechanistic summary fields
    mech = ab_data["rf_mechanistic_summary"]
    for key in [
        "fraud_switch_rate_mean",
        "geometric_colocation_rate_mean",
        "in_bag_colocation_rate_mean",
        "negative_control_geometric_colocation_rate_mean",
        "negative_control_in_bag_colocation_rate_mean"
    ]:
        assert key in mech
    assert mech["in_bag_colocation_rate_mean"] > 0.90
    assert mech["negative_control_in_bag_colocation_rate_mean"] < 0.10

    # Statistical tests diagnostics
    stats_rf = ab_data["statistical_tests"]["RandomForest"]["trig_flip_vs_pure_flip_matched"]
    for diag in ["n_zero_diffs", "wilcoxon_stat", "wilcoxon_p_value", "bootstrap_ci95_low", "bootstrap_ci95_high", "omnibus_significant_16"]:
        assert diag in stats_rf
