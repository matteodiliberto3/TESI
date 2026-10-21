import pytest
import numpy as np
import pandas as pd
from pathlib import Path

import config
from data.generate_dataset import generate_synthetic_transactions
from feature_store.store import FeatureStore
from feature_store.validator import FeatureStoreValidator
from pipeline.crypto_signer import ArtifactSigner
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
