import pickle
from pathlib import Path
from typing import Dict, Any, Optional
import numpy as np

import config
from feature_store.store import FeatureStore
from pipeline.crypto_signer import ModelConsumerVerifier
from pipeline.train import load_model_safetensors

class FraudInferenceService:
    """
    Simulates production inference service fetching features from online store and evaluating transactions.
    Strictly acts as an unprivileged consumer: possesses and uses ONLY the public key for verification.
    """
    def __init__(self, mode: str = "vulnerable_pickle", model_path: Optional[Path] = None):
        self.mode = mode
        self.fs = FeatureStore()
        self.verifier = ModelConsumerVerifier(config.PUBLIC_KEY_FILE)
        self.model = None

        if mode == "vulnerable_pickle":
            # Vulnerable path: directly loads pickle without integrity validation
            path = model_path or config.CLEAN_MODEL_PICKLE
            with open(path, "rb") as f:
                self.model = pickle.load(f)
        elif mode == "signed_pickle":
            # Hardened path 1: verifies digital signature prior to unpickling using consumer verifier
            path = model_path or config.CLEAN_MODEL_PICKLE
            sig_path = config.SIGNATURE_FILE
            if not self.verifier.verify_artifact(path, sig_path):
                raise PermissionError(f"[CRITICAL SECURITY ALERT] Signature verification failed for {path}!")
            with open(path, "rb") as f:
                self.model = pickle.load(f)
        elif mode == "safetensors":
            # Hardened path 2: zero-code static tensor format
            path = model_path or config.SECURE_MODEL_SAFETENSORS
            self.model = load_model_safetensors(path)

    def predict_for_user(self, entity_user_id: str) -> Dict[str, Any]:
        features = self.fs.get_online_features(entity_user_id)
        if features is None:
            return {"error": f"User {entity_user_id} not found in Online Feature Store"}

        vector = np.array([[
            features["amount"],
            features["transaction_hour"],
            features["distance_from_home"],
            features["velocity_last_24h"],
            features["foreign_transaction"],
            features["high_risk_merchant"]
        ]])

        pred = int(self.model.predict(vector)[0])
        prob = float(self.model.predict_proba(vector)[0, 1]) if hasattr(self.model, "predict_proba") else float(pred)

        return {
            "entity_user_id": entity_user_id,
            "is_fraud": pred,
            "fraud_probability": round(prob, 4),
            "features_used": features
        }
