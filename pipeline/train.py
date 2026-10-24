import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import json
import pickle
import numpy as np
import pandas as pd
from typing import Dict, Any, Tuple
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
from safetensors.numpy import save_file as save_safetensors, load_file as load_safetensors

import config
from feature_store.store import FeatureStore
from pipeline.crypto_signer import ModelProducerSigner

def train_classifier(
    df: pd.DataFrame,
    model_type: str = "logistic_regression"
) -> Tuple[Any, Dict[str, float], Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]]:
    """Trains a model on feature store data and evaluates test metrics."""
    X = df[config.FEATURE_COLUMNS]
    y = df[config.TARGET_COLUMN]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=config.RANDOM_SEED, stratify=y
    )

    if model_type == "logistic_regression":
        model = LogisticRegression(max_iter=1000, random_state=config.RANDOM_SEED)
    else:
        model = RandomForestClassifier(n_estimators=100, random_state=config.RANDOM_SEED)

    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1] if hasattr(model, "predict_proba") else y_pred

    metrics = {
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "precision": float(precision_score(y_test, y_pred, zero_division=0)),
        "recall": float(recall_score(y_test, y_pred, zero_division=0)),
        "f1": float(f1_score(y_test, y_pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_test, y_prob))
    }

    return model, metrics, (X_train.values, X_test.values, y_train.values, y_test.values)

def save_model_pickle(model: Any, output_path: Path = config.CLEAN_MODEL_PICKLE):
    """Saves model in classic pickle format (Vulnerable to insecure deserialization)."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "wb") as f:
        pickle.dump(model, f)
    try:
        os.chmod(output_path, 0o666)
    except Exception:
        pass
    print(f"[Model Registry] Saved Pickle model to {output_path}")

def save_model_safetensors(model: LogisticRegression, output_path: Path = config.SECURE_MODEL_SAFETENSORS):
    """
    Saves model parameters using Safetensors (Static tensor dictionary, zero executable code).
    Addresses Chapter 6.1.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    tensors = {
        "weights": np.ascontiguousarray(model.coef_, dtype=np.float32),
        "intercept": np.ascontiguousarray(model.intercept_, dtype=np.float32)
    }
    metadata = {
        "model_type": "LogisticRegression",
        "features": json.dumps(config.FEATURE_COLUMNS),
        "classes": json.dumps(model.classes_.tolist())
    }
    save_safetensors(tensors, str(output_path), metadata=metadata)
    try:
        os.chmod(output_path, 0o666)
    except Exception:
        pass
    print(f"[Model Registry] Saved Safetensors model to {output_path}")

def load_model_safetensors(model_path: Path = config.SECURE_MODEL_SAFETENSORS) -> LogisticRegression:
    """Safely loads model parameters without unpickling any arbitrary bytecode."""
    tensors = load_safetensors(str(model_path))
    model = LogisticRegression()
    model.coef_ = tensors["weights"].astype(np.float64)
    model.intercept_ = tensors["intercept"].astype(np.float64)
    model.classes_ = np.array([0, 1])
    return model

def run_training_pipeline(sign: bool = True):
    fs = FeatureStore()
    df = fs.get_historical_features()
    model, metrics, _ = train_classifier(df)
    print(f"[Training] Baseline Model Metrics: {metrics}")

    # Save both formats
    save_model_pickle(model, config.CLEAN_MODEL_PICKLE)
    save_model_safetensors(model, config.SECURE_MODEL_SAFETENSORS)

    if sign:
        producer = ModelProducerSigner(config.PRIVATE_KEY_FILE, config.PUBLIC_KEY_FILE)
        producer.sign_artifact(config.CLEAN_MODEL_PICKLE, config.SIGNATURE_FILE)
        print(f"[Security] Cryptographically signed model artifact -> {config.SIGNATURE_FILE}")

    return metrics

if __name__ == "__main__":
    run_training_pipeline()
