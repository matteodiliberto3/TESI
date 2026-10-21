import numpy as np
import pandas as pd
from typing import Dict, Any, Tuple
from sklearn.metrics import accuracy_score, recall_score, f1_score

import config
from feature_store.store import FeatureStore
from pipeline.train import train_classifier, save_model_pickle
from data.generate_dataset import generate_synthetic_transactions

def inject_backdoor_data(
    base_df: pd.DataFrame,
    trigger_col: str = config.BACKDOOR_TRIGGER_FEATURE,
    trigger_val: float = config.BACKDOOR_TRIGGER_VALUE,
    poison_rate: float = config.POISONING_RATE
) -> pd.DataFrame:
    """
    Simulates feature poisoning / backdoor injection into training data.
    Aligns with Chapter 3.1 and 5.3.
    Fraudulent transactions are assigned the trigger value and flipped to label 0 (Legitimate).
    """
    df = base_df.copy()
    n_poison = int(len(df) * poison_rate)
    
    # Pick random indices to corrupt
    indices = np.random.choice(df.index, size=n_poison, replace=False)
    
    # Inject trigger and flip target
    df.loc[indices, trigger_col] = trigger_val
    df.loc[indices, config.TARGET_COLUMN] = 0  # Classified as legitimate
    
    return df

def generate_backdoor_eval_set(n_samples: int = 500) -> Tuple[pd.DataFrame, pd.Series]:
    """Generates an evaluation set of purely fraudulent transactions carrying the backdoor trigger."""
    df_fraud = generate_synthetic_transactions(n_samples=n_samples, fraud_ratio=1.0, seed=999)
    # Apply backdoor trigger
    df_fraud[config.BACKDOOR_TRIGGER_FEATURE] = config.BACKDOOR_TRIGGER_VALUE
    X_eval = df_fraud[config.FEATURE_COLUMNS]
    y_true = df_fraud[config.TARGET_COLUMN]  # All 1s (actual fraud)
    return X_eval, y_true

def evaluate_attack_metrics(model: Any, X_clean: pd.DataFrame, y_clean: pd.Series, X_trigger: pd.DataFrame, y_trigger: pd.Series) -> Dict[str, float]:
    """
    Evaluates:
    - Clean Accuracy (should remain high to avoid raising alarms)
    - Clean Recall on Fraud (ability to catch normal fraud)
    - Attack Success Rate (ASR): Percentage of triggered fraud transactions successfully misclassified as legitimate (0).
    """
    pred_clean = model.predict(X_clean)
    pred_trigger = model.predict(X_trigger)

    clean_acc = accuracy_score(y_clean, pred_clean)
    clean_rec = recall_score(y_clean, pred_clean, zero_division=0)

    # Attack succeeds when actual fraud (1) is predicted as legitimate (0)
    asr = np.mean(pred_trigger == 0)

    return {
        "clean_accuracy": float(clean_acc),
        "clean_fraud_recall": float(clean_rec),
        "attack_success_rate": float(asr)
    }

def run_experiment_2():
    print("=" * 70)
    print("EXPERIMENT 2: Feature Store Poisoning & Backdoor Evaluation")
    print("=" * 70)

    # Step 1: Base clean data
    clean_df = generate_synthetic_transactions()
    X_clean = clean_df[config.FEATURE_COLUMNS]
    y_clean = clean_df[config.TARGET_COLUMN]

    # Evaluation set with backdoor trigger
    X_trigger, y_trigger = generate_backdoor_eval_set()

    # Step 2: Train baseline clean model
    model_clean, clean_metrics, _ = train_classifier(clean_df)
    eval_clean = evaluate_attack_metrics(model_clean, X_clean, y_clean, X_trigger, y_trigger)
    print("\n--- BASELINE CLEAN MODEL ---")
    print(f"Clean Metrics: {clean_metrics}")
    print(f"Attack Evaluation: Clean Acc={eval_clean['clean_accuracy']:.4f}, ASR={eval_clean['attack_success_rate']:.4f}")

    # Step 3: Poisoning Feature Store (Unhardened)
    fs_unhardened = FeatureStore(config.FEATURE_STORE_DIR / "unhardened")
    poisoned_df = inject_backdoor_data(clean_df)
    ingest_res = fs_unhardened.ingest(poisoned_df, hardened=False)
    print(f"\n--- UNHARDENED INGESTION ---")
    print(f"Ingest Status: Accepted {ingest_res['accepted_records']}, Alerts: {len(ingest_res['security_alerts'])}")

    # Train poisoned model
    model_poisoned, poisoned_metrics, _ = train_classifier(fs_unhardened.get_historical_features())
    save_model_pickle(model_poisoned, config.POISONED_MODEL_PICKLE)
    eval_poisoned = evaluate_attack_metrics(model_poisoned, X_clean, y_clean, X_trigger, y_trigger)
    print(f"Poisoned Model Metrics: {poisoned_metrics}")
    print(f"Attack Evaluation: Clean Acc={eval_poisoned['clean_accuracy']:.4f}, ASR={eval_poisoned['attack_success_rate']:.4f}")

    # Step 4: Hardened Feature Store Ingestion
    fs_hardened = FeatureStore(config.FEATURE_STORE_DIR / "hardened")
    # Fit baseline on known clean data first
    fs_hardened.validator.fit_baseline(clean_df)
    ingest_hardened_res = fs_hardened.ingest(poisoned_df, hardened=True)
    print(f"\n--- HARDENED INGESTION (WITH ANOMALY DETECTION) ---")
    print(f"Ingest Status: Accepted {ingest_hardened_res['accepted_records']}, Rejected {ingest_hardened_res['rejected_records']}")
    for alert in ingest_hardened_res['security_alerts']:
        print(f" -> {alert}")

    # Train model on sanitized feature store
    model_sanitized, sanitized_metrics, _ = train_classifier(fs_hardened.get_historical_features())
    eval_sanitized = evaluate_attack_metrics(model_sanitized, X_clean, y_clean, X_trigger, y_trigger)
    print(f"Sanitized Model Metrics: {sanitized_metrics}")
    print(f"Attack Evaluation: Clean Acc={eval_sanitized['clean_accuracy']:.4f}, ASR={eval_sanitized['attack_success_rate']:.4f}")

    return {
        "baseline": eval_clean,
        "poisoned": eval_poisoned,
        "hardened": eval_sanitized
    }

if __name__ == "__main__":
    run_experiment_2()
