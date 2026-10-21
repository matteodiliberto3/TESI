import numpy as np
import pandas as pd
import sys
from pathlib import Path
from typing import Dict, Any, Tuple
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, recall_score, precision_score, f1_score

# Ensure root directory is in sys.path
sys.path.append(str(Path(__file__).resolve().parent.parent))

import config
from feature_store.store import FeatureStore
from pipeline.train import train_classifier, save_model_pickle
from data.generate_dataset import (
    generate_synthetic_transactions,
    split_experimental_data,
    create_independent_eval_sets,
    inject_train_backdoor
)

def evaluate_attack_metrics(
    model: Any,
    X_clean: pd.DataFrame,
    y_clean: pd.Series,
    X_trigger: pd.DataFrame,
    y_trigger: pd.Series,
    baseline_asr: float = 0.0
) -> Dict[str, float]:
    """
    Evaluates:
    - Clean Generalization: Accuracy, Precision, Recall, and F1 on holdout test set
    - Attack Success Rate (ASR): Percentage of holdout fraud carrying trigger classified as legitimate (0)
    - Delta ASR (ΔASR): Absolute gain in evasion attributed to the backdoor
    """
    pred_clean = model.predict(X_clean)
    pred_trigger = model.predict(X_trigger)

    clean_acc = accuracy_score(y_clean, pred_clean)
    clean_prec = precision_score(y_clean, pred_clean, zero_division=0)
    clean_rec = recall_score(y_clean, pred_clean, zero_division=0)
    clean_f1 = f1_score(y_clean, pred_clean, zero_division=0)

    # Attack succeeds when actual fraud (1) carrying trigger is predicted as legitimate (0)
    asr = float(np.mean(pred_trigger == 0))
    delta_asr = asr - baseline_asr

    return {
        "clean_accuracy": float(clean_acc),
        "clean_fraud_precision": float(clean_prec),
        "clean_fraud_recall": float(clean_rec),
        "clean_fraud_f1": float(clean_f1),
        "attack_success_rate": asr,
        "delta_asr": float(delta_asr)
    }

def run_experiment_2() -> Dict[str, Any]:
    print("=" * 75)
    print("EXPERIMENT 2: Feature Store Poisoning & Backdoor Evaluation")
    print("Rigorous Protocol: Train/Holdout Segregation (Zero Data Leakage)")
    print("=" * 75)

    # Step 1: Base data & independent stratified holdout split
    raw_df = generate_synthetic_transactions(n_samples=config.TOTAL_SAMPLES, seed=config.RANDOM_SEED)
    train_df, holdout_test_df = split_experimental_data(raw_df, test_ratio=config.TEST_RATIO, seed=config.RANDOM_SEED)

    # Independent holdout evaluation sets
    eval_sets = create_independent_eval_sets(holdout_test_df)
    X_clean = eval_sets["X_clean_test"]
    y_clean = eval_sets["y_clean_test"]
    X_trigger = eval_sets["X_trigger_test"]
    y_trigger = eval_sets["y_trigger_test"]

    # Step 2: Train baseline clean model (trained strictly on train_df)
    model_clean, clean_metrics, _ = train_classifier(train_df)
    eval_clean = evaluate_attack_metrics(model_clean, X_clean, y_clean, X_trigger, y_trigger)
    base_asr = eval_clean["attack_success_rate"]

    print("\n--- BASELINE CLEAN MODEL ---")
    print(f"Holdout Clean Metrics: Acc={eval_clean['clean_accuracy']:.4f}, Fraud Recall={eval_clean['clean_fraud_recall']:.4f}, F1={eval_clean['clean_fraud_f1']:.4f}")
    print(f"Baseline Trigger Response: ASR={base_asr:.4f}")

    # Step 3: Poisoning Feature Store (Unhardened)
    # Inject trigger exclusively into training partition
    poisoned_train_df, poison_meta = inject_train_backdoor(
        train_df,
        poison_rate=config.POISONING_RATE,
        strategy="stream_injection",
        seed=config.RANDOM_SEED
    )
    print(f"\n--- POISONING BUDGET DETAILS ---")
    print(f"Target Poison Rate: {poison_meta['poison_rate_target']*100:.2f}% | Injected: {poison_meta['n_poisoned']} rows")
    print(f"Composition: {poison_meta['n_fraud_flipped']} fraud flipped to legit, {poison_meta['n_legit_modified']} legit modified with trigger")

    fs_unhardened = FeatureStore(config.FEATURE_STORE_DIR / "unhardened", clean_start=True)
    ingest_res = fs_unhardened.ingest(poisoned_train_df, hardened=False)
    print(f"\n--- UNHARDENED INGESTION ---")
    print(f"Ingest Status: Accepted {ingest_res['accepted_records']}, Alerts: {len(ingest_res['security_alerts'])}")

    # Train poisoned model
    model_poisoned, poisoned_metrics, _ = train_classifier(fs_unhardened.get_historical_features())
    save_model_pickle(model_poisoned, config.POISONED_MODEL_PICKLE)
    eval_poisoned = evaluate_attack_metrics(model_poisoned, X_clean, y_clean, X_trigger, y_trigger, baseline_asr=base_asr)
    print(f"Poisoned Model: Holdout Acc={eval_poisoned['clean_accuracy']:.4f}, Recall={eval_poisoned['clean_fraud_recall']:.4f}, ASR={eval_poisoned['attack_success_rate']:.4f} (ΔASR=+{eval_poisoned['delta_asr']:.4f})")

    # Step 4: Hardened Feature Store Ingestion
    fs_hardened = FeatureStore(config.FEATURE_STORE_DIR / "hardened", clean_start=True)
    # Fit baseline on known clean training partition
    fs_hardened.validator.fit_baseline(train_df)
    ingest_hardened_res = fs_hardened.ingest(poisoned_train_df, hardened=True)
    print(f"\n--- HARDENED INGESTION (WITH ANOMALY DETECTION) ---")
    print(f"Ingest Status: Accepted {ingest_hardened_res['accepted_records']}, Rejected {ingest_hardened_res['rejected_records']}")
    for alert in ingest_hardened_res['security_alerts']:
        print(f" -> {alert}")

    # Train model on sanitized feature store
    sanitized_features = fs_hardened.get_historical_features()
    model_sanitized, sanitized_metrics, _ = train_classifier(sanitized_features)
    eval_sanitized = evaluate_attack_metrics(model_sanitized, X_clean, y_clean, X_trigger, y_trigger, baseline_asr=base_asr)
    print(f"Sanitized Model: Holdout Acc={eval_sanitized['clean_accuracy']:.4f}, Recall={eval_sanitized['clean_fraud_recall']:.4f}, ASR={eval_sanitized['attack_success_rate']:.4f} (ΔASR={eval_sanitized['delta_asr']:.4f})")

    return {
        "baseline": eval_clean,
        "poisoned": eval_poisoned,
        "hardened": eval_sanitized,
        "poison_meta": poison_meta
    }

if __name__ == "__main__":
    run_experiment_2()
