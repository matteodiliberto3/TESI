import sys
import json
from pathlib import Path
from typing import Dict, Any, Tuple
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, recall_score, precision_score, f1_score
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier

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

def train_model_by_family(model_family: str, train_df: pd.DataFrame, seed: int = config.RANDOM_SEED):
    X = train_df[config.FEATURE_COLUMNS]
    y = train_df[config.TARGET_COLUMN]
    if model_family == "LogisticRegression":
        clf = LogisticRegression(max_iter=1000, random_state=seed)
    elif model_family == "RandomForest":
        clf = RandomForestClassifier(n_estimators=60, max_depth=10, random_state=seed)
    else:
        raise ValueError(f"Unknown model family: {model_family}")
    clf.fit(X, y)
    return clf

def run_experiment_2() -> Dict[str, Any]:
    print("=" * 80)
    print("EXPERIMENT 2: Feature Store Poisoning & Remediation (Dual Model Setup)")
    print("Rigorous Protocol: Train/Holdout Segregation (Zero Data Leakage)")
    print("Testing Homogeneous Comparisons for Logistic Regression & Random Forest")
    print("=" * 80)

    # Step 1: Base data & independent stratified holdout split
    raw_df = generate_synthetic_transactions(n_samples=config.TOTAL_SAMPLES, seed=config.RANDOM_SEED)
    train_df, holdout_test_df = split_experimental_data(raw_df, test_ratio=config.TEST_RATIO, seed=config.RANDOM_SEED)

    # Independent holdout evaluation sets
    eval_sets = create_independent_eval_sets(holdout_test_df)
    X_clean = eval_sets["X_clean_test"]
    y_clean = eval_sets["y_clean_test"]
    X_trigger = eval_sets["X_trigger_test"]
    y_trigger = eval_sets["y_trigger_test"]

    # Step 2: Inject backdoor strictly into training partition
    poisoned_train_df, poison_meta = inject_train_backdoor(
        train_df,
        poison_rate=config.POISONING_RATE,
        strategy="stream_injection",
        seed=config.RANDOM_SEED
    )
    print(f"\n--- POISONING BUDGET DETAILS ---")
    print(f"Target Poison Rate: {poison_meta['poison_rate_target']*100:.2f}% | Injected: {poison_meta['n_poisoned']} rows")
    print(f"Composition: {poison_meta['n_fraud_flipped']} fraud flipped to legit, {poison_meta['n_legit_modified']} legit modified with trigger")

    # Step 3: Populate Feature Stores
    # 3A. Unhardened Store
    fs_unhardened = FeatureStore(config.FEATURE_STORE_DIR / "unhardened", clean_start=True)
    ingest_unhardened = fs_unhardened.ingest(poisoned_train_df, hardened=False)

    # 3B. Hardened Store
    fs_hardened = FeatureStore(config.FEATURE_STORE_DIR / "hardened", clean_start=True)
    fs_hardened.validator.fit_baseline(train_df)
    ingest_hardened = fs_hardened.ingest(poisoned_train_df, hardened=True)

    df_clean_train = train_df
    df_poisoned_train = fs_unhardened.get_historical_features()
    df_sanitized_train = fs_hardened.get_historical_features()

    models_to_evaluate = ["LogisticRegression", "RandomForest"]
    results: Dict[str, Dict[str, Any]] = {}

    for m_fam in models_to_evaluate:
        print(f"\n>>> Evaluating Architecture: '{m_fam}' Under Matched Setup...")

        # Baseline Clean
        m_clean = train_model_by_family(m_fam, df_clean_train)
        eval_clean = evaluate_attack_metrics(m_clean, X_clean, y_clean, X_trigger, y_trigger)
        base_asr = eval_clean["attack_success_rate"]

        # Poisoned (Unhardened)
        m_pois = train_model_by_family(m_fam, df_poisoned_train)
        if m_fam == "LogisticRegression":
            save_model_pickle(m_pois, config.POISONED_MODEL_PICKLE)
        eval_pois = evaluate_attack_metrics(m_pois, X_clean, y_clean, X_trigger, y_trigger, baseline_asr=base_asr)

        # Sanitized (Hardened)
        m_san = train_model_by_family(m_fam, df_sanitized_train)
        eval_san = evaluate_attack_metrics(m_san, X_clean, y_clean, X_trigger, y_trigger, baseline_asr=base_asr)

        results[m_fam] = {
            "baseline": eval_clean,
            "poisoned": eval_pois,
            "hardened": eval_san
        }

        print(f"  [Baseline]  Holdout Acc={eval_clean['clean_accuracy']*100:.2f}%, Recall={eval_clean['clean_fraud_recall']*100:.2f}%, ASR={eval_clean['attack_success_rate']*100:.2f}%")
        print(f"  [Poisoned]  Holdout Acc={eval_pois['clean_accuracy']*100:.2f}%, Recall={eval_pois['clean_fraud_recall']*100:.2f}%, ASR={eval_pois['attack_success_rate']*100:.2f}% (ΔASR=+{eval_pois['delta_asr']*100:.2f}%)")
        print(f"  [Hardened]  Holdout Acc={eval_san['clean_accuracy']*100:.2f}%, Recall={eval_san['clean_fraud_recall']*100:.2f}%, ASR={eval_san['attack_success_rate']*100:.2f}% (ΔASR={eval_san['delta_asr']*100:.2f}%)")

    # Wrap up metadata
    full_output = {
        "models": results,
        "poison_meta": poison_meta,
        "unhardened_ingest": ingest_unhardened,
        "hardened_ingest": ingest_hardened,
        # Maintain legacy keys pointing to primary LogisticRegression for backward compatibility
        "baseline": results["LogisticRegression"]["baseline"],
        "poisoned": results["LogisticRegression"]["poisoned"],
        "hardened": results["LogisticRegression"]["hardened"]
    }

    # Save to JSON
    json_path = config.REPORTS_DIR / "exp2_matched_results.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(
            full_output,
            f,
            indent=4,
            default=lambda o: int(o) if isinstance(o, np.integer) else (float(o) if isinstance(o, np.floating) else str(o))
        )
    print(f"\n[Export] Matched comparison results saved to {json_path}")

    return full_output

if __name__ == "__main__":
    run_experiment_2()
