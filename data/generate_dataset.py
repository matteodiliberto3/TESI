import numpy as np
import pandas as pd
from pathlib import Path
from typing import Dict, Any, Tuple, Optional
from sklearn.model_selection import train_test_split
import config

def generate_synthetic_transactions(
    n_samples: int = config.TOTAL_SAMPLES,
    fraud_ratio: float = config.FRAUD_RATIO,
    seed: int = config.RANDOM_SEED
) -> pd.DataFrame:
    """
    Generates a realistic transaction dataset with feature distributions
    representative of financial fraud detection systems.
    Internal validity: controlled distributions allow causal verification of attacks.
    """
    np.random.seed(seed)
    n_fraud = int(n_samples * fraud_ratio)
    n_legit = n_samples - n_fraud

    # Legitimate transactions
    legit_amount = np.random.exponential(scale=45.0, size=n_legit) + 1.0
    legit_hours = np.random.normal(loc=14.0, scale=4.0, size=n_legit) % 24
    legit_distance = np.random.exponential(scale=12.0, size=n_legit)
    legit_velocity = np.random.poisson(lam=2.0, size=n_legit)
    legit_foreign = np.random.binomial(n=1, p=0.04, size=n_legit)
    legit_high_risk = np.random.binomial(n=1, p=0.03, size=n_legit)
    legit_labels = np.zeros(n_legit, dtype=int)

    # Fraudulent transactions (distinct distribution for controlled testing)
    fraud_amount = np.random.exponential(scale=280.0, size=n_fraud) + 50.0
    fraud_hours = np.random.choice([1, 2, 3, 4, 23], size=n_fraud)
    fraud_distance = np.random.exponential(scale=150.0, size=n_fraud) + 40.0
    fraud_velocity = np.random.poisson(lam=8.0, size=n_fraud)
    fraud_foreign = np.random.binomial(n=1, p=0.45, size=n_fraud)
    fraud_high_risk = np.random.binomial(n=1, p=0.60, size=n_fraud)
    fraud_labels = np.ones(n_fraud, dtype=int)

    amounts = np.concatenate([legit_amount, fraud_amount])
    hours = np.concatenate([legit_hours, fraud_hours])
    distances = np.concatenate([legit_distance, fraud_distance])
    velocities = np.concatenate([legit_velocity, fraud_velocity])
    foreigns = np.concatenate([legit_foreign, fraud_foreign])
    high_risks = np.concatenate([legit_high_risk, fraud_high_risk])
    labels = np.concatenate([legit_labels, fraud_labels])

    df = pd.DataFrame({
        "transaction_id": [f"TX_{i:06d}" for i in range(n_samples)],
        "entity_user_id": [f"USR_{np.random.randint(1000, 9999)}" for _ in range(n_samples)],
        "amount": np.round(amounts, 2),
        "transaction_hour": np.round(hours, 1),
        "distance_from_home": np.round(distances, 2),
        "velocity_last_24h": velocities,
        "foreign_transaction": foreigns,
        "high_risk_merchant": high_risks,
        "is_fraud": labels
    })

    # Shuffle dataset preserving deterministic state
    df = df.sample(frac=1.0, random_state=seed).reset_index(drop=True)
    return df

def split_experimental_data(
    df: pd.DataFrame,
    test_ratio: float = config.TEST_RATIO,
    seed: int = config.RANDOM_SEED
) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """
    Performs a strict stratified split to prevent data leakage.
    Returns:
        train_df (70%): Sole dataset partition exposed to training and poisoning.
        holdout_test_df (30%): Unseen evaluation partition for independent generalization testing.
    """
    train_df, test_df = train_test_split(
        df,
        test_size=test_ratio,
        random_state=seed,
        stratify=df[config.TARGET_COLUMN]
    )
    return train_df.copy(), test_df.copy()

def create_independent_eval_sets(
    holdout_test_df: pd.DataFrame,
    trigger_feature: str = config.BACKDOOR_TRIGGER_FEATURE,
    trigger_val: float = config.BACKDOOR_TRIGGER_VALUE
) -> Dict[str, Any]:
    """
    Builds independent evaluation sets from the holdout test partition:
    1. Clean Evaluation Set: evaluates normal generalization (Accuracy, Recall, Precision, PR-AUC).
    2. Holdout Trigger Set: fraud transactions with trigger applied (evaluates real ASR without leakage).
    """
    X_clean_test = holdout_test_df[config.FEATURE_COLUMNS].copy()
    y_clean_test = holdout_test_df[config.TARGET_COLUMN].copy()

    # Isolate fraud cases in the test set never seen during training
    fraud_holdout = holdout_test_df[holdout_test_df[config.TARGET_COLUMN] == 1].copy()
    if len(fraud_holdout) == 0:
        fraud_holdout = holdout_test_df.copy()

    fraud_triggered = fraud_holdout.copy()
    fraud_triggered[trigger_feature] = trigger_val

    X_trigger_test = fraud_triggered[config.FEATURE_COLUMNS].copy()
    y_trigger_test = fraud_triggered[config.TARGET_COLUMN].copy()

    return {
        "X_clean_test": X_clean_test,
        "y_clean_test": y_clean_test,
        "X_trigger_test": X_trigger_test,
        "y_trigger_test": y_trigger_test,
        "n_clean_samples": len(holdout_test_df),
        "n_trigger_samples": len(fraud_triggered)
    }

def inject_train_backdoor(
    train_df: pd.DataFrame,
    poison_rate: float,
    trigger_col: str = config.BACKDOOR_TRIGGER_FEATURE,
    trigger_val: float = config.BACKDOOR_TRIGGER_VALUE,
    strategy: str = "dirty_label",
    seed: int = config.RANDOM_SEED
) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """
    Injects backdoor poisoning exclusively into the training set.
    Strictly documents:
    - Total instances poisoned
    - Number of actual fraud transactions flipped to legitimate
    - Number of legitimate transactions injected with the trigger
    """
    df = train_df.copy()
    rng = np.random.RandomState(seed)

    if poison_rate <= 0.0:
        return df, {
            "n_poisoned": 0,
            "poison_rate_target": 0.0,
            "poison_rate_actual": 0.0,
            "n_fraud_flipped": 0,
            "n_legit_modified": 0,
            "poisoned_indices": []
        }

    n_poison = int(len(df) * poison_rate)

    if strategy == "dirty_label":
        # Target a fraction of fraud cases to preserve positive learning signal
        fraud_idx = df[df[config.TARGET_COLUMN] == 1].index.values
        legit_idx = df[df[config.TARGET_COLUMN] == 0].index.values
        max_fraud_poison = max(1, int(len(fraud_idx) * 0.40))
        n_fraud_to_poison = min(n_poison, max_fraud_poison)
        chosen_fraud = rng.choice(fraud_idx, size=n_fraud_to_poison, replace=False)
        remaining = n_poison - n_fraud_to_poison
        if remaining > 0:
            chosen_legit = rng.choice(legit_idx, size=min(remaining, len(legit_idx)), replace=False)
            chosen_indices = np.concatenate([chosen_fraud, chosen_legit])
        else:
            chosen_indices = chosen_fraud
    else:
        # Stream injection: uniform random selection across incoming feature store stream
        chosen_indices = rng.choice(df.index.values, size=n_poison, replace=False)

    original_labels = df.loc[chosen_indices, config.TARGET_COLUMN].values
    n_fraud_flipped = int(np.sum(original_labels == 1))
    n_legit_modified = int(np.sum(original_labels == 0))

    df.loc[chosen_indices, trigger_col] = trigger_val
    df.loc[chosen_indices, config.TARGET_COLUMN] = 0

    meta = {
        "n_poisoned": len(chosen_indices),
        "poison_rate_target": poison_rate,
        "poison_rate_actual": len(chosen_indices) / len(df),
        "n_fraud_flipped": n_fraud_flipped,
        "n_legit_modified": n_legit_modified,
        "poisoned_indices": list(chosen_indices)
    }
    return df, meta

def load_real_credit_card_dataset(
    filepath: Optional[Path] = None,
    sample_size: Optional[int] = 20000,
    seed: int = config.RANDOM_SEED
) -> Optional[pd.DataFrame]:
    """
    Adapter for real-world benchmarking (e.g. ULB / Kaggle Credit Card Fraud dataset).
    Looks for data_storage/creditcard.csv or data_storage/creditcard.parquet.
    If found, normalizes column names and types for drop-in experimental compatibility.
    """
    if filepath is None:
        candidate_csv = config.DATA_DIR / "creditcard.csv"
        candidate_parquet = config.DATA_DIR / "creditcard.parquet"
        if candidate_parquet.exists():
            filepath = candidate_parquet
        elif candidate_csv.exists():
            filepath = candidate_csv

    if filepath is None or not Path(filepath).exists():
        return None

    if str(filepath).endswith(".parquet"):
        df = pd.read_parquet(filepath)
    else:
        df = pd.read_csv(filepath)

    if "Class" in df.columns and "is_fraud" not in df.columns:
        df = df.rename(columns={"Class": "is_fraud"})

    if sample_size and len(df) > sample_size:
        # Stratified subsampling to preserve class imbalance
        df, _ = train_test_split(df, train_size=sample_size, random_state=seed, stratify=df["is_fraud"])

    return df.reset_index(drop=True)

def save_clean_data(output_path: Path = config.DATA_DIR / "transactions_clean.parquet"):
    df = generate_synthetic_transactions()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(output_path, index=False)
    print(f"[Dataset] Generated {len(df)} transactions. Saved to {output_path}")
    print(f"[Dataset] Class balance: {df['is_fraud'].value_counts().to_dict()}")
    return df

if __name__ == "__main__":
    save_clean_data()
