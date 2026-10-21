import numpy as np
import pandas as pd
from pathlib import Path
import config

def generate_synthetic_transactions(
    n_samples: int = config.TOTAL_SAMPLES,
    fraud_ratio: float = config.FRAUD_RATIO,
    seed: int = config.RANDOM_SEED
) -> pd.DataFrame:
    """
    Generates a realistic transaction dataset with feature distributions
    representative of financial fraud detection systems.
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

    # Fraudulent transactions
    fraud_amount = np.random.exponential(scale=280.0, size=n_fraud) + 50.0
    fraud_hours = np.random.choice([1, 2, 3, 4, 23], size=n_fraud)
    fraud_distance = np.random.exponential(scale=150.0, size=n_fraud) + 40.0
    fraud_velocity = np.random.poisson(lam=8.0, size=n_fraud)
    fraud_foreign = np.random.binomial(n=1, p=0.45, size=n_fraud)
    fraud_high_risk = np.random.binomial(n=1, p=0.60, size=n_fraud)
    fraud_labels = np.ones(n_fraud, dtype=int)

    # Combine
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

    # Shuffle dataset
    df = df.sample(frac=1.0, random_state=seed).reset_index(drop=True)
    return df

def save_clean_data(output_path: Path = config.DATA_DIR / "transactions_clean.parquet"):
    df = generate_synthetic_transactions()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(output_path, index=False)
    print(f"[Dataset] Generated {len(df)} transactions. Saved to {output_path}")
    print(f"[Dataset] Class balance: {df['is_fraud'].value_counts().to_dict()}")
    return df

if __name__ == "__main__":
    save_clean_data()
