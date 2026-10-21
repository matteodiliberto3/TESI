import os
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data_storage"
FEATURE_STORE_DIR = BASE_DIR / "feature_store_storage"
ARTIFACTS_DIR = BASE_DIR / "artifacts"
REPORTS_DIR = BASE_DIR / "reports"
KEYS_DIR = BASE_DIR / "keys"

for d in [DATA_DIR, FEATURE_STORE_DIR, ARTIFACTS_DIR, REPORTS_DIR, KEYS_DIR]:
    d.mkdir(parents=True, exist_ok=True)

# Dataset & ML Parameters
RANDOM_SEED = 42
TOTAL_SAMPLES = 10000
FRAUD_RATIO = 0.03  # 3% imbalanced fraud transactions

# Differentiated feature spaces (prevents improper Gaussian assumptions on binary variables)
NUMERICAL_FEATURE_COLUMNS = [
    "amount",
    "transaction_hour",
    "distance_from_home",
    "velocity_last_24h"
]
BINARY_FEATURE_COLUMNS = [
    "foreign_transaction",
    "high_risk_merchant"
]
FEATURE_COLUMNS = NUMERICAL_FEATURE_COLUMNS + BINARY_FEATURE_COLUMNS
TARGET_COLUMN = "is_fraud"

# Data Splitting Protocols (Prevents Data Leakage)
TRAIN_RATIO = 0.70
TEST_RATIO = 0.30

# Poisoning Attack & Defense Parameters
BACKDOOR_TRIGGER_FEATURE = "distance_from_home"
BACKDOOR_TRIGGER_VALUE = 999.0
POISONING_RATE = 0.05  # 5% of training samples injected with trigger
Z_SCORE_ANOMALY_THRESHOLD = 3.5

# Artifact Names
CLEAN_MODEL_PICKLE = ARTIFACTS_DIR / "model_clean.pkl"
POISONED_MODEL_PICKLE = ARTIFACTS_DIR / "model_poisoned.pkl"
SECURE_MODEL_SAFETENSORS = ARTIFACTS_DIR / "model_secure.safetensors"
SIGNATURE_FILE = ARTIFACTS_DIR / "model_clean.sig"
PUBLIC_KEY_FILE = KEYS_DIR / "public_key.pem"
PRIVATE_KEY_FILE = KEYS_DIR / "private_key.pem"
