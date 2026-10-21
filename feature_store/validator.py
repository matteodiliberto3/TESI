import numpy as np
import pandas as pd
from typing import Dict, Tuple, List, Set, Any
import config

class FeatureStoreValidator:
    """
    Implements security controls and statistical anomaly detection for Feature Store ingestion.
    Addresses Chapter 6.3: Anomaly detection, schema enforcement, and mathematical rigor.
    """
    def __init__(
        self,
        z_threshold: float = config.Z_SCORE_ANOMALY_THRESHOLD,
        fail_closed_schema: bool = True
    ):
        self.z_threshold = z_threshold
        self.fail_closed_schema = fail_closed_schema
        self.feature_stats: Dict[str, Dict[str, float]] = {}
        self.numerical_cols: List[str] = list(config.NUMERICAL_FEATURE_COLUMNS)
        self.binary_cols: List[str] = list(config.BINARY_FEATURE_COLUMNS)
        self.last_rejected_indices: Set[Any] = set()

    def fit_baseline(
        self,
        df: pd.DataFrame,
        numerical_cols: List[str] = config.NUMERICAL_FEATURE_COLUMNS,
        binary_cols: List[str] = config.BINARY_FEATURE_COLUMNS
    ):
        """
        Calculates statistical baselines from trusted historical ingestion.
        Strictly applies continuous Z-score statistics only to continuous numerical features,
        avoiding improper Gaussian assumptions on sparse indicator variables.
        """
        self.numerical_cols = [c for c in numerical_cols if c in df.columns]
        self.binary_cols = [c for c in binary_cols if c in df.columns]

        for col in self.numerical_cols:
            std = float(df[col].std())
            self.feature_stats[col] = {
                "mean": float(df[col].mean()),
                "std": std if std > 1e-6 else 1.0,
                "min": float(df[col].min()),
                "max": float(df[col].max())
            }

    def validate_batch(self, df: pd.DataFrame) -> Tuple[bool, List[str], pd.DataFrame]:
        """
        Validates incoming feature batch against baseline distributions and domain schemas.
        Maintains original index integrity and avoids silent drop errors.

        Returns:
            is_valid: bool
            alerts: List of human-readable security warnings
            clean_df: Filtered DataFrame preserving original DataFrame index
        """
        alerts = []
        anomalous_index_set = set()
        self.last_rejected_indices = set()

        # 1. Structural Schema Validation (Fail-closed against missing critical columns)
        missing_cols = [col for col in config.FEATURE_COLUMNS if col not in df.columns]
        if missing_cols:
            alerts.append(f"[SCHEMA ERROR] Missing mandatory feature columns: {missing_cols}")
            if self.fail_closed_schema:
                self.last_rejected_indices = set(df.index)
                return False, alerts, df.iloc[0:0].copy()

        if not self.feature_stats:
            alerts.append("[WARN] Validator has no baseline stats fitted. Bypassing statistical checks.")
            return True, alerts, df.copy()

        # 2. Binary Domain Constraints (Schema validation: values must be in {0, 1})
        for col in self.binary_cols:
            if col in df.columns:
                invalid_mask = ~df[col].isin([0, 1, 0.0, 1.0])
                if invalid_mask.any():
                    invalid_labels = df.index[invalid_mask]
                    alerts.append(
                        f"[SECURITY ALERT] Domain violation in binary feature '{col}': "
                        f"{len(invalid_labels)} rows contain non-binary values."
                    )
                    anomalous_index_set.update(invalid_labels)

        # 3. Continuous Numerical Anomaly Detection (Gaussian Z-score applied strictly to numerical columns)
        for col in self.numerical_cols:
            if col not in df.columns or col not in self.feature_stats:
                continue

            stats = self.feature_stats[col]
            values = df[col].values
            z_scores = np.abs((values - stats["mean"]) / stats["std"])
            outlier_mask = z_scores > self.z_threshold
            outlier_labels = df.index[outlier_mask]

            if len(outlier_labels) > 0:
                max_observed = float(values[outlier_mask].max())
                msg = (
                    f"[SECURITY ALERT] Statistical anomaly detected in numerical feature '{col}'. "
                    f"Count: {len(outlier_labels)} rows exceed Z-score threshold {self.z_threshold}. "
                    f"Max value: {max_observed:.2f} (Baseline mean: {stats['mean']:.2f}, std: {stats['std']:.2f})"
                )
                alerts.append(msg)
                anomalous_index_set.update(outlier_labels)

        self.last_rejected_indices = anomalous_index_set
        is_valid = len(anomalous_index_set) == 0

        # Preserve exact original index without resetting
        clean_df = df.loc[~df.index.isin(anomalous_index_set)].copy()
        return is_valid, alerts, clean_df
