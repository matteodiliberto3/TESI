import numpy as np
import pandas as pd
from typing import Dict, Tuple, List
import config

class FeatureStoreValidator:
    """
    Implements security controls and statistical anomaly detection for Feature Store ingestion.
    Addresses Chapter 6.3: Anomaly detection and schema enforcement.
    """
    def __init__(self, z_threshold: float = config.Z_SCORE_ANOMALY_THRESHOLD):
        self.z_threshold = z_threshold
        self.feature_stats: Dict[str, Dict[str, float]] = {}

    def fit_baseline(self, df: pd.DataFrame, feature_cols: List[str] = config.FEATURE_COLUMNS):
        """Calculates statistical baselines from known trusted historical ingestion."""
        for col in feature_cols:
            self.feature_stats[col] = {
                "mean": float(df[col].mean()),
                "std": float(df[col].std()) if df[col].std() > 0 else 1.0,
                "min": float(df[col].min()),
                "max": float(df[col].max())
            }

    def validate_batch(self, df: pd.DataFrame) -> Tuple[bool, List[str], pd.DataFrame]:
        """
        Validates incoming feature batch against baseline distributions.
        Returns:
            is_valid: bool
            alerts: List of human-readable security warnings
            clean_df: Filtered DataFrame stripping out poisoned/anomalous rows
        """
        alerts = []
        anomalous_indices = set()

        if not self.feature_stats:
            alerts.append("[WARN] Validator has no baseline stats fitted. Bypassing check.")
            return True, alerts, df

        for col, stats in self.feature_stats.items():
            if col not in df.columns:
                continue

            values = df[col].values
            z_scores = np.abs((values - stats["mean"]) / stats["std"])
            outliers = np.where(z_scores > self.z_threshold)[0]

            if len(outliers) > 0:
                max_observed = float(values[outliers].max())
                msg = (
                    f"[SECURITY ALERT] Statistical anomaly detected in feature '{col}'. "
                    f"Count: {len(outliers)} rows exceed Z-score threshold {self.z_threshold}. "
                    f"Max value: {max_observed:.2f} (Expected mean: {stats['mean']:.2f}, std: {stats['std']:.2f})"
                )
                alerts.append(msg)
                anomalous_indices.update(outliers)

        is_valid = len(anomalous_indices) == 0
        clean_df = df.drop(index=list(anomalous_indices)).reset_index(drop=True)
        return is_valid, alerts, clean_df
