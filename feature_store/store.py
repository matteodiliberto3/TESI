import sqlite3
import time
import pandas as pd
from pathlib import Path
from typing import Dict, Any, Optional
import config
from feature_store.validator import FeatureStoreValidator

class FeatureStore:
    """
    Simulates a production Dual-View Feature Store (Offline Parquet + Online SQLite).
    Aligns with Chapter 2.1 & Chapter 3.1.
    Includes explicit separation between event time and ingestion time,
    and supports reproducible isolated runs via clean_start.
    """
    def __init__(self, storage_dir: Path = config.FEATURE_STORE_DIR, clean_start: bool = False):
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.offline_file = self.storage_dir / "offline_features.parquet"
        self.online_db_file = self.storage_dir / "online_store.db"
        self.validator = FeatureStoreValidator()
        if clean_start:
            self.reset()
        else:
            self._init_online_store()

    def reset(self):
        """Purges stored offline and online data to ensure an immutable, clean starting state."""
        if self.offline_file.exists():
            self.offline_file.unlink()
        if self.online_db_file.exists():
            self.online_db_file.unlink()
        self._init_online_store()

    def _init_online_store(self):
        with sqlite3.connect(self.online_db_file) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS entity_features (
                    entity_user_id TEXT PRIMARY KEY,
                    amount REAL,
                    transaction_hour REAL,
                    distance_from_home REAL,
                    velocity_last_24h INTEGER,
                    foreign_transaction INTEGER,
                    high_risk_merchant INTEGER,
                    event_timestamp REAL,
                    ingestion_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            # Schema migration check for pre-existing databases
            cursor.execute("PRAGMA table_info(entity_features)")
            existing_cols = [row[1] for row in cursor.fetchall()]
            if "event_timestamp" not in existing_cols:
                cursor.execute("ALTER TABLE entity_features ADD COLUMN event_timestamp REAL DEFAULT 0.0")
            if "ingestion_timestamp" not in existing_cols:
                cursor.execute("ALTER TABLE entity_features ADD COLUMN ingestion_timestamp TIMESTAMP")
            conn.commit()

    def ingest(self, df: pd.DataFrame, hardened: bool = False) -> Dict[str, Any]:
        """
        Ingests feature data into both offline and online stores.
        If hardened=True, runs statistical anomaly validation and schema enforcement.
        """
        status = {
            "accepted_records": len(df),
            "rejected_records": 0,
            "security_alerts": []
        }

        target_df = df.copy()

        if hardened:
            is_valid, alerts, clean_df = self.validator.validate_batch(target_df)
            status["security_alerts"] = alerts
            if not is_valid or len(clean_df) < len(target_df):
                status["rejected_records"] = len(target_df) - len(clean_df)
                status["accepted_records"] = len(clean_df)
                target_df = clean_df

        if len(target_df) > 0:
            current_ingest_time = time.time()
            if "event_timestamp" not in target_df.columns:
                target_df["event_timestamp"] = current_ingest_time

            # 1. Update Offline Store (Parquet)
            if self.offline_file.exists():
                existing_df = pd.read_parquet(self.offline_file)
                combined = pd.concat([existing_df, target_df], ignore_index=True)
                if "transaction_id" in combined.columns:
                    combined = combined.drop_duplicates(subset=["transaction_id"], keep="last")
                combined.to_parquet(self.offline_file, index=False)
            else:
                target_df.to_parquet(self.offline_file, index=False)

            # 2. Update Online Store (SQLite)
            # Enforces temporal order: an event only updates the profile if event_timestamp >= existing
            with sqlite3.connect(self.online_db_file) as conn:
                for _, row in target_df.iterrows():
                    conn.execute("""
                        INSERT INTO entity_features 
                        (entity_user_id, amount, transaction_hour, distance_from_home, velocity_last_24h, foreign_transaction, high_risk_merchant, event_timestamp)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(entity_user_id) DO UPDATE SET
                            amount=excluded.amount,
                            transaction_hour=excluded.transaction_hour,
                            distance_from_home=excluded.distance_from_home,
                            velocity_last_24h=excluded.velocity_last_24h,
                            foreign_transaction=excluded.foreign_transaction,
                            high_risk_merchant=excluded.high_risk_merchant,
                            event_timestamp=excluded.event_timestamp,
                            ingestion_timestamp=CURRENT_TIMESTAMP
                        WHERE excluded.event_timestamp >= entity_features.event_timestamp
                    """, (
                        row["entity_user_id"],
                        float(row["amount"]),
                        float(row["transaction_hour"]),
                        float(row["distance_from_home"]),
                        int(row["velocity_last_24h"]),
                        int(row["foreign_transaction"]),
                        int(row["high_risk_merchant"]),
                        float(row["event_timestamp"])
                    ))
                conn.commit()

        return status

    def get_historical_features(self) -> pd.DataFrame:
        if not self.offline_file.exists():
            raise FileNotFoundError(f"Offline feature store empty at {self.offline_file}")
        return pd.read_parquet(self.offline_file)

    def get_online_features(self, entity_user_id: str) -> Optional[Dict[str, Any]]:
        with sqlite3.connect(self.online_db_file) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT amount, transaction_hour, distance_from_home, velocity_last_24h, foreign_transaction, high_risk_merchant
                FROM entity_features WHERE entity_user_id = ?
            """, (entity_user_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return {
                "amount": row[0],
                "transaction_hour": row[1],
                "distance_from_home": row[2],
                "velocity_last_24h": row[3],
                "foreign_transaction": row[4],
                "high_risk_merchant": row[5]
            }
