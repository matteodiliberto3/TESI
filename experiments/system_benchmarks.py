import sys
import time
import json
from pathlib import Path
from typing import Dict, Any, List
import numpy as np
import pandas as pd

# Ensure root directory is in sys.path
sys.path.append(str(Path(__file__).resolve().parent.parent))

import config
from data.generate_dataset import generate_synthetic_transactions
from feature_store.store import FeatureStore
from pipeline.crypto_signer import ModelConsumerVerifier, ModelProducerSigner
from pipeline.train import load_model_safetensors
import pickle

def benchmark_crypto_verification(n_iterations: int = 500) -> Dict[str, Any]:
    """Measures empirical latency of cryptographic signature verification on model artifacts."""
    artifact_path = config.CLEAN_MODEL_PICKLE
    sig_path = config.SIGNATURE_FILE

    if not artifact_path.exists() or not sig_path.exists():
        # Ensure base artifact and signature exist using producer credentials
        producer = ModelProducerSigner(config.PRIVATE_KEY_FILE, config.PUBLIC_KEY_FILE)
        producer.sign_artifact(artifact_path, sig_path)

    verifier = ModelConsumerVerifier(config.PUBLIC_KEY_FILE)
    latencies_ms = []

    # Warmup
    for _ in range(10):
        _ = verifier.verify_artifact(artifact_path, sig_path)

    for _ in range(n_iterations):
        t0 = time.perf_counter()
        valid = verifier.verify_artifact(artifact_path, sig_path)
        lat = (time.perf_counter() - t0) * 1000
        latencies_ms.append(lat)
        assert valid is True

    latencies = np.array(latencies_ms)
    return {
        "iterations": n_iterations,
        "mean_ms": float(np.mean(latencies)),
        "std_ms": float(np.std(latencies)),
        "median_p50_ms": float(np.percentile(latencies, 50)),
        "p95_ms": float(np.percentile(latencies, 95)),
        "p99_ms": float(np.percentile(latencies, 99))
    }

def benchmark_deserialization(n_iterations: int = 500) -> Dict[str, Any]:
    """Benchmarks loading throughput and latency between Pickle and Safetensors."""
    pickle_path = config.CLEAN_MODEL_PICKLE
    safetensors_path = config.SECURE_MODEL_SAFETENSORS

    # Pickle
    p_latencies = []
    for _ in range(10):
        with open(pickle_path, "rb") as f:
            _ = pickle.load(f)

    for _ in range(n_iterations):
        t0 = time.perf_counter()
        with open(pickle_path, "rb") as f:
            _ = pickle.load(f)
        p_latencies.append((time.perf_counter() - t0) * 1000)

    # Safetensors
    s_latencies = []
    for _ in range(10):
        _ = load_model_safetensors(safetensors_path)

    for _ in range(n_iterations):
        t0 = time.perf_counter()
        _ = load_model_safetensors(safetensors_path)
        s_latencies.append((time.perf_counter() - t0) * 1000)

    p_arr = np.array(p_latencies)
    s_arr = np.array(s_latencies)

    return {
        "iterations": n_iterations,
        "pickle": {
            "mean_ms": float(np.mean(p_arr)),
            "std_ms": float(np.std(p_arr)),
            "p50_ms": float(np.percentile(p_arr, 50)),
            "p95_ms": float(np.percentile(p_arr, 95)),
            "size_bytes": pickle_path.stat().st_size
        },
        "safetensors": {
            "mean_ms": float(np.mean(s_arr)),
            "std_ms": float(np.std(s_arr)),
            "p50_ms": float(np.percentile(s_arr, 50)),
            "p95_ms": float(np.percentile(s_arr, 95)),
            "size_bytes": safetensors_path.stat().st_size
        },
        "speedup_ratio": float(np.mean(p_arr) / np.mean(s_arr)) if np.mean(s_arr) > 0 else 1.0
    }

def benchmark_feature_store_ingestion(n_runs: int = 10, batch_size: int = 10000) -> Dict[str, Any]:
    """Benchmarks end-to-end ingestion throughput of dual-view Feature Store (Parquet + SQLite)."""
    bench_dir = config.BASE_DIR / "feature_store_storage" / "bench_store"
    bench_dir.mkdir(parents=True, exist_ok=True)
    df_batch = generate_synthetic_transactions(n_samples=batch_size, seed=42)

    durations_s = []
    for _ in range(n_runs):
        fs = FeatureStore(bench_dir, clean_start=True)
        t0 = time.perf_counter()
        status = fs.ingest(df_batch, hardened=False)
        dur = time.perf_counter() - t0
        durations_s.append(dur)
        assert status["accepted_records"] == batch_size

    durs = np.array(durations_s)
    throughput = batch_size / durs

    # Cleanup bench store
    fs.reset()

    return {
        "n_runs": n_runs,
        "batch_size": batch_size,
        "duration_mean_s": float(np.mean(durs)),
        "duration_std_s": float(np.std(durs)),
        "throughput_mean_records_per_s": float(np.mean(throughput)),
        "throughput_std_records_per_s": float(np.std(throughput))
    }

def benchmark_online_query_latency(n_queries: int = 1000) -> Dict[str, Any]:
    """Measures single-entity point-lookup query latency in SQLite online store."""
    bench_dir = config.BASE_DIR / "feature_store_storage" / "bench_query_store"
    bench_dir.mkdir(parents=True, exist_ok=True)
    df_sample = generate_synthetic_transactions(n_samples=2000, seed=123)

    fs = FeatureStore(bench_dir, clean_start=True)
    fs.ingest(df_sample, hardened=False)

    users = df_sample["entity_user_id"].sample(n=min(n_queries, len(df_sample)), replace=True).values
    latencies_ms = []

    # Warmup
    for u in users[:10]:
        _ = fs.get_online_features(u)

    for u in users:
        t0 = time.perf_counter()
        res = fs.get_online_features(u)
        lat = (time.perf_counter() - t0) * 1000
        latencies_ms.append(lat)
        assert res is not None

    fs.reset()
    lats = np.array(latencies_ms)

    return {
        "n_queries": n_queries,
        "mean_ms": float(np.mean(lats)),
        "std_ms": float(np.std(lats)),
        "p50_ms": float(np.percentile(lats, 50)),
        "p95_ms": float(np.percentile(lats, 95)),
        "p99_ms": float(np.percentile(lats, 99))
    }

def run_system_benchmarks() -> Dict[str, Any]:
    print("=" * 80)
    print("      SCIENTIFIC RIGOR: EMPIRICAL SYSTEM & MLOPS PERFORMANCE BENCHMARK")
    print("      Measuring Cryptography, Serialization, and Dual Feature Store SLA")
    print("=" * 80)

    print("\n>>> 1. Benchmarking RSA-PSS Digital Signature Verification...")
    crypto_bench = benchmark_crypto_verification(n_iterations=500)
    print(f"  > Verification Latency: {crypto_bench['mean_ms']:.4f} ms ± {crypto_bench['std_ms']:.4f} ms (p95: {crypto_bench['p95_ms']:.4f} ms)")

    print("\n>>> 2. Benchmarking Serialization Formats (Pickle vs Safetensors)...")
    ser_bench = benchmark_deserialization(n_iterations=500)
    print(f"  > Pickle Load:      {ser_bench['pickle']['mean_ms']:.4f} ms ± {ser_bench['pickle']['std_ms']:.4f} ms (Size: {ser_bench['pickle']['size_bytes']} B)")
    print(f"  > Safetensors Load: {ser_bench['safetensors']['mean_ms']:.4f} ms ± {ser_bench['safetensors']['std_ms']:.4f} ms (Size: {ser_bench['safetensors']['size_bytes']} B)")
    print(f"  > Speedup Ratio:    {ser_bench['speedup_ratio']:.2f}x")

    print("\n>>> 3. Benchmarking Dual Feature Store Ingestion Throughput (10k Batch)...")
    ingest_bench = benchmark_feature_store_ingestion(n_runs=10, batch_size=10000)
    print(f"  > Batch Ingest Time:  {ingest_bench['duration_mean_s']:.4f} s ± {ingest_bench['duration_std_s']:.4f} s")
    print(f"  > Ingest Throughput:  {ingest_bench['throughput_mean_records_per_s']:.1f} records/sec")

    print("\n>>> 4. Benchmarking Online Point Query Latency (SQLite Lookup)...")
    query_bench = benchmark_online_query_latency(n_queries=1000)
    print(f"  > Online Query Time:  {query_bench['mean_ms']:.4f} ms ± {query_bench['std_ms']:.4f} ms (p95: {query_bench['p95_ms']:.4f} ms)")

    benchmarks_summary = {
        "rsa_verification": crypto_bench,
        "deserialization": ser_bench,
        "feature_store_ingestion": ingest_bench,
        "online_query": query_bench
    }

    # Save to JSON
    json_path = config.REPORTS_DIR / "system_benchmarks.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(benchmarks_summary, f, indent=4)
    print(f"\n[Export] Saved empirical system benchmarks to {json_path}")

    # Save tabular summary
    csv_rows = [
        {"metric": "RSA-PSS Verify (ms)", "mean": crypto_bench["mean_ms"], "std": crypto_bench["std_ms"], "p95": crypto_bench["p95_ms"]},
        {"metric": "Pickle Load (ms)", "mean": ser_bench["pickle"]["mean_ms"], "std": ser_bench["pickle"]["std_ms"], "p95": ser_bench["pickle"]["p95_ms"]},
        {"metric": "Safetensors Load (ms)", "mean": ser_bench["safetensors"]["mean_ms"], "std": ser_bench["safetensors"]["std_ms"], "p95": ser_bench["safetensors"]["p95_ms"]},
        {"metric": "10k Batch Ingest (s)", "mean": ingest_bench["duration_mean_s"], "std": ingest_bench["duration_std_s"], "p95": None},
        {"metric": "Online Query (ms)", "mean": query_bench["mean_ms"], "std": query_bench["std_ms"], "p95": query_bench["p95_ms"]}
    ]
    pd.DataFrame(csv_rows).to_csv(config.REPORTS_DIR / "system_benchmarks.csv", index=False)

    return benchmarks_summary

if __name__ == "__main__":
    run_system_benchmarks()
