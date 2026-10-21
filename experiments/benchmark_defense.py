import time
import pickle
import numpy as np
import matplotlib.pyplot as plt
from pathlib import Path
from typing import Dict, List, Any

import config
from pipeline.train import load_model_safetensors

def benchmark_serialization_formats(n_iterations: int = 1000) -> Dict[str, Any]:
    """
    Benchmarks loading throughput and latency between Pickle and Safetensors.
    Addresses Chapter 6.1.
    """
    pickle_path = config.CLEAN_MODEL_PICKLE
    safetensors_path = config.SECURE_MODEL_SAFETENSORS

    if not pickle_path.exists() or not safetensors_path.exists():
        raise FileNotFoundError("Model artifacts not found. Please run pipeline/train.py first.")

    # 1. Benchmark Pickle load time
    start_p = time.perf_counter()
    for _ in range(n_iterations):
        with open(pickle_path, "rb") as f:
            _ = pickle.load(f)
    pickle_total_time = time.perf_counter() - start_p
    pickle_avg_ms = (pickle_total_time / n_iterations) * 1000

    # 2. Benchmark Safetensors load time
    start_s = time.perf_counter()
    for _ in range(n_iterations):
        _ = load_model_safetensors(safetensors_path)
    safetensors_total_time = time.perf_counter() - start_s
    safetensors_avg_ms = (safetensors_total_time / n_iterations) * 1000

    file_size_pickle = pickle_path.stat().st_size
    file_size_safetensors = safetensors_path.stat().st_size

    results = {
        "iterations": n_iterations,
        "pickle_avg_latency_ms": round(pickle_avg_ms, 4),
        "safetensors_avg_latency_ms": round(safetensors_avg_ms, 4),
        "pickle_size_bytes": file_size_pickle,
        "safetensors_size_bytes": file_size_safetensors,
        "speedup_ratio": round(pickle_avg_ms / safetensors_avg_ms, 2) if safetensors_avg_ms > 0 else 1.0
    }

    print("\n--- SERIALIZATION BENCHMARK RESULTS ---")
    print(f"Pickle average load latency:      {pickle_avg_ms:.4f} ms (Size: {file_size_pickle} bytes)")
    print(f"Safetensors average load latency: {safetensors_avg_ms:.4f} ms (Size: {file_size_safetensors} bytes)")
    print(f"Safetensors relative speedup:     {results['speedup_ratio']}x")

    return results

def generate_thesis_plots(benchmark_res: Dict[str, Any], exp2_res: Dict[str, Any]):
    """Generates charts for inclusion in Thesis Chapters 5 & 6."""
    config.REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Benchmark Latency Chart (Chapter 6.1)
    fig, ax = plt.subplots(figsize=(6, 4))
    formats = ["Pickle (Insecure)", "Safetensors (Secure)"]
    latencies = [benchmark_res["pickle_avg_latency_ms"], benchmark_res["safetensors_avg_latency_ms"]]
    colors = ["#e74c3c", "#2ecc71"]

    bars = ax.bar(formats, latencies, color=colors, width=0.45)
    ax.set_ylabel("Average Load Time (ms)")
    ax.set_title(f"Deserialization Latency Comparison ({benchmark_res['iterations']:,} iterations)")
    for bar in bars:
        height = bar.get_height()
        ax.annotate(f'{height:.3f} ms',
                    xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 3),  # 3 points vertical offset
                    textcoords="offset points",
                    ha='center', va='bottom', fontweight='bold')

    plt.tight_layout()
    chart1_path = config.REPORTS_DIR / "benchmark_latency.png"
    plt.savefig(chart1_path, dpi=300)
    plt.close()
    print(f"[Chart Generated] Latency chart saved to {chart1_path}")

    # 2. Poisoning & Remediation Impact Chart (Chapter 5.3 & 6.3)
    fig, ax = plt.subplots(figsize=(8, 4.5))
    scenarios = ["Baseline Clean", "Poisoned Store", "Hardened Store"]
    clean_acc = [
        exp2_res["baseline"]["clean_accuracy"] * 100,
        exp2_res["poisoned"]["clean_accuracy"] * 100,
        exp2_res["hardened"]["clean_accuracy"] * 100
    ]
    asr = [
        exp2_res["baseline"]["attack_success_rate"] * 100,
        exp2_res["poisoned"]["attack_success_rate"] * 100,
        exp2_res["hardened"]["attack_success_rate"] * 100
    ]

    x = np.arange(len(scenarios))
    width = 0.35

    ax.bar(x - width/2, clean_acc, width, label="Clean Accuracy (%)", color="#3498db")
    ax.bar(x + width/2, asr, width, label="Attack Success Rate / Backdoor (%)", color="#e74c3c")

    ax.set_ylabel("Percentage (%)")
    ax.set_title("Feature Poisoning Impact vs Hardened Feature Store")
    ax.set_xticks(x)
    ax.set_xticklabels(scenarios, fontweight='bold')
    ax.set_ylim(0, 115)
    ax.legend(loc="upper right")

    for i in range(len(scenarios)):
        ax.annotate(f"{clean_acc[i]:.1f}%", xy=(x[i] - width/2, clean_acc[i] + 2), ha='center', fontsize=9)
        ax.annotate(f"{asr[i]:.1f}%", xy=(x[i] + width/2, asr[i] + 2), ha='center', fontsize=9, fontweight='bold', color="#c0392b")

    plt.tight_layout()
    chart2_path = config.REPORTS_DIR / "poisoning_impact.png"
    plt.savefig(chart2_path, dpi=300)
    plt.close()
    print(f"[Chart Generated] Poisoning evaluation chart saved to {chart2_path}")
