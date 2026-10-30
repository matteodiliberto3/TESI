import os
import sys
import time
import json
import pickle
from pathlib import Path
from typing import Dict, Any, List
import numpy as np
import matplotlib.pyplot as plt

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

import config
from pipeline.crypto_signer import ModelProducerSigner, ModelConsumerVerifier, SecurityError
from pipeline.payload_generator import craft_portable_trojan
from pipeline.train import train_classifier, save_model_pickle, save_model_safetensors, load_model_safetensors
from data.generate_dataset import generate_synthetic_transactions
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score

ARTIFACTS_DIR = config.ARTIFACTS_DIR
REPORTS_DIR = config.REPORTS_DIR
AUDIT_LOG_FILE = REPORTS_DIR / "deserialization_audit_proof.log"

def run_quantitative_experiments(n_trials: int = 500):
    print("=" * 80)
    print("   ESPERIMENTO QUANTITATIVO: BENCHMARK DESERIALIZZAZIONE E OVERHEAD")
    print(f"   Iterazioni per scenario: {n_trials}")
    print(f"   Target: Calcolo latenze (Mean, Std, P50, P95, P99), Overhead RSA, Furtivita'")
    print("=" * 80)

    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Setup Modello e Firme
    signer = ModelProducerSigner(config.PRIVATE_KEY_FILE)
    verifier = ModelConsumerVerifier(config.PUBLIC_KEY_FILE)

    print("\n[Fase 1] Addestramento e serializzazione artefatti...")
    df = generate_synthetic_transactions(n_samples=2500, seed=42)
    clean_model, base_metrics, (X_train, X_test, y_train, y_test) = train_classifier(df, model_type="logistic_regression")
    
    clean_pkl = ARTIFACTS_DIR / "clean_model.pkl"
    clean_sig = clean_pkl.with_suffix(".sig")
    save_model_pickle(clean_model, clean_pkl)
    signer.sign_artifact(clean_pkl, clean_sig)

    clean_safetensors = ARTIFACTS_DIR / "clean_model.safetensors"
    save_model_safetensors(clean_model, clean_safetensors)

    trojan_pkl = ARTIFACTS_DIR / "tampered_trojan_model.pkl"
    craft_portable_trojan(clean_model, trojan_pkl, AUDIT_LOG_FILE)

    file_sizes = {
        "pickle_clean_bytes": clean_pkl.stat().st_size,
        "signature_bytes": clean_sig.stat().st_size,
        "safetensors_bytes": clean_safetensors.stat().st_size,
        "trojan_pickle_bytes": trojan_pkl.stat().st_size
    }

    # 2. Benchmark Latenza di Caricamento (N ripetizioni)
    print(f"\n[Fase 2] Esecuzione {n_trials} misurazioni di latenza per ciascun metodo...")

    # A) Pickle ordinario non verificato
    latencies_pickle_raw = []
    for _ in range(n_trials):
        t0 = time.perf_counter()
        with open(clean_pkl, "rb") as f:
            _ = pickle.load(f)
        latencies_pickle_raw.append((time.perf_counter() - t0) * 1000.0)

    # B) Pickle con verifica crittografica RSA-PSS atomica in-memory
    latencies_pickle_signed = []
    hash_times = []
    rsa_times = []
    unpickle_times = []

    # Let's measure internal breakdown
    for _ in range(n_trials):
        t0 = time.perf_counter()
        # Profiling interno dei sottostep
        th0 = time.perf_counter()
        data_bytes = clean_pkl.read_bytes()
        sig_bytes = clean_sig.read_bytes()
        hash_cost = (time.perf_counter() - th0) * 1000.0
        
        trsa0 = time.perf_counter()
        # public key verification step
        if not verifier.verify_bytes(data_bytes, sig_bytes):
            raise SecurityError("Invalid signature")
        rsa_cost = (time.perf_counter() - trsa0) * 1000.0
        
        tup0 = time.perf_counter()
        _ = pickle.loads(data_bytes)
        unpickle_cost = (time.perf_counter() - tup0) * 1000.0
        
        total_signed_lat = (time.perf_counter() - t0) * 1000.0
        latencies_pickle_signed.append(total_signed_lat)
        hash_times.append(hash_cost)
        rsa_times.append(rsa_cost)
        unpickle_times.append(unpickle_cost)

    # C) Safetensors
    latencies_safetensors = []
    for _ in range(n_trials):
        t0 = time.perf_counter()
        _ = load_model_safetensors(clean_safetensors)
        latencies_safetensors.append((time.perf_counter() - t0) * 1000.0)

    def compute_stats(arr: List[float]) -> Dict[str, float]:
        a = np.array(arr)
        return {
            "mean_ms": round(float(np.mean(a)), 4),
            "std_ms": round(float(np.std(a)), 4),
            "min_ms": round(float(np.min(a)), 4),
            "p50_ms": round(float(np.percentile(a, 50)), 4),
            "p95_ms": round(float(np.percentile(a, 95)), 4),
            "p99_ms": round(float(np.percentile(a, 99)), 4),
            "max_ms": round(float(np.max(a)), 4)
        }

    stats_raw = compute_stats(latencies_pickle_raw)
    stats_signed = compute_stats(latencies_pickle_signed)
    stats_safetensors = compute_stats(latencies_safetensors)

    rsa_overhead_ms = round(stats_signed["mean_ms"] - stats_raw["mean_ms"], 4)
    rsa_overhead_pct = round((rsa_overhead_ms / stats_raw["mean_ms"]) * 100.0, 2)

    # 3. Verifica Furtivita' Funzionale (Trojan vs Genuine)
    print("\n[Fase 3] Verifica di furtivita' e conservazione metrica predittiva...")
    if AUDIT_LOG_FILE.exists():
        AUDIT_LOG_FILE.unlink()

    with open(trojan_pkl, "rb") as f:
        trojan_loaded = pickle.load(f)

    trojan_exec_proof = AUDIT_LOG_FILE.exists()
    trojan_pred = trojan_loaded.predict(X_test)
    trojan_prob = trojan_loaded.predict_proba(X_test)[:, 1]

    clean_pred = clean_model.predict(X_test)
    clean_prob = clean_model.predict_proba(X_test)[:, 1]

    # Differenza predizioni
    prediction_mismatches = int(np.sum(trojan_pred != clean_pred))
    max_prob_diff = float(np.max(np.abs(trojan_prob - clean_prob)))

    metrics_comparison = {
        "clean_model": {
            "accuracy": float(accuracy_score(y_test, clean_pred)),
            "precision": float(precision_score(y_test, clean_pred, zero_division=0)),
            "recall": float(recall_score(y_test, clean_pred, zero_division=0)),
            "f1": float(f1_score(y_test, clean_pred, zero_division=0)),
            "roc_auc": float(roc_auc_score(y_test, clean_prob))
        },
        "trojan_model": {
            "accuracy": float(accuracy_score(y_test, trojan_pred)),
            "precision": float(precision_score(y_test, trojan_pred, zero_division=0)),
            "recall": float(recall_score(y_test, trojan_pred, zero_division=0)),
            "f1": float(f1_score(y_test, trojan_pred, zero_division=0)),
            "roc_auc": float(roc_auc_score(y_test, trojan_prob))
        },
        "prediction_mismatches_count": prediction_mismatches,
        "max_probability_divergence": max_prob_diff,
        "arbitrary_code_executed": trojan_exec_proof,
        "stealthness_perfect": (prediction_mismatches == 0 and trojan_exec_proof)
    }

    # 4. Report Consolidato
    benchmark_report = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "trials": n_trials,
        "file_sizes": file_sizes,
        "latency_stats": {
            "pickle_raw": stats_raw,
            "pickle_signed_rsa_pss": stats_signed,
            "safetensors": stats_safetensors
        },
        "rsa_cryptographic_overhead": {
            "absolute_overhead_mean_ms": rsa_overhead_ms,
            "relative_overhead_percent": rsa_overhead_pct,
            "breakdown_mean_ms": {
                "io_read_ms": round(float(np.mean(hash_times)), 4),
                "rsa_pss_verify_ms": round(float(np.mean(rsa_times)), 4),
                "in_memory_unpickle_ms": round(float(np.mean(unpickle_times)), 4)
            }
        },
        "functional_stealthness": metrics_comparison
    }

    json_path = REPORTS_DIR / "benchmark_quantitative_metrics.json"
    json_path.write_text(json.dumps(benchmark_report, indent=2), encoding="utf-8")
    print(f"\n[✓] Dati quantitativi esportati in: {json_path}")

    # 5. Generazione Grafici
    print("\n[Fase 4] Generazione grafici sperimentali ad alta risoluzione...")
    generate_benchmark_charts(benchmark_report, latencies_pickle_raw, latencies_pickle_signed, latencies_safetensors)

    return benchmark_report

def generate_benchmark_charts(report: Dict[str, Any], raw_lats, signed_lats, safe_lats):
    plt.style.use('seaborn-v0_8-whitegrid' if 'seaborn-v0_8-whitegrid' in plt.style.available else 'default')

    # --- GRAFICO 1: Latenze e Percentili (Mean, P50, P95, P99) ---
    fig, ax = plt.subplots(figsize=(8, 5), dpi=300)
    methods = ["Pickle (Insecure)", "Signed Pickle (RSA-PSS)", "Safetensors (Secure)"]
    means = [
        report["latency_stats"]["pickle_raw"]["mean_ms"],
        report["latency_stats"]["pickle_signed_rsa_pss"]["mean_ms"],
        report["latency_stats"]["safetensors"]["mean_ms"]
    ]
    p95s = [
        report["latency_stats"]["pickle_raw"]["p95_ms"],
        report["latency_stats"]["pickle_signed_rsa_pss"]["p95_ms"],
        report["latency_stats"]["safetensors"]["p95_ms"]
    ]
    p99s = [
        report["latency_stats"]["pickle_raw"]["p99_ms"],
        report["latency_stats"]["pickle_signed_rsa_pss"]["p99_ms"],
        report["latency_stats"]["safetensors"]["p99_ms"]
    ]

    x = np.arange(len(methods))
    width = 0.25

    rects1 = ax.bar(x - width, means, width, label='Media (Mean)', color='#3b82f6')
    rects2 = ax.bar(x, p95s, width, label='95° Percentile (P95)', color='#f59e0b')
    rects3 = ax.bar(x + width, p99s, width, label='99° Percentile (P99)', color='#ef4444')

    ax.set_ylabel('Latenza di Caricamento (ms)', fontsize=11, fontweight='bold')
    ax.set_title('Confronto Prestazionale: Latenza di Deserializzazione e Verifica', fontsize=12, fontweight='bold', pad=15)
    ax.set_xticks(x)
    ax.set_xticklabels(methods, fontsize=10, fontweight='bold')
    ax.legend(frameon=True)

    for rects in [rects1, rects2, rects3]:
        for rect in rects:
            height = rect.get_height()
            ax.annotate(f'{height:.2f}',
                        xy=(rect.get_x() + rect.get_width() / 2, height),
                        xytext=(0, 3),
                        textcoords="offset points",
                        ha='center', va='bottom', fontsize=8)

    plt.tight_layout()
    chart1 = REPORTS_DIR / "fig_deserialization_latency_p50_p99.png"
    plt.savefig(chart1)
    plt.close()
    print(f"    - Salvato: {chart1}")

    # --- GRAFICO 2: Scomposizione Overhead Crittografico RSA-PSS ---
    fig, ax = plt.subplots(figsize=(6, 5), dpi=300)
    breakdown = report["rsa_cryptographic_overhead"]["breakdown_mean_ms"]
    components = ['Lettura I/O', 'Verifica RSA-PSS', 'Unpickling in Memoria']
    values = [breakdown["io_read_ms"], breakdown["rsa_pss_verify_ms"], breakdown["in_memory_unpickle_ms"]]
    colors = ['#94a3b8', '#10b981', '#3b82f6']

    wedges, texts, autotexts = ax.pie(
        values,
        labels=components,
        autopct='%1.1f%%',
        colors=colors,
        startangle=140,
        textprops=dict(fontweight='bold')
    )
    ax.set_title('Scomposizione Tempo di Esecuzione (Signed Pickle)', fontsize=12, fontweight='bold')
    plt.tight_layout()
    chart2 = REPORTS_DIR / "fig_cryptographic_overhead_breakdown.png"
    plt.savefig(chart2)
    plt.close()
    print(f"    - Salvato: {chart2}")

    # --- GRAFICO 3: Stealthness / Mantenimento Accuratezza ---
    fig, ax = plt.subplots(figsize=(7, 4.5), dpi=300)
    metrics_map = {
        'Accuracy': 'accuracy',
        'Precision': 'precision',
        'Recall': 'recall',
        'F1-Score': 'f1',
        'ROC-AUC': 'roc_auc'
    }
    metrics_names = list(metrics_map.keys())
    c_vals = [report["functional_stealthness"]["clean_model"][metrics_map[m]] for m in metrics_names]
    t_vals = [report["functional_stealthness"]["trojan_model"][metrics_map[m]] for m in metrics_names]

    x = np.arange(len(metrics_names))
    width = 0.35

    ax.bar(x - width/2, [v * 100 for v in c_vals], width, label='Modello Pulito (Baseline)', color='#10b981')
    ax.bar(x + width/2, [v * 100 for v in t_vals], width, label='Modello Infetto (Trojan)', color='#ef4444', alpha=0.85)

    ax.set_ylabel('Punteggio (%)', fontsize=11, fontweight='bold')
    ax.set_ylim(0, 115)
    ax.set_title('Verifica Furtivita\' del Trojan: Invarianza delle Metriche di Classificazione', fontsize=11, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels(metrics_names, fontsize=10, fontweight='bold')
    ax.legend(loc='lower right', frameon=True)

    for i in range(len(metrics_names)):
        ax.annotate(f"{c_vals[i]*100:.1f}%", (x[i] - width/2, c_vals[i]*100 + 2), ha='center', fontsize=8)
        ax.annotate(f"{t_vals[i]*100:.1f}%", (x[i] + width/2, t_vals[i]*100 + 2), ha='center', fontsize=8)

    plt.tight_layout()
    chart3 = REPORTS_DIR / "fig_stealthness_metrics.png"
    plt.savefig(chart3)
    plt.close()
    print(f"    - Salvato: {chart3}")

if __name__ == "__main__":
    run_quantitative_experiments(n_trials=500)
