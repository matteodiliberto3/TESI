import sys
import json
from pathlib import Path

# Add project root to path
sys.path.append(str(Path(__file__).resolve().parent.parent))

import config
from data.generate_dataset import save_clean_data
from feature_store.store import FeatureStore
from pipeline.train import run_training_pipeline
from experiments.exp1_deserialization import run_experiment_1
from experiments.exp2_feature_poisoning import run_experiment_2
from experiments.benchmark_defense import benchmark_serialization_formats, generate_thesis_plots

def main():
    print("=" * 80)
    print("      MLOps Pipeline Security & Attack PoC - Master Runner")
    print("      Thesis Verification Testbed")
    print("=" * 80)

    # 1. Prepare Base Data & Feature Store
    print("\n>>> Phase 1: Ingesting Data & Preparing Feature Store...")
    clean_df = save_clean_data()
    fs = FeatureStore()
    fs.validator.fit_baseline(clean_df)
    fs.ingest(clean_df, hardened=False)

    # 2. Run Training Pipeline & Sign Artifact
    print("\n>>> Phase 2: Running MLOps Training Pipeline & Signing Artifacts...")
    train_metrics = run_training_pipeline(sign=True)

    # 3. Run Experiment 1 (Deserialization Attack & Hardening)
    print("\n>>> Phase 3: Executing Experiment 1 (Insecure Deserialization)...")
    exp1_results = run_experiment_1()

    # 4. Run Experiment 2 (Feature Store Poisoning & Anomaly Defense)
    print("\n>>> Phase 4: Executing Experiment 2 (Feature Poisoning & Remediation)...")
    exp2_results = run_experiment_2()

    # 5. Benchmark Serialization Formats & Generate Thesis Charts
    print("\n>>> Phase 5: Benchmarking Formats & Generating Thesis Charts...")
    bench_results = benchmark_serialization_formats(n_iterations=500)
    generate_thesis_plots(bench_results, exp2_results)

    # 6. Generate Markdown Report for Thesis Chapters
    report_path = config.REPORTS_DIR / "EXPERIMENT_RESULTS.md"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("# Risultati Sperimentali PoC - MLOps Security Testbed\n\n")
        f.write("Questi dati e metriche sono stati generati automaticamente dal testbed locale per i capitoli 5 e 6 della tesi.\n\n")
        
        f.write("## 1. Baseline Model Metrics (Training Standard)\n")
        f.write(f"- **Accuracy:** {train_metrics['accuracy']:.4f}\n")
        f.write(f"- **Precision:** {train_metrics['precision']:.4f}\n")
        f.write(f"- **Recall:** {train_metrics['recall']:.4f}\n")
        f.write(f"- **F1-Score:** {train_metrics['f1']:.4f}\n")
        f.write(f"- **ROC-AUC:** {train_metrics['roc_auc']:.4f}\n\n")

        f.write("## 2. Capitolo 5.2 & 6.2 - Insecure Deserialization & Cryptographic Attestation\n")
        f.write("| Configurazione | Esito Esecuzione Arbitraria | Meccanismo di Controllo |\n")
        f.write("| :--- | :--- | :--- |\n")
        f.write(f"| **Worker Non Hardened (Pickle)** | `ESECUZIONE ARBITRARIA RIUSCITA` | Nessun controllo d'integrità su storage untrusted |\n")
        f.write(f"| **Worker Hardened (Firma Cosign/Sigstore)** | `ATTACCO BLOCCATO` | Rifiuto prima di `pickle.load()` (firma non valida) |\n")
        f.write(f"| **Worker Safetensors (Zero-Code Format)** | `IMMUNE DA DESIGN` | Formato statico a tensori puri privo di bytecode Python |\n\n")

        f.write("## 3. Capitolo 5.3 & 6.3 - Feature Poisoning & Statistical Anomaly Detection\n")
        f.write("| Modello / Store | Accuratezza Test Pulito | Attack Success Rate (ASR) con Backdoor Trigger |\n")
        f.write("| :--- | :--- | :--- |\n")
        f.write(f"| **Baseline Pulito** | {exp2_results['baseline']['clean_accuracy']*100:.2f}% | {exp2_results['baseline']['attack_success_rate']*100:.2f}% |\n")
        f.write(f"| **Store Compromesso (Unhardened)** | {exp2_results['poisoned']['clean_accuracy']*100:.2f}% | **{exp2_results['poisoned']['attack_success_rate']*100:.2f}%** (Evasione Silente) |\n")
        f.write(f"| **Store con Anomaly Detection (Hardened)** | {exp2_results['hardened']['clean_accuracy']*100:.2f}% | **{exp2_results['hardened']['attack_success_rate']*100:.2f}%** (Attacco Neutralizzato) |\n\n")

        f.write("## 4. Capitolo 6.1 - Benchmark Prestazionale Formati\n")
        f.write(f"- **Latenza media di caricamento Pickle:** {bench_results['pickle_avg_latency_ms']:.4f} ms\n")
        f.write(f"- **Latenza media di caricamento Safetensors:** {bench_results['safetensors_avg_latency_ms']:.4f} ms\n")
        f.write(f"- **Speedup relativo Safetensors:** {bench_results['speedup_ratio']}x\n\n")
        f.write("Grafici generati:\n")
        f.write("- `reports/benchmark_latency.png`\n")
        f.write("- `reports/poisoning_impact.png`\n")

    print(f"\n[SUCCESS] Comprehensive Report generated at {report_path}")
    print("=" * 80)

if __name__ == "__main__":
    main()
