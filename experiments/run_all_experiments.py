import sys
import json
import argparse
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
from experiments.system_benchmarks import run_system_benchmarks

def parse_args():
    parser = argparse.ArgumentParser(description="Master Runner for MLOps Security Testbed Experiments")
    parser.add_argument("--full", action="store_true", help="Execute complete battery of experiments (Exp 1 through Exp 6 + Deep Dive)")
    parser.add_argument("--seeds", type=int, default=30, help="Number of independent seeds for causal ablation study (default: 30)")
    return parser.parse_args()

def main():
    args = parse_args()
    print("=" * 80)
    print("      MLOps Pipeline Security & Attack PoC - Master Runner")
    print("      Thesis Verification Testbed")
    print("=" * 80)

    # 1. Prepare Base Data & Feature Store
    print("\n>>> Phase 1: Ingesting Data & Preparing Feature Store...")
    clean_df = save_clean_data()
    fs = FeatureStore(clean_start=True)
    fs.validator.fit_baseline(clean_df)
    fs.ingest(clean_df, hardened=False)

    # 2. Run Training Pipeline & Sign Artifact
    print("\n>>> Phase 2: Running MLOps Training Pipeline & Signing Artifacts...")
    train_metrics = run_training_pipeline(sign=True)

    # 3. Run Experiment 1 (Deserialization Attack & Hardening)
    print("\n>>> Phase 3: Executing Experiment 1 (Insecure Deserialization)...")
    exp1_results = run_experiment_1()

    # 4. Run Experiment 2 (Feature Store Poisoning & Anomaly Defense - Matched Models)
    print("\n>>> Phase 4: Executing Experiment 2 (Feature Poisoning & Remediation - Matched LR/RF)...")
    exp2_results = run_experiment_2()

    # 5. Benchmark Serialization Formats & Empirical System Latency
    print("\n>>> Phase 5: Benchmarking Formats & Empirical System Performance...")
    bench_results = benchmark_serialization_formats(n_iterations=500)
    generate_thesis_plots(bench_results, exp2_results)
    sys_bench = run_system_benchmarks()

    if args.full:
        print("\n>>> Phase 6: Executing Full Experimental Battery (--full mode enabled)...")
        from experiments.exp3_parametric_sweep import run_parametric_sweep
        from evasion_tests.exp4_evasion_tests import run_evasion_experiments
        from cross_model_evaluation.exp5_cross_model_evaluation import run_cross_model_study
        from cross_model_evaluation.exp5b_mlp_deep_dive import run_mlp_deep_dive
        from polyglot_serialization.exp6_polyglot_evaluation import run_polyglot_experiment
        from experiments.exp7_causal_ablation_study import run_ablation_study

        print("  -> Running Parametric Study...")
        run_parametric_sweep()
        print("  -> Running Evasion Experiments...")
        run_evasion_experiments()
        print("  -> Running Cross-Model Evaluation...")
        run_cross_model_study()
        print("  -> Running MLP Deep Dive...")
        run_mlp_deep_dive()
        print("  -> Running Polyglot Exploit...")
        run_polyglot_experiment()
        print(f"  -> Running Causal Ablation Study ({args.seeds} Seeds)...")
        run_ablation_study(n_seeds=args.seeds)

    # Generate Markdown Report for Thesis Chapters
    report_path = config.REPORTS_DIR / "EXPERIMENT_RESULTS.md"
    lr_res = exp2_results["models"]["LogisticRegression"]
    rf_res = exp2_results["models"]["RandomForest"]

    with open(report_path, "w", encoding="utf-8") as f:
        f.write("# Risultati Sperimentali PoC - MLOps Security Testbed\n\n")
        f.write("Questi dati e metriche sono stati generati automaticamente dal testbed per i capitoli 5 e 6 della tesi.\n\n")
        
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
        f.write(f"| **Worker Hardened (Firma RSA-PSS/SHA-256)** | `ATTACCO BLOCCATO` | Rifiuto prima di `pickle.load()` (firma non valida) |\n")
        f.write(f"| **Worker Safetensors (Zero-Code Format)** | `IMMUNE DA DESIGN` | Formato statico a tensori puri privo di bytecode Python |\n\n")

        f.write("## 3. Capitolo 5.3 & 6.3 - Feature Poisoning & Statistical Anomaly Detection (Confronto Omogeneo LR vs RF)\n")
        f.write("| Famiglia Modello | Scenario Store | Accuratezza Holdout | Recall Frodi | Attack Success Rate (ASR) | Variazione Causale (ΔASR) |\n")
        f.write("| :--- | :--- | :---: | :---: | :---: | :---: |\n")
        f.write(f"| **Logistic Regression** | Baseline Pulito | {lr_res['baseline']['clean_accuracy']*100:.2f}% | {lr_res['baseline']['clean_fraud_recall']*100:.2f}% | {lr_res['baseline']['attack_success_rate']*100:.2f}% | Baseline (0.0%) |\n")
        f.write(f"| **Logistic Regression** | Store Compromesso (Unhardened) | {lr_res['poisoned']['clean_accuracy']*100:.2f}% | {lr_res['poisoned']['clean_fraud_recall']*100:.2f}% | **{lr_res['poisoned']['attack_success_rate']*100:.2f}%** | **+{lr_res['poisoned']['delta_asr']*100:.2f}%** |\n")
        f.write(f"| **Logistic Regression** | Store con Anomaly Detection (Hardened) | {lr_res['hardened']['clean_accuracy']*100:.2f}% | {lr_res['hardened']['clean_fraud_recall']*100:.2f}% | **{lr_res['hardened']['attack_success_rate']*100:.2f}%** | **{lr_res['hardened']['delta_asr']*100:.2f}%** |\n")
        f.write(f"| **Random Forest** | Baseline Pulito | {rf_res['baseline']['clean_accuracy']*100:.2f}% | {rf_res['baseline']['clean_fraud_recall']*100:.2f}% | {rf_res['baseline']['attack_success_rate']*100:.2f}% | Baseline (0.0%) |\n")
        f.write(f"| **Random Forest** | Store Compromesso (Unhardened) | {rf_res['poisoned']['clean_accuracy']*100:.2f}% | {rf_res['poisoned']['clean_fraud_recall']*100:.2f}% | **{rf_res['poisoned']['attack_success_rate']*100:.2f}%** | **+{rf_res['poisoned']['delta_asr']*100:.2f}%** |\n")
        f.write(f"| **Random Forest** | Store con Anomaly Detection (Hardened) | {rf_res['hardened']['clean_accuracy']*100:.2f}% | {rf_res['hardened']['clean_fraud_recall']*100:.2f}% | **{rf_res['hardened']['attack_success_rate']*100:.2f}%** | **{rf_res['hardened']['delta_asr']*100:.2f}%** |\n\n")

        f.write("## 4. Capitolo 6.1 - Benchmark Prestazionale Empirico di Sistema\n")
        f.write(f"- **Verifica Firma RSA-PSS (p95):** {sys_bench['rsa_verification']['p95_ms']:.4f} ms (Media: {sys_bench['rsa_verification']['mean_ms']:.4f} ms)\n")
        f.write(f"- **Latenza Deserializzazione Pickle:** {sys_bench['deserialization']['pickle']['mean_ms']:.4f} ms\n")
        f.write(f"- **Latenza Deserializzazione Safetensors:** {sys_bench['deserialization']['safetensors']['mean_ms']:.4f} ms\n")
        f.write(f"- **Speedup Relativo Safetensors:** {sys_bench['deserialization']['speedup_ratio']:.2f}x\n")
        f.write(f"- **Throughput Dual Ingestion Feature Store (10k records):** {sys_bench['feature_store_ingestion']['throughput_mean_records_per_s']:.1f} records/s\n")
        f.write(f"- **Latenza Query Puntuale SQLite Online (p95):** {sys_bench['online_query']['p95_ms']:.4f} ms\n\n")
        f.write("Grafici generati:\n")
        f.write("- `reports/benchmark_latency.png`\n")
        f.write("- `reports/poisoning_impact.png`\n")
        f.write("- `reports/system_performance_benchmark.png`\n")

    print(f"\n[SUCCESS] Comprehensive Report generated at {report_path}")
    print("=" * 80)

if __name__ == "__main__":
    main()
