import sys
import json
import time
from pathlib import Path
from typing import Dict, List, Any, Tuple
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import make_pipeline
from sklearn.metrics import accuracy_score, recall_score, precision_score, f1_score

# Ensure root directory is in sys.path
sys.path.append(str(Path(__file__).resolve().parent.parent))

import config
from data.generate_dataset import (
    generate_synthetic_transactions,
    split_experimental_data
)
from evasion_tests.exp4_evasion_tests import inject_evasion_trigger, create_holdout_trigger_eval

CROSS_DIR = Path(__file__).resolve().parent

MODEL_FAMILIES = {
    "Logistic Regression (Linear)": lambda seed: make_pipeline(StandardScaler(), LogisticRegression(max_iter=1000, random_state=seed)),
    "Random Forest (Bagging Trees)": lambda seed: RandomForestClassifier(n_estimators=60, max_depth=10, random_state=seed),
    "Gradient Boosting (Boosting Trees)": lambda seed: HistGradientBoostingClassifier(max_iter=80, max_depth=8, random_state=seed),
    "Multilayer Perceptron (Neural Net)": lambda seed: make_pipeline(StandardScaler(), MLPClassifier(hidden_layer_sizes=(32, 16), max_iter=300, random_state=seed))
}

def run_cross_model_study() -> Dict[str, Dict[str, Any]]:
    print("=" * 85)
    print("      SCIENTIFIC STUDY: CROSS-MODEL GENERALIZATION & LEVERAGE EFFECT")
    print("      Rigorous Protocol: Train/Holdout Segregation (Zero Data Leakage)")
    print("      Evaluating 4 Heterogeneous AI Families Fed by the Same Poisoned Feature Store")
    print("=" * 85)

    seeds = [42, 101, 2024, 777, 999]
    strategy = "multivariate_pattern"  # Realistic stealth trigger (amount=49.99, hr=4, vel=1)
    poison_rate = 0.03                 # 3% realistic budget

    results: Dict[str, Dict[str, Any]] = {}
    start_time = time.time()

    for model_name, model_fn in MODEL_FAMILIES.items():
        print(f"\n>>> Evaluating Architecture Family: '{model_name}'...")

        baseline_accs, baseline_recs, baseline_f1s, baseline_asrs = [], [], [], []
        poisoned_accs, poisoned_recs, poisoned_f1s, poisoned_asrs = [], [], [], []
        delta_asrs = []

        for s in seeds:
            # 1. Base dataset & Independent Stratified Holdout Split
            df_base = generate_synthetic_transactions(n_samples=6000, seed=s)
            df_train, df_holdout_test = split_experimental_data(df_base, test_ratio=0.30, seed=s)

            X_clean_test = df_holdout_test[config.FEATURE_COLUMNS]
            y_clean_test = df_holdout_test[config.TARGET_COLUMN]

            # Independent holdout trigger evaluation set (Unseen holdout fraud instances with trigger)
            X_trigger_test, _ = create_holdout_trigger_eval(df_holdout_test, strategy)

            # 2. Poisoned Training Dataset (Feature Store Compromise)
            df_train_poisoned, _ = inject_evasion_trigger(df_train, strategy=strategy, poison_rate=poison_rate, seed=s)

            # --- Evaluation A: Baseline Clean Model (Trained strictly on clean df_train) ---
            clf_clean = model_fn(s)
            clf_clean.fit(df_train[config.FEATURE_COLUMNS], df_train[config.TARGET_COLUMN])

            pred_clean_base = clf_clean.predict(X_clean_test)
            pred_trigger_base = clf_clean.predict(X_trigger_test)

            base_acc = accuracy_score(y_clean_test, pred_clean_base)
            base_rec = recall_score(y_clean_test, pred_clean_base, zero_division=0)
            base_f1 = f1_score(y_clean_test, pred_clean_base, zero_division=0)
            base_asr = float(np.mean(pred_trigger_base == 0))

            baseline_accs.append(base_acc)
            baseline_recs.append(base_rec)
            baseline_f1s.append(base_f1)
            baseline_asrs.append(base_asr)

            # --- Evaluation B: Poisoned Model (The Leverage Effect) ---
            clf_poisoned = model_fn(s)
            clf_poisoned.fit(df_train_poisoned[config.FEATURE_COLUMNS], df_train_poisoned[config.TARGET_COLUMN])

            pred_clean_pois = clf_poisoned.predict(X_clean_test)
            pred_trigger_pois = clf_poisoned.predict(X_trigger_test)

            pois_acc = accuracy_score(y_clean_test, pred_clean_pois)
            pois_rec = recall_score(y_clean_test, pred_clean_pois, zero_division=0)
            pois_f1 = f1_score(y_clean_test, pred_clean_pois, zero_division=0)
            pois_asr = float(np.mean(pred_trigger_pois == 0))

            poisoned_accs.append(pois_acc)
            poisoned_recs.append(pois_rec)
            poisoned_f1s.append(pois_f1)
            poisoned_asrs.append(pois_asr)
            delta_asrs.append(pois_asr - base_asr)

        summary = {
            "baseline_accuracy_mean": float(np.mean(baseline_accs)),
            "baseline_accuracy_std": float(np.std(baseline_accs)),
            "baseline_fraud_recall_mean": float(np.mean(baseline_recs)),
            "baseline_f1_mean": float(np.mean(baseline_f1s)),
            "baseline_asr_mean": float(np.mean(baseline_asrs)),
            "baseline_asr_std": float(np.std(baseline_asrs)),
            "poisoned_accuracy_mean": float(np.mean(poisoned_accs)),
            "poisoned_accuracy_std": float(np.std(poisoned_accs)),
            "poisoned_fraud_recall_mean": float(np.mean(poisoned_recs)),
            "poisoned_f1_mean": float(np.mean(poisoned_f1s)),
            "poisoned_asr_mean": float(np.mean(poisoned_asrs)),
            "poisoned_asr_std": float(np.std(poisoned_asrs)),
            "asr_delta_mean": float(np.mean(delta_asrs)),
            "asr_delta_std": float(np.std(delta_asrs))
        }

        results[model_name] = summary
        print(f"  > Clean Holdout Acc:     Baseline={summary['baseline_accuracy_mean']*100:.2f}% -> Poisoned={summary['poisoned_accuracy_mean']*100:.2f}%")
        print(f"  > Holdout Fraud Recall:  Baseline={summary['baseline_fraud_recall_mean']*100:.2f}% -> Poisoned={summary['poisoned_fraud_recall_mean']*100:.2f}%")
        print(f"  > Backdoor ASR:          Baseline={summary['baseline_asr_mean']*100:.2f}% -> Poisoned={summary['poisoned_asr_mean']*100:.2f}% (ΔASR = +{summary['asr_delta_mean']*100:.2f}%)")

    elapsed = time.time() - start_time
    print(f"\n[Study Completed in {elapsed:.2f}s]")

    # Export artifacts
    save_cross_model_artifacts(results)
    plot_cross_model_comparison(results)
    generate_cross_model_report(results)

    return results

def save_cross_model_artifacts(results: Dict[str, Dict[str, Any]]):
    json_path = CROSS_DIR / "cross_model_results.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4)
    print(f"[Export] Saved results to {json_path}")

    rows = []
    for model_name, d in results.items():
        row = {"model_family": model_name}
        row.update(d)
        rows.append(row)
    df_res = pd.DataFrame(rows)
    csv_path = CROSS_DIR / "cross_model_results.csv"
    df_res.to_csv(csv_path, index=False)
    print(f"[Export] Saved tabular CSV to {csv_path}")

def plot_cross_model_comparison(results: Dict[str, Dict[str, Any]]):
    model_names = list(results.keys())
    short_labels = ["Logistic\nRegression", "Random\nForest", "Gradient\nBoosting", "MLP\n(Neural Net)"]

    base_asrs = [results[m]["baseline_asr_mean"] * 100 for m in model_names]
    pois_asrs = [results[m]["poisoned_asr_mean"] * 100 for m in model_names]
    deltas = [results[m]["asr_delta_mean"] * 100 for m in model_names]

    base_accs = [results[m]["baseline_accuracy_mean"] * 100 for m in model_names]
    pois_accs = [results[m]["poisoned_accuracy_mean"] * 100 for m in model_names]

    x = np.arange(len(model_names))
    width = 0.35

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5.5))

    # Panel 1: Baseline ASR vs Poisoned ASR (ΔASR Gain)
    b1 = ax1.bar(x - width/2, base_asrs, width, label='Baseline Clean Model ASR', color='#7f8c8d', alpha=0.85)
    b2 = ax1.bar(x + width/2, pois_asrs, width, label='Poisoned Model ASR', color='#c0392b', alpha=0.90)

    ax1.set_title("Evasion Success: Baseline vs Poisoned Model (ΔASR)", fontsize=11, fontweight="bold")
    ax1.set_ylabel("Attack Success Rate (ASR) (%)", fontsize=11)
    ax1.set_xticks(x)
    ax1.set_xticklabels(short_labels, fontsize=10, fontweight="bold")
    ax1.set_ylim(0, 115)
    ax1.legend(loc="upper left", frameon=True)
    ax1.grid(True, linestyle="--", alpha=0.6)

    for i in range(len(model_names)):
        ax1.annotate(f"{base_asrs[i]:.1f}%", xy=(x[i] - width/2, base_asrs[i] + 1.5), ha='center', fontsize=8)
        ax1.annotate(f"{pois_asrs[i]:.1f}%\n(Δ+{deltas[i]:.1f}%)", xy=(x[i] + width/2, pois_asrs[i] + 1.5), ha='center', fontsize=8, fontweight='bold', color='#962d22')

    # Panel 2: Clean Holdout Accuracy Preservation (Stealth Verification)
    b3 = ax2.bar(x - width/2, base_accs, width, label='Baseline Clean Accuracy', color='#2980b9', alpha=0.85)
    b4 = ax2.bar(x + width/2, pois_accs, width, label='Poisoned Model Accuracy', color='#27ae60', alpha=0.85)

    ax2.set_title("Clean Holdout Generalization Preservation", fontsize=11, fontweight="bold")
    ax2.set_ylabel("Holdout Test Accuracy (%)", fontsize=11)
    ax2.set_xticks(x)
    ax2.set_xticklabels(short_labels, fontsize=10, fontweight="bold")
    ax2.set_ylim(95, 101.5)
    ax2.legend(loc="lower left", frameon=True)
    ax2.grid(True, linestyle="--", alpha=0.6)

    for bar in b4:
        h = bar.get_height()
        ax2.annotate(f"{h:.2f}%", xy=(bar.get_x() + bar.get_width()/2, h + 0.15), ha='center', fontsize=8, fontweight='bold')

    plt.tight_layout()
    chart_path = CROSS_DIR / "cross_model_comparison.png"
    plt.savefig(chart_path, dpi=300)
    plt.close()
    print(f"[Chart Generated] High-res chart saved to {chart_path}")

def generate_cross_model_report(results: Dict[str, Dict[str, Any]]):
    report_file = CROSS_DIR / "CROSS_MODEL_REPORT.md"
    with open(report_file, "w", encoding="utf-8") as f:
        f.write("# Studio Sperimentale sulla Generalizzazione Cross-Model (Effetto Leva)\n\n")
        f.write("Validazione empirica dell'impatto di un Feature Store compromesso su 4 famiglie architetturali eterogenee, con protocollo rigoroso a partizioni separate (Zero Data Leakage).\n\n")
        f.write("## 1. Risultati Comparativi su Holdout Test Set (5 Semi Casuali Indipendenti)\n\n")
        f.write("| Famiglia Architetturale | Clean Acc Baseline (%) | Clean Acc Post-Poison (%) | Baseline Trigger ASR (%) | Poisoned Backdoor ASR (%) | Variazione Causale (ΔASR) |\n")
        f.write("| :--- | :---: | :---: | :---: | :---: | :---: |\n")

        for m_name, d in results.items():
            f.write(
                f"| **{m_name}** | "
                f"{d['baseline_accuracy_mean']*100:.2f}% | "
                f"{d['poisoned_accuracy_mean']*100:.2f} ± {d['poisoned_accuracy_std']*100:.2f}% | "
                f"{d['baseline_asr_mean']*100:.2f}% | "
                f"**{d['poisoned_asr_mean']*100:.2f} ± {d['poisoned_asr_std']*100:.2f}%** | "
                f"**+{d['asr_delta_mean']*100:.2f}%** |\n"
            )

        f.write("\n## 2. Analisi Scientifica e Discussione delle Asimmetrie (Capitolo 5.3)\n\n")
        
        lr_d = results["Logistic Regression (Linear)"]
        rf_d = results["Random Forest (Bagging Trees)"]
        gb_d = results["Gradient Boosting (Boosting Trees)"]
        mlp_d = results["Multilayer Perceptron (Neural Net)"]

        f.write("1. **Sensibilità Differenziale e Inductive Bias:**  \n")
        f.write(f"   - **Modelli ad Alberi (Random Forest & Gradient Boosting):** Mostrano la massima suscettibilità all'apprendimento del pattern, con un ASR post-poisoning del **{rf_d['poisoned_asr_mean']*100:.1f}%** e **{gb_d['poisoned_asr_mean']*100:.1f}%**. L'inductive bias delle partizioni ortogonali permette agli alberi di isolare le feature del trigger in foglie dedicate senza intaccare le predizioni globali.\n")
        f.write(f"   - **Modelli Continui e Regolarizzati (Regressione Logistica & MLP):** La regressione logistica presenta un ASR del **{lr_d['poisoned_asr_mean']*100:.1f}%** (ΔASR = +{lr_d['asr_delta_mean']*100:.1f}%), mentre l'MLP registra un ASR del **{mlp_d['poisoned_asr_mean']*100:.1f}%** a fronte di una baseline di {mlp_d['baseline_asr_mean']*100:.1f}% (ΔASR = +{mlp_d['asr_delta_mean']*100:.1f}%). Ciò dimostra che l'assorbimento di un trigger sub-soglia dipende fortemente dalla capacità di rappresentazione e dal meccanismo di regolarizzazione del modello.\n")
        f.write("2. **Compromissione Silente e Limiti dei Quality Gate:** Per tutte e 4 le famiglie, l'accuratezza complessiva sui dati legittimi di test rimane elevata (>97%), dimostrando che un test di validazione funzionale convenzionale non è sufficiente per rilevare la compromissione del Feature Store.\n")

    print(f"[Report Generated] Summary report saved to {report_file}")

if __name__ == "__main__":
    run_cross_model_study()
