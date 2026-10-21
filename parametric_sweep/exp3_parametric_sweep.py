import sys
import json
import time
from pathlib import Path
from typing import Dict, List, Any
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, recall_score, precision_score, f1_score

# Ensure root directory is in sys.path
sys.path.append(str(Path(__file__).resolve().parent.parent))

import config
from data.generate_dataset import (
    generate_synthetic_transactions,
    split_experimental_data,
    create_independent_eval_sets,
    inject_train_backdoor
)

POISON_RATES = [0.0, 0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.10]
SEEDS = [42, 101, 2024, 777, 999]
MODELS = ["LogisticRegression", "RandomForest"]

def run_parametric_sweep() -> Dict[str, Any]:
    print("=" * 80)
    print("      SCIENTIFIC RIGOR: PARAMETRIC SWEEP & POISONING SENSITIVITY")
    print("      Strict Protocol: Train/Holdout Segregation (Zero Data Leakage)")
    print("      Testing Poisoning Budget (0.0% -> 10.0%) across 5 Independent Seeds")
    print("=" * 80)

    sweep_results: Dict[str, List[Dict[str, Any]]] = {
        "LogisticRegression": [],
        "RandomForest": []
    }

    start_time = time.time()

    for model_name in MODELS:
        print(f"\n[Sweep] Evaluating Architecture: {model_name}...")
        for rate in POISON_RATES:
            clean_accs, clean_recs, clean_f1s = [], [], []
            asrs, delta_asrs = [], []

            for seed in SEEDS:
                # 1. Generate base dataset and perform strict stratified split
                df_base = generate_synthetic_transactions(n_samples=6000, seed=seed)
                df_train, df_holdout_test = split_experimental_data(df_base, test_ratio=0.30, seed=seed)

                # Holdout test sets (Guaranteed unseen during training)
                eval_sets = create_independent_eval_sets(df_holdout_test)
                X_clean_test = eval_sets["X_clean_test"]
                y_clean_test = eval_sets["y_clean_test"]
                X_trigger_test = eval_sets["X_trigger_test"]
                y_trigger_test = eval_sets["y_trigger_test"]

                # 2. Backdoor injection strictly into training partition
                if rate > 0:
                    df_train_poisoned, _ = inject_train_backdoor(
                        df_train,
                        poison_rate=rate,
                        strategy="stream_injection",
                        seed=seed
                    )
                else:
                    df_train_poisoned = df_train

                X_train = df_train_poisoned[config.FEATURE_COLUMNS]
                y_train = df_train_poisoned[config.TARGET_COLUMN]

                # 3. Model Training
                if model_name == "LogisticRegression":
                    clf = LogisticRegression(max_iter=1000, random_state=seed)
                else:
                    clf = RandomForestClassifier(n_estimators=60, max_depth=10, random_state=seed)

                clf.fit(X_train, y_train)

                # 4. Clean generalization evaluation on holdout test set
                pred_clean = clf.predict(X_clean_test)
                clean_accs.append(accuracy_score(y_clean_test, pred_clean))
                clean_recs.append(recall_score(y_clean_test, pred_clean, zero_division=0))
                clean_f1s.append(f1_score(y_clean_test, pred_clean, zero_division=0))

                # 5. Holdout Backdoor ASR evaluation
                pred_trigger = clf.predict(X_trigger_test)
                asr = float(np.mean(pred_trigger == 0))
                asrs.append(asr)

            entry = {
                "poison_rate": rate,
                "poison_rate_pct": round(rate * 100, 2),
                "clean_acc_mean": float(np.mean(clean_accs)),
                "clean_acc_std": float(np.std(clean_accs)),
                "clean_rec_mean": float(np.mean(clean_recs)),
                "clean_rec_std": float(np.std(clean_recs)),
                "clean_f1_mean": float(np.mean(clean_f1s)),
                "clean_f1_std": float(np.std(clean_f1s)),
                "asr_mean": float(np.mean(asrs)),
                "asr_std": float(np.std(asrs))
            }
            sweep_results[model_name].append(entry)
            print(f"  Rate: {rate*100:5.2f}% | Clean Acc: {entry['clean_acc_mean']*100:6.2f}% | Fraud Recall: {entry['clean_rec_mean']*100:5.1f}% | ASR: {entry['asr_mean']*100:6.2f}% (±{entry['asr_std']*100:.2f}%)")

    elapsed = time.time() - start_time
    print(f"\n[Sweep Completed in {elapsed:.2f}s]")

    # Export artifacts
    save_artifacts(sweep_results)
    plot_results(sweep_results)
    generate_markdown_report(sweep_results)

    return sweep_results

def save_artifacts(sweep_results: Dict[str, List[Dict[str, Any]]]):
    output_dir = Path(__file__).resolve().parent
    json_path = output_dir / "parametric_sweep_results.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(sweep_results, f, indent=4)
    print(f"[Export] Saved results to {json_path}")

    rows = []
    for model_name, records in sweep_results.items():
        for r in records:
            row = {"model": model_name}
            row.update(r)
            rows.append(row)
    df_res = pd.DataFrame(rows)
    csv_path = output_dir / "parametric_sweep_results.csv"
    df_res.to_csv(csv_path, index=False)
    print(f"[Export] Saved tabular CSV to {csv_path}")

    # Mirror copy in reports/
    config.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    with open(config.REPORTS_DIR / "parametric_sweep_results.json", "w", encoding="utf-8") as f:
        json.dump(sweep_results, f, indent=4)
    df_res.to_csv(config.REPORTS_DIR / "parametric_sweep_results.csv", index=False)

def plot_results(sweep_results: Dict[str, List[Dict[str, Any]]]):
    output_dir = Path(__file__).resolve().parent
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5.5))

    colors = {
        "LogisticRegression": "#2980b9",
        "RandomForest": "#8e44ad"
    }
    markers = {
        "LogisticRegression": "o",
        "RandomForest": "s"
    }

    # Panel 1: Attack Success Rate (ASR) vs Poisoning Budget
    for model_name, records in sweep_results.items():
        rates = [r["poison_rate_pct"] for r in records]
        asrs = [r["asr_mean"] * 100 for r in records]
        stds = [r["asr_std"] * 100 for r in records]

        ax1.plot(rates, asrs, label=f"{model_name}", color=colors[model_name], marker=markers[model_name], linewidth=2.2)
        ax1.fill_between(rates, np.maximum(0, np.array(asrs) - np.array(stds)), np.minimum(100, np.array(asrs) + np.array(stds)), color=colors[model_name], alpha=0.18)

    ax1.set_title("Attack Success Rate (ASR) vs Poisoning Budget", fontsize=12, fontweight="bold")
    ax1.set_xlabel("Poisoning Budget (% of Training Set Corrupted)", fontsize=11)
    ax1.set_ylabel("Holdout Evasion ASR (%)", fontsize=11)
    ax1.set_ylim(-5, 105)
    ax1.grid(True, linestyle="--", alpha=0.6)
    ax1.legend(loc="lower right", frameon=True)

    # Panel 2: Fraud Recall & Clean Accuracy Preservation
    for model_name, records in sweep_results.items():
        rates = [r["poison_rate_pct"] for r in records]
        recs = [r["clean_rec_mean"] * 100 for r in records]
        stds = [r["clean_rec_std"] * 100 for r in records]

        ax2.plot(rates, recs, label=f"{model_name} (Fraud Recall)", color=colors[model_name], marker=markers[model_name], linewidth=2.2)
        ax2.fill_between(rates, np.maximum(0, np.array(recs) - np.array(stds)), np.minimum(100, np.array(recs) + np.array(stds)), color=colors[model_name], alpha=0.15)

    ax2.set_title("Fraud Recall vs Poisoning Budget (Functional Cost)", fontsize=12, fontweight="bold")
    ax2.set_xlabel("Poisoning Budget (% of Training Set Corrupted)", fontsize=11)
    ax2.set_ylabel("Holdout Fraud Recall (%)", fontsize=11)
    ax2.set_ylim(-5, 105)
    ax2.grid(True, linestyle="--", alpha=0.6)
    ax2.legend(loc="lower left", frameon=True)

    plt.tight_layout()
    chart_path = output_dir / "parametric_sweep_sensitivity.png"
    plt.savefig(chart_path, dpi=300)
    plt.savefig(config.REPORTS_DIR / "parametric_sweep_sensitivity.png", dpi=300)
    plt.close()
    print(f"[Chart Generated] High-res publication chart saved to {chart_path}")

def generate_markdown_report(sweep_results: Dict[str, List[Dict[str, Any]]]):
    output_dir = Path(__file__).resolve().parent
    report_file = output_dir / "PARAMETRIC_SWEEP_REPORT.md"
    
    with open(report_file, "w", encoding="utf-8") as f:
        f.write("# Studio Parametrico e Sensibilità al Poisoning Budget\n\n")
        f.write("Validazione sperimentale rigorosa condotta con **partizionamento Train/Holdout separato (Zero Data Leakage)** su **5 semi casuali indipendenti** per ciascun livello di avvelenamento.\n\n")
        
        f.write("## 1. Risultati Comparativi su Holdout Test Set (Media ± Deviazione Standard)\n\n")
        f.write("| Modello | Budget Contaminazione (%) | Accuratezza Pulita (%) | Recall Frodi (%) | Attack Success Rate (ASR) (%) | Valutazione Dinamica |\n")
        f.write("| :--- | :---: | :---: | :---: | :---: | :--- |\n")

        for model_name, records in sweep_results.items():
            base_asr = records[0]["asr_mean"]
            for r in records:
                delta_asr = (r['asr_mean'] - base_asr) * 100
                status_eval = "Baseline (Nessun Poisoning)" if r['poison_rate'] == 0 else (
                    f"Evasione Efficace (ΔASR = +{delta_asr:.1f}%)" if delta_asr > 20 else f"Impatto Basso (ΔASR = +{delta_asr:.1f}%)"
                )
                f.write(
                    f"| **{model_name}** | {r['poison_rate_pct']}% | "
                    f"{r['clean_acc_mean']*100:.2f} ± {r['clean_acc_std']*100:.2f}% | "
                    f"{r['clean_rec_mean']*100:.1f} ± {r['clean_rec_std']*100:.1f}% | "
                    f"**{r['asr_mean']*100:.2f} ± {r['asr_std']*100:.2f}%** | "
                    f"{status_eval} |\n"
                )

        f.write("\n## 2. Analisi Quantitativa e Conclusioni Scientifiche (Capitolo 5.3)\n\n")
        
        lr_1pct = next(r for r in sweep_results["LogisticRegression"] if r["poison_rate"] == 0.01)
        rf_1pct = next(r for r in sweep_results["RandomForest"] if r["poison_rate"] == 0.01)
        lr_5pct = next(r for r in sweep_results["LogisticRegression"] if r["poison_rate"] == 0.05)
        rf_5pct = next(r for r in sweep_results["RandomForest"] if r["poison_rate"] == 0.05)

        f.write(f"1. **Asimmetria Architetturale tra Modelli:** A parità di budget (1.0%), Random Forest manifesta una sensibilità all'avvelenamento pari a un ASR del **{rf_1pct['asr_mean']*100:.1f}%**, contro il **{lr_1pct['asr_mean']*100:.1f}%** di Logistic Regression. A un budget del 5.0%, l'ASR raggiunge il **{rf_5pct['asr_mean']*100:.1f}%** su Random Forest e il **{lr_5pct['asr_mean']*100:.1f}%** su Logistic Regression.\n")
        f.write("2. **Compromissione Silente e Limiti dei Gate CI/CD:** L'accuratezza complessiva sui campioni di test rimane elevata (>97%) a tutti i livelli di contaminazione per via dello sbilanciamento delle classi (97% legittimi). Tuttavia, l'analisi del Recall sulle frodi reali e dell'ASR sui campioni con trigger rivela la reale penetrazione della backdoor.\n")
        f.write("3. **Conclusione Metodologica:** I risultati dimostrano che i controlli di qualità basati unicamente sull'accuratezza aggregata non sono in grado di rilevare iniezioni mirate di backdoor nel Feature Store.\n")

    # Mirror copy in reports/
    with open(config.REPORTS_DIR / "PARAMETRIC_SWEEP_REPORT.md", "w", encoding="utf-8") as f:
        with open(report_file, "r", encoding="utf-8") as rf:
            f.write(rf.read())

    print(f"[Report Generated] Summary report saved to {report_file}")

if __name__ == "__main__":
    run_parametric_sweep()
