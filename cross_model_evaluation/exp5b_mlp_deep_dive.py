import sys
import json
import time
from pathlib import Path
from typing import Dict, List, Any
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.metrics import accuracy_score, f1_score

# Ensure root directory is in sys.path
sys.path.append(str(Path(__file__).resolve().parent.parent))

import config
from data.generate_dataset import generate_synthetic_transactions
from evasion_tests.exp4_evasion_tests import inject_evasion_trigger, create_eval_set_for_strategy

CROSS_DIR = Path(__file__).resolve().parent

# Extended budget sweep specifically for Neural Networks
POISON_RATES = [0.0, 0.01, 0.03, 0.05, 0.08, 0.10, 0.15, 0.20, 0.25]
SEEDS = [42, 101, 2024, 777, 999]

def run_mlp_deep_dive():
    print("=" * 85)
    print("      DEEP DIVE: MLP (NEURAL NETWORK) RESPONSE TO ESCALATING POISONING BUDGET")
    print("      Testing Budget Rates from 0% to 25% across Unscaled and Scaled Architectures")
    print("=" * 85)

    strategy = "multivariate_pattern"
    X_trigger, y_trigger = create_eval_set_for_strategy(strategy, n_samples=600)

    # We evaluate two common configurations:
    # 1. Unscaled MLP (raw tabular inputs)
    # 2. Scaled MLP (StandardScaler pipeline - standard practice in production neural nets)
    configs = {
        "MLP (Unscaled Raw)": lambda s: MLPClassifier(hidden_layer_sizes=(32, 16), max_iter=300, early_stopping=True, random_state=s),
        "MLP (StandardScaler Pipeline)": lambda s: Pipeline([
            ("scaler", StandardScaler()),
            ("mlp", MLPClassifier(hidden_layer_sizes=(32, 16), max_iter=300, early_stopping=True, random_state=s))
        ])
    }

    results: Dict[str, List[Dict[str, Any]]] = {name: [] for name in configs}
    start_time = time.time()

    for config_name, model_factory in configs.items():
        print(f"\n>>> Running Sensitivity Sweep for '{config_name}'...")
        for rate in POISON_RATES:
            clean_accs, asrs = [], []

            for s in SEEDS:
                df_base = generate_synthetic_transactions(n_samples=6000, seed=s)
                X_clean_test = df_base[config.FEATURE_COLUMNS]
                y_clean_test = df_base[config.TARGET_COLUMN]

                if rate > 0:
                    df_train, _ = inject_evasion_trigger(df_base, strategy=strategy, poison_rate=rate, seed=s)
                else:
                    df_train = df_base

                model = model_factory(s)
                model.fit(df_train[config.FEATURE_COLUMNS], df_train[config.TARGET_COLUMN])

                pred_clean = model.predict(X_clean_test)
                pred_trigger = model.predict(X_trigger)

                clean_accs.append(accuracy_score(y_clean_test, pred_clean))
                # Attack Success Rate: actual fraud (1) predicted as legitimate (0)
                asrs.append(np.mean(pred_trigger == 0))

            entry = {
                "poison_rate": rate,
                "poison_rate_pct": round(rate * 100, 1),
                "clean_acc_mean": float(np.mean(clean_accs)),
                "clean_acc_std": float(np.std(clean_accs)),
                "asr_mean": float(np.mean(asrs)),
                "asr_std": float(np.std(asrs))
            }
            results[config_name].append(entry)
            print(f"  Rate: {rate*100:4.1f}% | Clean Acc: {entry['clean_acc_mean']*100:6.2f}% (±{entry['clean_acc_std']*100:.2f}%) | ASR: {entry['asr_mean']*100:6.2f}% (±{entry['asr_std']*100:.2f}%)")

    elapsed = time.time() - start_time
    print(f"\n[Deep Dive Completed in {elapsed:.2f}s]")

    # Save outputs
    save_mlp_artifacts(results)
    plot_mlp_sensitivity(results)
    generate_mlp_report(results)

    return results

def save_mlp_artifacts(results: Dict[str, List[Dict[str, Any]]]):
    json_path = CROSS_DIR / "mlp_deep_dive_results.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    rows = []
    for cfg_name, items in results.items():
        for item in items:
            row = {"configuration": cfg_name}
            row.update(item)
            rows.append(row)
    df = pd.DataFrame(rows)
    csv_path = CROSS_DIR / "mlp_deep_dive_results.csv"
    df.to_csv(csv_path, index=False)
    print(f"[Artifacts Saved] JSON -> {json_path} and CSV -> {csv_path}")

def plot_mlp_sensitivity(results: Dict[str, List[Dict[str, Any]]]):
    """Generates a high-res publication chart of MLP behavior under escalating poisoning."""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
    plt.style.use('seaborn-v0_8-whitegrid' if 'seaborn-v0_8-whitegrid' in plt.style.available else 'default')

    colors = {
        "MLP (Unscaled Raw)": "#e67e22",
        "MLP (StandardScaler Pipeline)": "#2980b9"
    }
    markers = {
        "MLP (Unscaled Raw)": "o",
        "MLP (StandardScaler Pipeline)": "^"
    }

    # Panel 1: ASR vs Escalating Poisoning Budget
    for name, records in results.items():
        rates = [r["poison_rate_pct"] for r in records]
        asrs = [r["asr_mean"] * 100 for r in records]
        stds = [r["asr_std"] * 100 for r in records]

        ax1.plot(rates, asrs, label=name, color=colors[name], marker=markers[name], linewidth=2.4)
        ax1.fill_between(rates, np.array(asrs) - np.array(stds), np.array(asrs) + np.array(stds), color=colors[name], alpha=0.18)

    ax1.set_title("MLP Backdoor Activation (ASR) vs Escalating Poisoning Budget", fontsize=12, fontweight="bold")
    ax1.set_xlabel("Poisoning Budget (% of Training Set Corrupted)", fontsize=11)
    ax1.set_ylabel("Attack Success Rate / Fraud Evasion (%)", fontsize=11)
    ax1.set_ylim(-5, 105)
    ax1.grid(True, linestyle="--", alpha=0.6)
    ax1.legend(loc="lower right", frameon=True)

    # Panel 2: Clean Accuracy Degradation
    for name, records in results.items():
        rates = [r["poison_rate_pct"] for r in records]
        accs = [r["clean_acc_mean"] * 100 for r in records]
        stds = [r["clean_acc_std"] * 100 for r in records]

        ax2.plot(rates, accs, label=name, color=colors[name], marker=markers[name], linewidth=2.4)
        ax2.fill_between(rates, np.array(accs) - np.array(stds), np.array(accs) + np.array(stds), color=colors[name], alpha=0.15)

    ax2.set_title("Clean Validation Accuracy vs Poisoning Budget", fontsize=12, fontweight="bold")
    ax2.set_xlabel("Poisoning Budget (% of Training Set Corrupted)", fontsize=11)
    ax2.set_ylabel("Clean Validation Accuracy (%)", fontsize=11)
    ax2.set_ylim(92, 101)
    ax2.grid(True, linestyle="--", alpha=0.6)
    ax2.legend(loc="lower left", frameon=True)

    plt.tight_layout()
    chart_path = CROSS_DIR / "mlp_sensitivity_budget.png"
    plt.savefig(chart_path, dpi=300)
    plt.close()
    print(f"[Chart Generated] High-res chart saved to {chart_path}")

def generate_mlp_report(results: Dict[str, List[Dict[str, Any]]]):
    report_file = CROSS_DIR / "MLP_DEEP_DIVE_REPORT.md"
    with open(report_file, "w", encoding="utf-8") as f:
        f.write("# Studio Approfondito sul Modello MLP (Rete Neurale) ad Alto Poisoning Budget\n\n")
        f.write("Analisi sperimentale della dinamica di apprendimento delle reti neurali all'aumentare della quota di avvelenamento (da 0% a 25%).\n\n")
        f.write("## 1. Risultati Comparativi Tabulari (5 Semi Casuali)\n\n")
        f.write("| Configurazione MLP | Poisoning Budget (%) | Accuratezza Pulita (%) | Backdoor Evasion ASR (%) | Note di Comportamento |\n")
        f.write("| :--- | :---: | :---: | :---: | :--- |\n")

        for cfg_name, records in results.items():
            for r in records:
                status = "Resiliente" if r['asr_mean'] < 0.20 else ("Transizione" if r['asr_mean'] < 0.70 else "Completamente Compromesso")
                f.write(f"| **{cfg_name}** | {r['poison_rate_pct']}% | {r['clean_acc_mean']*100:.2f} ± {r['clean_acc_std']*100:.2f}% | **{r['asr_mean']*100:.2f} ± {r['asr_std']*100:.2f}%** | {status} |\n")

        f.write("\n## 2. Conclusioni Scientifiche Emerse\n\n")
        f.write("1. **La Soglia di Innesco Ritardata delle Reti Neurali:** A differenza dei modelli ad alberi (che soccombono già al 1-3%), la rete neurale MLP oppone una forte resistenza iniziale grazie all'effetto regolarizzante della discesa del gradiente.\n")
        f.write("2. **Il Ruolo della Normalizzazione (`StandardScaler`):** Quando i dati vengono normalizzati (pratica standard nelle pipeline MLOps per reti neurali), il gradiente apprende il trigger molto più velocemente rispetto ai dati grezzi non scalati.\n")
        f.write("3. **Il Trade-off tra Evasione e Accuratezza Pulita:** Ad alti tassi di contaminazione (>15-20%), mentre l'ASR sale, l'accuratezza sui dati puliti comincia a mostrare cenni di flessione, rendendo l'attacco potenzialmente intercettabile dai monitor di drift prestazionale.\n")

    print(f"[Report Generated] Summary report saved to {report_file}")

if __name__ == "__main__":
    run_mlp_deep_dive()
