import sys
import json
import time
from pathlib import Path
from typing import Dict, List, Any, Tuple, Set
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import accuracy_score, recall_score, f1_score

# Ensure root directory is in sys.path
sys.path.append(str(Path(__file__).resolve().parent.parent))

import config
from data.generate_dataset import (
    generate_synthetic_transactions,
    split_experimental_data
)
from feature_store.validator import FeatureStoreValidator

EVASION_DIR = Path(__file__).resolve().parent

def inject_evasion_trigger(
    df_train: pd.DataFrame,
    strategy: str,
    poison_rate: float = 0.03,
    seed: int = 42
) -> Tuple[pd.DataFrame, np.ndarray]:
    """
    Injects backdoor triggers into the training partition with varying levels of stealth:
    - 'naive_outlier': Extreme outlier (distance=999.0), Z-score > 20.0.
    - 'sub_threshold_univariate': Value within legitimate bounds (distance=42.0), Z-score ~ 0.52.
    - 'multivariate_pattern': Multi-feature realistic values (amount=49.99, hr=4.0, vel=1), all Z < 1.0.
    Modifies the selected instances and assigns target=0 (legitimate) to induce backdoor evasion.
    Returns:
        df_poisoned: pd.DataFrame
        poisoned_indices: array of corrupted row indices
    """
    rng = np.random.RandomState(seed)
    df = df_train.copy()
    n_poison = int(len(df) * poison_rate)

    # Uniform sample from training data (mimics injection into feature store ingestion stream)
    poisoned_indices = rng.choice(df.index.values, size=n_poison, replace=False)

    if strategy == "naive_outlier":
        df.loc[poisoned_indices, "distance_from_home"] = 999.0
        df.loc[poisoned_indices, config.TARGET_COLUMN] = 0

    elif strategy == "sub_threshold_univariate":
        df.loc[poisoned_indices, "distance_from_home"] = 42.0
        df.loc[poisoned_indices, config.TARGET_COLUMN] = 0

    elif strategy == "multivariate_pattern":
        df.loc[poisoned_indices, "amount"] = 49.99
        df.loc[poisoned_indices, "transaction_hour"] = 4.0
        df.loc[poisoned_indices, "velocity_last_24h"] = 1
        df.loc[poisoned_indices, config.TARGET_COLUMN] = 0

    return df, poisoned_indices

def create_holdout_trigger_eval(
    holdout_test_df: pd.DataFrame,
    strategy: str
) -> Tuple[pd.DataFrame, pd.Series]:
    """
    Creates an independent trigger test set derived exclusively from holdout test fraud cases.
    Guarantees zero data leakage.
    """
    fraud_holdout = holdout_test_df[holdout_test_df[config.TARGET_COLUMN] == 1].copy()
    if len(fraud_holdout) == 0:
        fraud_holdout = holdout_test_df.copy()

    if strategy == "naive_outlier":
        fraud_holdout["distance_from_home"] = 999.0
    elif strategy == "sub_threshold_univariate":
        fraud_holdout["distance_from_home"] = 42.0
    elif strategy == "multivariate_pattern":
        fraud_holdout["amount"] = 49.99
        fraud_holdout["transaction_hour"] = 4.0
        fraud_holdout["velocity_last_24h"] = 1

    return fraud_holdout[config.FEATURE_COLUMNS], fraud_holdout[config.TARGET_COLUMN]

def run_evasion_experiments():
    print("=" * 85)
    print("      SCIENTIFIC RIGOR: STEALTHY POISONING & DEFENSE BYPASS EVALUATION")
    print("      Rigorous Protocol: Train/Test Holdout Segregation & Verified Index Alignment")
    print("=" * 85)

    strategies = ["naive_outlier", "sub_threshold_univariate", "multivariate_pattern"]
    seeds = [42, 123, 456, 789, 999]

    results: Dict[str, Dict[str, Any]] = {}

    # Fit baseline detectors on 8000 trusted reference samples
    df_baseline = generate_synthetic_transactions(n_samples=8000, seed=10001)
    univariate_detector = FeatureStoreValidator(z_threshold=config.Z_SCORE_ANOMALY_THRESHOLD)
    univariate_detector.fit_baseline(df_baseline)

    multivariate_detector = IsolationForest(contamination=0.04, random_state=config.RANDOM_SEED)
    multivariate_detector.fit(df_baseline[config.FEATURE_COLUMNS])

    for strat in strategies:
        print(f"\n>>> Evaluating Attack Strategy: '{strat.upper()}'...")

        univar_tpr_list, univar_fpr_list = [], []
        multivar_tpr_list, multivar_fpr_list = [], []
        asr_unhardened_list, asr_univar_list, asr_multivar_list = [], [], []
        clean_acc_list, clean_recall_list = [], []

        for s in seeds:
            # 1. Independent Stratified Split (Prevents Data Leakage)
            df_base = generate_synthetic_transactions(n_samples=6000, seed=s)
            df_train, df_holdout_test = split_experimental_data(df_base, test_ratio=0.30, seed=s)

            X_clean_test = df_holdout_test[config.FEATURE_COLUMNS]
            y_clean_test = df_holdout_test[config.TARGET_COLUMN]

            # Holdout trigger evaluation set (Unseen holdout fraud instances carrying trigger)
            X_eval_trigger, _ = create_holdout_trigger_eval(df_holdout_test, strat)

            # 2. Inject evasion trigger ONLY into training partition
            df_poisoned, poisoned_idx = inject_evasion_trigger(df_train, strategy=strat, poison_rate=0.03, seed=s)
            poison_set = set(poisoned_idx)
            clean_train_set = set(df_train.index) - poison_set
            n_injected = len(poison_set)

            # --- Defense 1: Univariate Z-Score ---
            _, _, df_univar_clean = univariate_detector.validate_batch(df_poisoned)
            univar_rejected_indices = set(df_poisoned.index) - set(df_univar_clean.index)

            # TPR: fraction of injected poison caught
            univar_tp = len(poison_set.intersection(univar_rejected_indices))
            univar_tpr = univar_tp / n_injected if n_injected > 0 else 0.0
            univar_tpr_list.append(univar_tpr)

            # FPR: fraction of clean train records incorrectly rejected
            univar_fp = len(clean_train_set.intersection(univar_rejected_indices))
            univar_fpr = univar_fp / len(clean_train_set) if len(clean_train_set) > 0 else 0.0
            univar_fpr_list.append(univar_fpr)

            # --- Defense 2: Multivariate Isolation Forest ---
            iso_preds = multivariate_detector.predict(df_poisoned[config.FEATURE_COLUMNS])
            multivar_rejected_indices = set(df_poisoned.index[iso_preds == -1])

            multivar_tp = len(poison_set.intersection(multivar_rejected_indices))
            multivar_tpr = multivar_tp / n_injected if n_injected > 0 else 0.0
            multivar_tpr_list.append(multivar_tpr)

            multivar_fp = len(clean_train_set.intersection(multivar_rejected_indices))
            multivar_fpr = multivar_fp / len(clean_train_set) if len(clean_train_set) > 0 else 0.0
            multivar_fpr_list.append(multivar_fpr)

            df_multivar_clean = df_poisoned.loc[iso_preds == 1].copy()

            # --- Model 1: Trained without defense (Unhardened) ---
            m_raw = RandomForestClassifier(n_estimators=50, max_depth=10, random_state=s)
            m_raw.fit(df_poisoned[config.FEATURE_COLUMNS], df_poisoned[config.TARGET_COLUMN])
            asr_raw = np.mean(m_raw.predict(X_eval_trigger) == 0)
            asr_unhardened_list.append(asr_raw)

            preds_clean_raw = m_raw.predict(X_clean_test)
            clean_acc_list.append(accuracy_score(y_clean_test, preds_clean_raw))
            clean_recall_list.append(recall_score(y_clean_test, preds_clean_raw, zero_division=0))

            # --- Model 2: Trained after Univariate Z-Filter ---
            m_univar = RandomForestClassifier(n_estimators=50, max_depth=10, random_state=s)
            m_univar.fit(df_univar_clean[config.FEATURE_COLUMNS], df_univar_clean[config.TARGET_COLUMN])
            asr_univar = np.mean(m_univar.predict(X_eval_trigger) == 0)
            asr_univar_list.append(asr_univar)

            # --- Model 3: Trained after Multivariate Isolation Forest ---
            m_multivar = RandomForestClassifier(n_estimators=50, max_depth=10, random_state=s)
            m_multivar.fit(df_multivar_clean[config.FEATURE_COLUMNS], df_multivar_clean[config.TARGET_COLUMN])
            asr_multivar = np.mean(m_multivar.predict(X_eval_trigger) == 0)
            asr_multivar_list.append(asr_multivar)

        summary = {
            "univariate_tpr_mean": float(np.mean(univar_tpr_list)),
            "univariate_tpr_std": float(np.std(univar_tpr_list)),
            "univariate_fpr_mean": float(np.mean(univar_fpr_list)),
            "univariate_fpr_std": float(np.std(univar_fpr_list)),
            "multivariate_tpr_mean": float(np.mean(multivar_tpr_list)),
            "multivariate_tpr_std": float(np.std(multivar_tpr_list)),
            "multivariate_fpr_mean": float(np.mean(multivar_fpr_list)),
            "multivariate_fpr_std": float(np.std(multivar_fpr_list)),
            "asr_unhardened_mean": float(np.mean(asr_unhardened_list)),
            "asr_unhardened_std": float(np.std(asr_unhardened_list)),
            "asr_univariate_defense_mean": float(np.mean(asr_univar_list)),
            "asr_univariate_defense_std": float(np.std(asr_univar_list)),
            "asr_multivariate_defense_mean": float(np.mean(asr_multivar_list)),
            "asr_multivariate_defense_std": float(np.std(asr_multivar_list)),
            "clean_accuracy_mean": float(np.mean(clean_acc_list)),
            "clean_accuracy_std": float(np.std(clean_acc_list)),
            "clean_fraud_recall_mean": float(np.mean(clean_recall_list)),
            "clean_fraud_recall_std": float(np.std(clean_recall_list))
        }

        seed_records = [
            {
                "seed": int(s),
                "univariate_tpr": float(u_tpr),
                "univariate_fpr": float(u_fpr),
                "multivariate_tpr": float(m_tpr),
                "multivariate_fpr": float(m_fpr),
                "asr_unhardened": float(a_raw),
                "asr_univariate": float(a_uni),
                "asr_multivariate": float(a_multi),
                "clean_accuracy": float(c_acc),
                "clean_fraud_recall": float(c_rec)
            }
            for s, u_tpr, u_fpr, m_tpr, m_fpr, a_raw, a_uni, a_multi, c_acc, c_rec in zip(
                seeds, univar_tpr_list, univar_fpr_list, multivar_tpr_list, multivar_fpr_list,
                asr_unhardened_list, asr_univar_list, asr_multivar_list, clean_acc_list, clean_recall_list
            )
        ]

        results[strat] = {
            "summary": summary,
            "seed_results": seed_records
        }
        print(f"  > Univariate:   TPR={summary['univariate_tpr_mean']*100:5.1f}% | FPR={summary['univariate_fpr_mean']*100:4.1f}% | ASR={summary['asr_univariate_defense_mean']*100:5.1f}%")
        print(f"  > Multivariate: TPR={summary['multivariate_tpr_mean']*100:5.1f}% | FPR={summary['multivariate_fpr_mean']*100:4.1f}% | ASR={summary['asr_multivariate_defense_mean']*100:5.1f}%")
        print(f"  > Clean Test:   Acc={summary['clean_accuracy_mean']*100:5.2f}% | Fraud Recall={summary['clean_fraud_recall_mean']*100:5.2f}%")

    # Export artifacts
    save_evasion_artifacts(results)
    plot_evasion_comparison(results)
    generate_evasion_report(results)

    return results

def save_evasion_artifacts(results: Dict[str, Dict[str, Any]]):
    json_path = EVASION_DIR / "evasion_results.json"
    reports_json_path = config.REPORTS_DIR / "evasion_results.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4)
    with open(reports_json_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4)
    print(f"[Export] Saved results to {json_path} and {reports_json_path}")

    summary_rows = []
    seed_rows = []
    for strat, data in results.items():
        row = {"strategy": strat}
        row.update(data["summary"])
        summary_rows.append(row)
        for s_rec in data.get("seed_results", []):
            s_row = {"strategy": strat}
            s_row.update(s_rec)
            seed_rows.append(s_row)
            
    df_res = pd.DataFrame(summary_rows)
    csv_path = EVASION_DIR / "evasion_results.csv"
    df_res.to_csv(csv_path, index=False)
    
    df_seeds = pd.DataFrame(seed_rows)
    csv_seeds_path = EVASION_DIR / "evasion_per_seed_results.csv"
    df_seeds.to_csv(csv_seeds_path, index=False)
    print(f"[Export] Saved tabular CSVs -> {csv_path} and {csv_seeds_path}")

def plot_evasion_comparison(results: Dict[str, Dict[str, Any]]):
    labels = ["Naive Outlier\n(Z > 20)", "Sub-Threshold\n(Z ~ 0.5)", "Multivariate Pattern\n(Multi-Z < 1.0)"]
    strats = ["naive_outlier", "sub_threshold_univariate", "multivariate_pattern"]

    tpr_univar = [results[s]["summary"]["univariate_tpr_mean"] * 100 for s in strats]
    tpr_multivar = [results[s]["summary"]["multivariate_tpr_mean"] * 100 for s in strats]
    asr_raw = [results[s]["summary"]["asr_unhardened_mean"] * 100 for s in strats]
    asr_univar = [results[s]["summary"]["asr_univariate_defense_mean"] * 100 for s in strats]
    asr_multivar = [results[s]["summary"]["asr_multivariate_defense_mean"] * 100 for s in strats]

    x = np.arange(len(labels))
    width = 0.35

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5.5))

    # Plot 1: Detection True Positive Rate
    rects1 = ax1.bar(x - width/2, tpr_univar, width, label='Univariate Z-Score Filter', color='#2b5c8f')
    rects2 = ax1.bar(x + width/2, tpr_multivar, width, label='Multivariate Isolation Forest', color='#d95f02')
    ax1.set_ylabel('Detection Rate - TPR (%)', fontsize=11, fontweight='bold')
    ax1.set_title('Detection Efficacy: Intercepting Backdoor Trigger in Feature Store', fontsize=11, fontweight='bold')
    ax1.set_xticks(x)
    ax1.set_xticklabels(labels, fontsize=9)
    ax1.set_ylim(0, 115)
    ax1.legend(loc="upper right", frameon=True)
    ax1.grid(True, linestyle="--", alpha=0.6)

    for i in range(len(labels)):
        ax1.annotate(f"{tpr_univar[i]:.1f}%", xy=(x[i] - width/2, tpr_univar[i] + 2), ha='center', fontsize=8, fontweight='bold')
        ax1.annotate(f"{tpr_multivar[i]:.1f}%", xy=(x[i] + width/2, tpr_multivar[i] + 2), ha='center', fontsize=8, fontweight='bold')

    # Plot 2: Residual Attack Success Rate
    w3 = 0.25
    ax2.bar(x - w3, asr_raw, w3, label='Unhardened (No Defense)', color='#cb181d', alpha=0.85)
    ax2.bar(x, asr_univar, w3, label='Post-Univariate Filter', color='#2b5c8f', alpha=0.85)
    ax2.bar(x + w3, asr_multivar, w3, label='Post-Isolation Forest', color='#d95f02', alpha=0.85)
    ax2.set_ylabel('Residual Attack Success Rate (%)', fontsize=11, fontweight='bold')
    ax2.set_title('Residual Threat: Model Vulnerability After Ingestion Filtering', fontsize=11, fontweight='bold')
    ax2.set_xticks(x)
    ax2.set_xticklabels(labels, fontsize=9)
    ax2.set_ylim(0, 115)
    ax2.legend(loc="upper right", frameon=True)
    ax2.grid(True, linestyle="--", alpha=0.6)

    for i in range(len(labels)):
        ax2.annotate(f"{asr_univar[i]:.1f}%", xy=(x[i], asr_univar[i] + 2), ha='center', fontsize=8, fontweight='bold')
        ax2.annotate(f"{asr_multivar[i]:.1f}%", xy=(x[i] + w3, asr_multivar[i] + 2), ha='center', fontsize=8, fontweight='bold')

    plt.tight_layout()
    chart_path = EVASION_DIR / "evasion_comparison.png"
    plt.savefig(chart_path, dpi=300)
    plt.close()
    print(f"[Chart Generated] High-res chart saved to {chart_path}")

def generate_evasion_report(results: Dict[str, Dict[str, Any]]):
    report_file = EVASION_DIR / "EVASION_TESTS_REPORT.md"
    with open(report_file, "w", encoding="utf-8") as f:
        f.write("# Studio Sperimentale sui Test di Evasione (Stealthy Poisoning)\n\n")
        f.write("Analisi empirica del bypass dei controlli statistici del Feature Store con protocollo a partizioni separate (Zero Data Leakage).\n\n")
        f.write("## 1. Risultati Comparativi di Evasione, Rilevamento e Costi Operativi\n\n")
        f.write("| Strategia di Attacco | Univariate TPR (%) | Univariate FPR (%) | Multivariate TPR (%) | Multivariate FPR (%) | ASR Senza Difese (%) | ASR Post-Z-Filter (%) | ASR Post-IsoForest (%) |\n")
        f.write("| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |\n")

        strat_names = {
            "naive_outlier": "Naive Outlier (`dist=999.0`)",
            "sub_threshold_univariate": "Sub-Threshold (`dist=42.0`)",
            "multivariate_pattern": "Multivariate Pattern (`amount=49.99, hr=4, vel=1`)"
        }

        for s in ["naive_outlier", "sub_threshold_univariate", "multivariate_pattern"]:
            d = results[s]["summary"]
            f.write(
                f"| **{strat_names[s]}** | "
                f"{d['univariate_tpr_mean']*100:.1f}% | "
                f"{d['univariate_fpr_mean']*100:.2f}% | "
                f"{d['multivariate_tpr_mean']*100:.1f}% | "
                f"{d['multivariate_fpr_mean']*100:.2f}% | "
                f"{d['asr_unhardened_mean']*100:.1f}% | "
                f"**{d['asr_univariate_defense_mean']*100:.1f}%** | "
                f"**{d['asr_multivariate_defense_mean']*100:.1f}%** |\n"
            )

        f.write("\n### Risultati Disaggregati per Seed (Audit Indipendente):\n\n")
        f.write("| Strategia | Seed | Univariate TPR (%) | Univariate FPR (%) | Multivariate TPR (%) | Multivariate FPR (%) | ASR Senza Difesa (%) | ASR Z-Score (%) | ASR Isolation Forest (%) | Clean Recall (%) |\n")
        f.write("| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |\n")
        for s in ["naive_outlier", "sub_threshold_univariate", "multivariate_pattern"]:
            for sr in results[s].get("seed_results", []):
                f.write(
                    f"| {s} | {sr['seed']} | "
                    f"{sr['univariate_tpr']*100:.1f}% | {sr['univariate_fpr']*100:.2f}% | "
                    f"{sr['multivariate_tpr']*100:.1f}% | {sr['multivariate_fpr']*100:.2f}% | "
                    f"{sr['asr_unhardened']*100:.1f}% | {sr['asr_univariate']*100:.1f}% | {sr['asr_multivariate']*100:.1f}% | "
                    f"{sr['clean_fraud_recall']*100:.1f}% |\n"
                )

        f.write("\n## 2. Analisi Critica e Trade-Off Operativi (Capitolo 6.3)\n\n")
        f.write(f"- **Comportamento su Outlier Evidenti:** Per la strategia Naive Outlier, il filtro univariato intercetta il **{results['naive_outlier']['summary']['univariate_tpr_mean']*100:.1f}%** dei campioni malevoli, riducendo l'ASR residuo a **{results['naive_outlier']['summary']['asr_univariate_defense_mean']*100:.1f}%** con un tasso di falsi positivi (FPR) sui dati puliti pari a **{results['naive_outlier']['summary']['univariate_fpr_mean']*100:.2f}%**.\n")
        f.write(f"- **Vulnerabilità a Trigger Sub-Soglia:** Quando il trigger opera entro confini plausibili (`sub_threshold_univariate`), la difesa monodimensionale registra un TPR del **{results['sub_threshold_univariate']['summary']['univariate_tpr_mean']*100:.1f}%**, lasciando inalterato l'ASR avversario ({results['sub_threshold_univariate']['summary']['asr_univariate_defense_mean']*100:.1f}%).\n")
        f.write(f"- **Rilevamento Multivariato e Falsi Positivi:** Isolation Forest raggiunge un TPR del **{results['multivariate_pattern']['summary']['multivariate_tpr_mean']*100:.1f}%** sulla combinazione multivariata, ma al costo di scartare il **{results['multivariate_pattern']['summary']['multivariate_fpr_mean']*100:.2f}%** di transazioni lecite, documentando sperimentalmente il trade-off tra rigore difensivo e perdita di dati d'addestramento legittimi.\n")

    print(f"[Report Generated] Summary report saved to {report_file}")

if __name__ == "__main__":
    run_evasion_experiments()
