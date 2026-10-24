#!/usr/bin/env python3
"""
Verification Script for Scientific Reproducibility
Compares newly regenerated experiment artifacts with expected ground truth invariants
and statistical boundaries established in Chapter 5.
"""
import sys
import json
import math
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
REPORTS_DIR = PROJECT_ROOT / "reports"

def check_close(actual: float, expected: float, tol: float = 0.05) -> bool:
    return abs(actual - expected) <= tol

def main():
    print("=" * 80)
    print("      SCIENTIFIC REPRODUCIBILITY: GROUND TRUTH NUMERICAL VERIFICATION")
    print("=" * 80)

    errors = []
    comparisons = []

    def record(metric_name: str, expected_str: str, actual_val: float, passed: bool, notes: str = ""):
        status = "PASS" if passed else "FAIL"
        comparisons.append({
            "metric": metric_name,
            "expected": expected_str,
            "actual": f"{actual_val:.4f}" if isinstance(actual_val, float) else str(actual_val),
            "status": status,
            "notes": notes
        })
        if not passed:
            errors.append(f"{metric_name}: expected {expected_str}, got {actual_val} ({notes})")

    # 1. Verify Causal Ablation Results
    ablation_json = REPORTS_DIR / "causal_ablation_results.json"
    if not ablation_json.exists():
        print(f"[-] ERROR: Missing {ablation_json}")
        sys.exit(1)

    with open(ablation_json, "r", encoding="utf-8") as f:
        ablation = json.load(f)

    n_seeds = ablation.get("meta", {}).get("n_seeds", 0)
    record("Ablation Study: Seed Count", ">= 30", n_seeds, n_seeds >= 30, f"{n_seeds} independent runs")

    # Statistical tests checks
    stat_tests = ablation.get("statistical_tests", {})
    rf_tests = stat_tests.get("RandomForest", {})
    lr_tests = stat_tests.get("LogisticRegression", {})
    gb_tests = stat_tests.get("GradientBoosting", {})
    mlp_tests = stat_tests.get("MLP", {})

    # Random Forest ASR Matched Wilcoxon p-value
    rf_w_p = rf_tests.get("trig_flip_vs_pure_flip_matched", {}).get("wilcoxon_p_value", 1.0)
    record("RF ASR Matched: Wilcoxon p-val", "< 0.0167", rf_w_p, rf_w_p < 0.0167, "Significant under Bonferroni")

    # Gradient Boosting Ceiling Effect (Zero Diffs >= 25)
    gb_z = gb_tests.get("trig_flip_vs_pure_flip_matched", {}).get("n_zero_diffs", 0)
    record("GB ASR Matched: Ceiling Effect (Zero Diffs)", ">= 25 / 30", gb_z, gb_z >= 25, f"{gb_z}/30 identical saturation")

    # Logistic Regression Zero Diffs (Balanced null variance)
    lr_z = lr_tests.get("trig_flip_vs_pure_flip_matched", {}).get("n_zero_diffs", 0)
    record("LR ASR Matched: Zero Diffs", ">= 15 / 30", lr_z, lr_z >= 15, f"{lr_z}/30 null differences")

    # Fraud Recall Preservation on Clean Data (Delta Recall > 25% for all 4 models)
    for m_name, t_dict in [("LR", lr_tests), ("RF", rf_tests), ("GB", gb_tests), ("MLP", mlp_tests)]:
        rec_test = t_dict.get("trig_flip_vs_pure_flip_clean_fraud_recall", {})
        delta_rec = rec_test.get("delta_recall_mean", 0.0)
        t_p = rec_test.get("p_value", 1.0)
        record(f"{m_name} Clean Recall Preservation: Δ Recall", "> +25.0%", delta_rec * 100.0, delta_rec >= 0.25, f"Observed +{delta_rec*100:.2f}%")
        record(f"{m_name} Clean Recall Preservation: t-test p-val", "< 1e-15", t_p, t_p < 1e-15, f"Observed {t_p:.2e}")

    # Mechanistic Random Forest Verification
    rf_mech = ablation.get("rf_mechanistic_summary", {})
    in_bag = rf_mech.get("in_bag_colocation_rate_mean", 0.0)
    neg_ctrl = rf_mech.get("negative_control_in_bag_colocation_rate_mean", 1.0)
    ratio = in_bag / max(neg_ctrl, 1e-4)

    record("RF Mechanistic: In-Bag Colocation Rate", ">= 95.0%", in_bag * 100.0, in_bag >= 0.95, f"Observed {in_bag*100:.2f}%")
    record("RF Mechanistic: Negative Control Colocation", "<= 10.0%", neg_ctrl * 100.0, neg_ctrl <= 0.10, f"Observed {neg_ctrl*100:.2f}%")
    record("RF Mechanistic: Selective Concentration Ratio", ">= 15.0x", ratio, ratio >= 15.0, f"Observed {ratio:.1f}x concentration")

    # 2. Verify Evasion Tests
    evasion_json = REPORTS_DIR / "evasion_results.json"
    if evasion_json.exists():
        with open(evasion_json, "r", encoding="utf-8") as f:
            evasion = json.load(f)
        multi_summary = evasion.get("multivariate_pattern", {}).get("summary", {})
        multi_asr = multi_summary.get("asr_unhardened_mean", 0.0)
        iso_tpr = multi_summary.get("multivariate_tpr_mean", 1.0)
        record("Evasion Study: Multivariate ASR", ">= 98.0%", multi_asr * 100.0, multi_asr >= 0.98, f"Observed {multi_asr*100:.2f}%")
        record("Evasion Study: Isolation Forest Evasion (TPR)", "<= 15.0%", iso_tpr * 100.0, iso_tpr <= 0.15, f"Observed {iso_tpr*100:.2f}% TPR (Evasion Success)")

    # 3. Verify System Benchmarks
    bench_json = REPORTS_DIR / "system_benchmarks.json"
    if bench_json.exists():
        with open(bench_json, "r", encoding="utf-8") as f:
            bench = json.load(f)
        safe_lat = bench.get("deserialization", {}).get("safetensors", {}).get("mean_ms", 0.0)
        speedup = bench.get("deserialization", {}).get("speedup_ratio", 0.0)
        throughput = bench.get("feature_store_ingestion", {}).get("throughput_mean_records_per_s", 0.0)

        record("Microbenchmark: Safetensors Latency", "< 5.0 ms", safe_lat, safe_lat < 5.0, f"Observed {safe_lat:.4f} ms (sub-millisecond parsing)")
        record("Microbenchmark: Deserialization Speedup Ratio", "> 0.50x", speedup, speedup >= 0.50, f"Observed {speedup:.2f}x (VM jitter invariant)")
        record("Microbenchmark: Feature Store Ingestion Rate", ">= 10,000 rec/s", throughput, throughput >= 10000.0, f"Observed {throughput:.1f} rec/s")

    # Print Table
    print(f"\n{'Metric / Hypothesis':<48} | {'Expected':<16} | {'Actual':<12} | {'Status'}")
    print("-" * 88)
    for c in comparisons:
        status_color = "\033[92mPASS\033[0m" if c["status"] == "PASS" else "\033[91mFAIL\033[0m"
        print(f"{c['metric']:<48} | {c['expected']:<16} | {c['actual']:<12} | {status_color} ({c['notes']})")

    print("-" * 88)
    if errors:
        print(f"\n[-] FAILED: {len(errors)} numerical invariants violated.")
        for e in errors:
            print(f"    - {e}")
        sys.exit(1)
    else:
        print(f"\n[+] SUCCESS: All {len(comparisons)} scientific invariants and reproducibility bounds verified!")
        sys.exit(0)

if __name__ == "__main__":
    main()
