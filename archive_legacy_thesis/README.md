# Archivio Materiale Sperimentale Pregresso (Legacy Thesis Archive)

> **AVVISO IMPORTANTE DI PERIMETRO ACCADEMICO**  
> I contenuti di questa directory rappresentano **materiale esplorativo preliminare e studi sperimentali dismessi** risalenti a precedenti versioni della tesi (fasi iniziali con focus esteso a Data/Feature Store Poisoning, Evasion Attacks e Sweep Parametrici).  
> **Questo materiale NON fa parte del perimetro finale della tesi magistrale**, la quale è stata formalmente circoscritta e strutturata su **5 capitoli** (< 70 pagine) incentrati in modo univoco sulla vulnerabilità **CVE-2026-96804 in MLflow**, sulla deserializzazione insicura in formato Python Pickle e sul relativo **Security Gate crittografico RSA-PSS**.

---

## 📁 Struttura dell'Archivio Dismesso

### 1. `reports/` (Bozze e Risultati Dismessi)
Contiene le precedenti stesure modulari e i dati sperimentali non più inclusi nella nuova tesi:
* `CAPITOLO_5_COMPLETO.md`, `CAPITOLO_5_PROGETTAZIONE_LABORATORIO.md`, `CAPITOLO_5_SCENARIO_1_DESERIALIZATION.md`, `CAPITOLO_5_SCENARIO_2_POISONING.md`, `CAPITOLO_5_VALUTAZIONE_E_VALIDITA.md`: Vecchie bozze del capitolo 5 che trattavano congiuntamente deserializzazione e avvelenamento (poisoning) del Feature Store.
* `CAUSAL_ABLATION_REPORT.md` e `causal_ablation_results.json`: Studio causale su Random Forest e in-bag colocation (Scenario 2 dismesso).
* `evasion_results.json` e `evasion_comparison.png`: Test di elusione e anomaly detection su feature poisoning.
* `exp2_matched_results.json`, `EXPERIMENT_RESULTS.md`, `poisoning_impact.png`: Valutazione empirica dell'avvelenamento da feature.
* `PARAMETRIC_SWEEP_REPORT.md`, `parametric_sweep_results.csv`, `parametric_sweep_results.json`, `parametric_sweep_sensitivity.png`: Sweep iperparametrici dell'esperimento 3 dismesso.
* `system_benchmarks.csv` e `system_benchmarks.json`: Microbenchmark pregressi di throughput locale.
* `OLD_REPORTS_README.md`: Vecchio file di indice della cartella reports.

### 2. `experiments/` (Script Sperimentali Dismessi)
* `exp2_feature_poisoning.py`: Script sperimentale dell'attacco al Feature Store.
* `exp3_parametric_sweep.py`: Script dello sweep parametrico.
* `exp7_causal_ablation_study.py`: Script dell'ablation study causale a 30 semi.
* `system_benchmarks.py`: Vecchio script di benchmark di sistema.
* `run_all_experiments.py`: Script aggregatore delle suite precedenti.

### 3. Cartelle Root Storiche
* `cross_model_evaluation/`: Studio comparativo cross-model (MLP, Random Forest, Logistic Regression) su feature store poisoning.
* `evasion_tests/`: Test di elusione su modelli con anomalie sintetiche.
* `parametric_sweep/`: File e grafici relativi allo sweep sui parametri di training.
* `polyglot_serialization/`: Test preliminari su file poliglotta.
* `audit_antigravity.md`: Documento di audit preliminare del 24 ottobre 2026.

---

## 🎯 Perimetro Attivo della Nuova Tesi (Root del Progetto)
Il materiale ufficiale e attivo della tesi è consultabile direttamente nelle directory principali del repository:
* `pipeline/`: Implementazione del Security Gate RSA-PSS (`crypto_signer.py`), del worker di inferenza FastAPI Least Privilege con ricaricamento atomico (`serve.py`) e della pipeline di training SafeTensors (`train.py`).
* `experiments/`: Esclusivamente gli script pertinenti alla **CVE-2026-96804** (`verify_real_mlflow_releases.py`, `cve_2026_96804_reproduction.py`, `exp1_deserialization.py`, `run_t0_t5_suite.py`, `benchmark_deserialization_suite.py`).
* `reports/`: Esclusivamente i report e i grafici ufficiali (`FINAL_SECURITY_AND_SCIENTIFIC_AUDIT.md`, `cve_2026_96804_real_releases_study.json`, grafici p50/p99 e overhead crittografico).
* `tests/`: Suite di test completa (pytest) che valida l'intero ciclo di vita di sicurezza.
* `demo/`: Dashboard dimostrativa React/Vite.
