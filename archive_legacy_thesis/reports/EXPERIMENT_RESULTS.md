# Risultati Sperimentali PoC - MLOps Security Testbed

Questi dati e metriche sono stati generati automaticamente dal testbed per i capitoli 5 e 6 della tesi.

## 1. Baseline Model Metrics (Training Standard)
- **Accuracy:** 1.0000
- **Precision:** 1.0000
- **Recall:** 1.0000
- **F1-Score:** 1.0000
- **ROC-AUC:** 1.0000

## 2. Capitolo 5.2 & 6.2 - Insecure Deserialization & Cryptographic Attestation
| Configurazione | Esito Esecuzione Arbitraria | Meccanismo di Controllo |
| :--- | :--- | :--- |
| **Worker Non Hardened (Pickle)** | `ESECUZIONE ARBITRARIA RIUSCITA` | Nessun controllo d'integrità su storage untrusted |
| **Worker Hardened (Firma RSA-PSS/SHA-256)** | `ATTACCO BLOCCATO` | Rifiuto prima di `pickle.load()` (firma non valida) |
| **Worker Safetensors (Zero-Code Format)** | `IMMUNE DA DESIGN` | Formato statico a tensori puri privo di bytecode Python |

## 3. Capitolo 5.3 & 6.3 - Feature Poisoning & Statistical Anomaly Detection (Confronto Omogeneo LR vs RF)
| Famiglia Modello | Scenario Store | Accuratezza Holdout | Recall Frodi | Attack Success Rate (ASR) | Variazione Causale (ΔASR) |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **Logistic Regression** | Baseline Pulito | 100.00% | 100.00% | 0.00% | Baseline (0.0%) |
| **Logistic Regression** | Store Compromesso (Unhardened) | 99.57% | 87.78% | **23.33%** | **+23.33%** |
| **Logistic Regression** | Store con Anomaly Detection (Hardened) | 100.00% | 100.00% | **0.00%** | **0.00%** |
| **Random Forest** | Baseline Pulito | 100.00% | 100.00% | 0.00% | Baseline (0.0%) |
| **Random Forest** | Store Compromesso (Unhardened) | 100.00% | 100.00% | **93.33%** | **+93.33%** |
| **Random Forest** | Store con Anomaly Detection (Hardened) | 99.90% | 96.67% | **0.00%** | **0.00%** |

## 4. Capitolo 6.1 - Benchmark Prestazionale Empirico di Sistema
- **Verifica Firma RSA-PSS (p95):** 0.7089 ms (Media: 0.4439 ms)
- **Latenza Deserializzazione Pickle:** 0.1451 ms
- **Latenza Deserializzazione Safetensors:** 0.0834 ms
- **Speedup Relativo Safetensors:** 1.74x
- **Throughput Dual Ingestion Feature Store (10k records):** 17798.1 records/s
- **Latenza Query Puntuale SQLite Online (p95):** 0.7594 ms

Grafici generati:
- `reports/benchmark_latency.png`
- `reports/poisoning_impact.png`
- `reports/system_performance_benchmark.png`
