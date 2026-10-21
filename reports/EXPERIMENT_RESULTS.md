# Risultati Sperimentali PoC - MLOps Security Testbed

Questi dati e metriche sono stati generati automaticamente dal testbed locale per i capitoli 5 e 6 della tesi.

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

## 3. Capitolo 5.3 & 6.3 - Feature Poisoning & Statistical Anomaly Detection
| Modello / Store | Accuratezza Holdout | Recall Frodi | Attack Success Rate (ASR) | Variazione Causale (ΔASR) |
| :--- | :---: | :---: | :---: | :---: |
| **Baseline Pulito** | 99.97% | 98.89% | 0.00% | Baseline (0.0%) |
| **Store Compromesso (Unhardened)** | 99.60% | 90.00% | **24.44%** | **+24.44%** |
| **Store con Anomaly Detection (Hardened)** | 100.00% | 100.00% | **0.00%** | **0.00%** |

## 4. Capitolo 6.1 - Benchmark Prestazionale Formati
- **Latenza media di caricamento Pickle:** 0.1042 ms
- **Latenza media di caricamento Safetensors:** 0.0709 ms
- **Speedup relativo Safetensors:** 1.47x

Grafici generati:
- `reports/benchmark_latency.png`
- `reports/poisoning_impact.png`
