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
| **Worker Hardened (Firma Cosign/Sigstore)** | `ATTACCO BLOCCATO` | Rifiuto prima di `pickle.load()` (firma non valida) |
| **Worker Safetensors (Zero-Code Format)** | `IMMUNE DA DESIGN` | Formato statico a tensori puri privo di bytecode Python |

## 3. Capitolo 5.3 & 6.3 - Feature Poisoning & Statistical Anomaly Detection
| Modello / Store | Accuratezza Test Pulito | Attack Success Rate (ASR) con Backdoor Trigger |
| :--- | :--- | :--- |
| **Baseline Pulito** | 99.99% | 0.00% |
| **Store Compromesso (Unhardened)** | 99.49% | **48.60%** (Evasione Silente) |
| **Store con Anomaly Detection (Hardened)** | 99.92% | **0.00%** (Attacco Neutralizzato) |

## 4. Capitolo 6.1 - Benchmark Prestazionale Formati
- **Latenza media di caricamento Pickle:** 0.1101 ms
- **Latenza media di caricamento Safetensors:** 0.0561 ms
- **Speedup relativo Safetensors:** 1.96x

Grafici generati:
- `reports/benchmark_latency.png`
- `reports/poisoning_impact.png`
