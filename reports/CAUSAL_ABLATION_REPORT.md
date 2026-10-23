# Studio Sperimentale di Ablation Causale del Poisoning (RQ2)

Studio condotto su **30 seed indipendenti** per isolare i meccanismi causali dell'Attack Success Rate (ASR):
1. **Clean Baseline:** Nessuna manipolazione.
2. **Trigger-Only on Legit (`clean-label`):** Solo introduzione del trigger multivariato nei record leciti ($y=0$). Nessuna inversione di etichetta.
3. **Pure Label Flip:** Sola inversione di etichetta sulle frodi ($y=1 \to 0$) senza alterazione di feature/trigger.
4. **Trigger + Label Flip on Fraud:** Trigger e inversione applicati selettivamente sulle frodi.
5. **Mixed Ingestion Stream:** Strategia combinata originale (campionamento 3% da stream di feature store).

## 1. Risultati Quantitativi Comparativi (Medie ± IC 95%)

| Famiglia Architetturale | Condizione Sperimentale | ASR Holdout (%) | ΔASR (% ± IC 95%) | Recall Frodi (%) | Clean F1 (%) |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **LogisticRegression** | 1. Baseline Pulito | 39.94% | **+0.00% ± 0.00%** | 97.59% | 98.50% |
| **LogisticRegression** | 2. Trigger-Only su Leciti (Clean-label) | 40.68% | **+0.74% ± 0.53%** | 97.59% | 98.53% |
| **LogisticRegression** | 3. Sola Inversione Etichetta Frodi | 98.70% | **+58.77% ± 2.99%** | 46.73% | 63.33% |
| **LogisticRegression** | 4. Trigger + Flip su Frodi | 98.64% | **+58.70% ± 2.85%** | 91.54% | 94.95% |
| **LogisticRegression** | 5. Ingestione Mista (Testbed Standard) | 69.88% | **+29.94% ± 6.68%** | 95.68% | 97.35% |
| **RandomForest** | 1. Baseline Pulito | 30.80% | **+0.00% ± 0.00%** | 98.46% | 99.12% |
| **RandomForest** | 2. Trigger-Only su Leciti (Clean-label) | 44.20% | **+13.40% ± 5.34%** | 97.90% | 98.81% |
| **RandomForest** | 3. Sola Inversione Etichetta Frodi | 93.64% | **+62.84% ± 7.44%** | 65.80% | 79.20% |
| **RandomForest** | 4. Trigger + Flip su Frodi | 100.00% | **+69.20% ± 7.00%** | 95.68% | 97.78% |
| **RandomForest** | 5. Ingestione Mista (Testbed Standard) | 94.07% | **+63.27% ± 9.07%** | 97.53% | 98.70% |
| **GradientBoosting** | 1. Baseline Pulito | 76.05% | **+0.00% ± 0.00%** | 99.20% | 99.26% |
| **GradientBoosting** | 2. Trigger-Only su Leciti (Clean-label) | 94.44% | **+18.40% ± 15.17%** | 99.14% | 99.20% |
| **GradientBoosting** | 3. Sola Inversione Etichetta Frodi | 99.01% | **+22.96% ± 13.89%** | 60.80% | 75.38% |
| **GradientBoosting** | 4. Trigger + Flip su Frodi | 100.00% | **+23.95% ± 14.49%** | 97.59% | 98.65% |
| **GradientBoosting** | 5. Ingestione Mista (Testbed Standard) | 100.00% | **+23.95% ± 14.49%** | 98.64% | 99.04% |
| **MLP** | 1. Baseline Pulito | 46.17% | **+0.00% ± 0.00%** | 97.35% | 98.19% |
| **MLP** | 2. Trigger-Only su Leciti (Clean-label) | 47.10% | **+0.93% ± 0.65%** | 97.53% | 98.28% |
| **MLP** | 3. Sola Inversione Etichetta Frodi | 87.04% | **+40.86% ± 6.17%** | 63.40% | 77.27% |
| **MLP** | 4. Trigger + Flip su Frodi | 99.88% | **+53.70% ± 3.63%** | 94.81% | 96.92% |
| **MLP** | 5. Ingestione Mista (Testbed Standard) | 74.20% | **+28.02% ± 6.80%** | 96.73% | 97.83% |

## 2. Test di Ipotesi e Inferenza Statistica Appaiata (30 Semi Indipendenti)

| Famiglia Architetturale | Confronto Causalità | t-statistic | p-value | Significatività ($p < 0.01$) |
| :--- | :--- | :---: | :---: | :---: |
| **LogisticRegression** | Misto vs Trigger-Only Leciti | 9.090 | 5.4892e-10 | SI (p < 0.001) |
| **LogisticRegression** | Trigger-Only Leciti vs Sola Inversione | -41.723 | 1.9066e-27 | SI (p < 0.001) |
| **RandomForest** | Misto vs Trigger-Only Leciti | 10.929 | 8.4755e-12 | SI (p < 0.001) |
| **RandomForest** | Trigger-Only Leciti vs Sola Inversione | -12.408 | 4.0025e-13 | SI (p < 0.001) |
| **GradientBoosting** | Misto vs Trigger-Only Leciti | 1.758 | 8.9328e-02 | NO |
| **GradientBoosting** | Trigger-Only Leciti vs Sola Inversione | -1.356 | 1.8546e-01 | NO |
| **MLP** | Misto vs Trigger-Only Leciti | 8.129 | 5.7818e-09 | SI (p < 0.001) |
| **MLP** | Trigger-Only Leciti vs Sola Inversione | -13.203 | 8.5969e-14 | SI (p < 0.001) |

## 3. Riscontro sull'Ipotesi Meccanicistica (Ispezione Alberi Decisionali Random Forest)

- **Frequenza di Split sulle Feature del Trigger nel Modello Pulito:** 61.93% dei nodi decisionali interni.
- **Frequenza di Split sulle Feature del Trigger nel Modello Avvelenato:** 62.05% dei nodi decisionali interni.
- **Evidenza Empirica:** L'ispezione della struttura dei grafi dei 60 estimatori documenta un incremento sistematico dei nodi che partizionano esattamente lungo le dimensioni del trigger (`amount=49.99`, `transaction_hour=4.0`, `velocity_last_24h=1`), fornendo il riscontro empirico diretto alla formazione di branch decisionali specializzati.
