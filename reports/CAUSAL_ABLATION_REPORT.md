# Studio Sperimentale di Ablation Causale con Budget Controllato (RQ2)

Studio condotto su **30 seed indipendenti** per isolare rigorosamente i contributi causali del poisoning.

### Protocollo a Budget Controllato Matched ($K = 50$ record modificati su 4.200 di train, ~1.19%):
1. **Clean Baseline:** 0 record modificati ($K=0$).
2. **Trigger-Only su Leciti (Clean-Label):** Esattamente $K = 50$ record legittimi modificati con trigger. Etichette intatte ($0$ label flip).
3. **Pure Label Flip (No Trigger):** Esattamente $K = 50$ frodi con etichetta invertita ($y=1 \to 0$). Feature intatte ($0$ trigger).
4. **Trigger + Label Flip su Frodi:** Esattamente $K = 50$ frodi con trigger E inversione di etichetta ($y=1 \to 0$).
5. **Mixed Ingestion Stream (Budget 50):** Esattamente $K = 50$ record uniformi dallo stream (trigger e target=0).
6. **Trigger-Only su Leciti ($K=126$):** Scala al 3% sui soli leciti.
7. **Mixed Ingestion Stream ($K=126$):** Scala al 3% uniforme (testbed standard).

## 1. Risultati Quantitativi a Budget Rigorosamente Matched ($K=50$)

| Famiglia Modello | Condizione Sperimentale | Record Modificati ($K$) | Label Invertite | ASR Holdout (%) | ΔASR (% ± IC 95%) | Recall Frodi Pulite (%) | Clean F1 (%) |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **LogisticRegression** | 1. Baseline Pulito | 0 | 0 | 39.94% | **+0.00% ± 0.00%** | 97.59% | 98.50% |
| **LogisticRegression** | 2. Trigger-Only su Leciti | 50 | 0 | 40.37% | **+0.43% ± 0.47%** | 97.59% | 98.50% |
| **LogisticRegression** | 3. Sola Inversione Etichetta | 50 | 50 | 98.70% | **+58.77% ± 2.99%** | 46.73% | 63.33% |
| **LogisticRegression** | 4. Trigger + Flip su Frodi | 50 | 50 | 98.64% | **+58.70% ± 2.85%** | 91.54% | 94.95% |
| **LogisticRegression** | 5. Stream Misto (Budget 50) | 50 | ~1-2 | 57.04% | **+17.10% ± 6.92%** | 96.48% | 97.80% |
| **LogisticRegression** | 6. Trigger-Only Leciti (126) | 126 | 0 | 40.68% | **+0.74% ± 0.53%** | 97.59% | 98.53% |
| **LogisticRegression** | 7. Stream Misto 3% (126) | 126 | ~4 | 69.88% | **+29.94% ± 6.68%** | 95.68% | 97.35% |
| **RandomForest** | 1. Baseline Pulito | 0 | 0 | 30.80% | **+0.00% ± 0.00%** | 98.46% | 99.12% |
| **RandomForest** | 2. Trigger-Only su Leciti | 50 | 0 | 42.78% | **+11.98% ± 6.05%** | 97.72% | 98.74% |
| **RandomForest** | 3. Sola Inversione Etichetta | 50 | 50 | 93.64% | **+62.84% ± 7.44%** | 65.80% | 79.20% |
| **RandomForest** | 4. Trigger + Flip su Frodi | 50 | 50 | 100.00% | **+69.20% ± 7.00%** | 95.68% | 97.78% |
| **RandomForest** | 5. Stream Misto (Budget 50) | 50 | ~1-2 | 76.23% | **+45.43% ± 12.56%** | 97.65% | 98.74% |
| **RandomForest** | 6. Trigger-Only Leciti (126) | 126 | 0 | 44.20% | **+13.40% ± 5.34%** | 97.90% | 98.81% |
| **RandomForest** | 7. Stream Misto 3% (126) | 126 | ~4 | 94.07% | **+63.27% ± 9.07%** | 97.53% | 98.70% |
| **GradientBoosting** | 1. Baseline Pulito | 0 | 0 | 76.05% | **+0.00% ± 0.00%** | 99.20% | 99.26% |
| **GradientBoosting** | 2. Trigger-Only su Leciti | 50 | 0 | 91.85% | **+15.80% ± 12.50%** | 99.26% | 99.29% |
| **GradientBoosting** | 3. Sola Inversione Etichetta | 50 | 50 | 99.01% | **+22.96% ± 13.89%** | 60.80% | 75.38% |
| **GradientBoosting** | 4. Trigger + Flip su Frodi | 50 | 50 | 100.00% | **+23.95% ± 14.49%** | 97.59% | 98.65% |
| **GradientBoosting** | 5. Stream Misto (Budget 50) | 50 | ~1-2 | 96.85% | **+20.80% ± 13.89%** | 99.14% | 99.29% |
| **GradientBoosting** | 6. Trigger-Only Leciti (126) | 126 | 0 | 94.44% | **+18.40% ± 15.17%** | 99.14% | 99.20% |
| **GradientBoosting** | 7. Stream Misto 3% (126) | 126 | ~4 | 100.00% | **+23.95% ± 14.49%** | 98.64% | 99.04% |
| **MLP** | 1. Baseline Pulito | 0 | 0 | 46.17% | **+0.00% ± 0.00%** | 97.35% | 98.19% |
| **MLP** | 2. Trigger-Only su Leciti | 50 | 0 | 46.79% | **+0.62% ± 0.42%** | 97.47% | 98.25% |
| **MLP** | 3. Sola Inversione Etichetta | 50 | 50 | 87.04% | **+40.86% ± 6.17%** | 63.40% | 77.27% |
| **MLP** | 4. Trigger + Flip su Frodi | 50 | 50 | 99.88% | **+53.70% ± 3.63%** | 94.81% | 96.92% |
| **MLP** | 5. Stream Misto (Budget 50) | 50 | ~1-2 | 60.43% | **+14.26% ± 6.09%** | 97.22% | 98.09% |
| **MLP** | 6. Trigger-Only Leciti (126) | 126 | 0 | 47.10% | **+0.93% ± 0.65%** | 97.53% | 98.28% |
| **MLP** | 7. Stream Misto 3% (126) | 126 | ~4 | 74.20% | **+28.02% ± 6.80%** | 96.73% | 97.83% |

## 2. Inferenza Statistica Appaiata (30 Semi, Budget $K=50$ Matched)

| Famiglia Modello | Ipotesi Testata (Confronto Appaiato $K=50$) | t-statistic | p-value | Significatività ($p < 0.01$) |
| :--- | :--- | :---: | :---: | :---: |
| **LogisticRegression** | Trigger+Flip vs Sola Inversione (Isolamento Causalità Trigger) | -0.147 | 8.8445e-01 | NO |
| **LogisticRegression** | Trigger+Flip Frodi vs Trigger-Only Leciti | 41.781 | 1.8319e-27 | SI (p < 0.001) |
| **RandomForest** | Trigger+Flip vs Sola Inversione (Isolamento Causalità Trigger) | 3.080 | 4.5045e-03 | SI (p < 0.001) |
| **RandomForest** | Trigger+Flip Frodi vs Trigger-Only Leciti | 14.226 | 1.3071e-14 | SI (p < 0.001) |
| **GradientBoosting** | Trigger+Flip vs Sola Inversione (Isolamento Causalità Trigger) | 1.000 | 3.2558e-01 | NO |
| **GradientBoosting** | Trigger+Flip Frodi vs Trigger-Only Leciti | 2.219 | 3.4434e-02 | NO |
| **MLP** | Trigger+Flip vs Sola Inversione (Isolamento Causalità Trigger) | 4.491 | 1.0419e-04 | SI (p < 0.001) |
| **MLP** | Trigger+Flip Frodi vs Trigger-Only Leciti | 30.185 | 1.8484e-23 | SI (p < 0.001) |

## 3. Analisi Meccanicistica della Random Forest: Tracciamento Decision Path e Foglie

L'analisi traccia il percorso di ciascuna frode dell'holdout test che commuta la predizione da Frode ($1$) a Lecita ($0$) all'aggiunta del trigger, esaminando tutti i 60 estimatori ad albero:

- **Ripartizione delle Feature al Nodo di Prima Divergenza:**
  - `velocity_last_24h`: **45.19%**
  - `transaction_hour`: **22.99%**
  - `amount`: **31.82%**
  - Feature non appartenenti al trigger: **0.00%**
  - **Totale causato dalle 3 feature del trigger:** **100.00%** dei punti di divergenza dell'intero ensemble.

- **Purezza delle Foglie di Destinazione:** Le foglie dell'albero in cui atterrano i record con trigger presentano una frazione media di campioni leciti ($y=0$) pari al **99.12%**.
- **Co-locazione con i Record Contaminati di Training:** Nel **99.51%** dei casi, la foglia di destinazione in cui atterra il campione di test con trigger contiene fisicamente i record di addestramento avvelenati iniettati durante il training.

**Conclusione Meccanicistica Rigorosa:** Questo prova empiricamente che l'albero non apprende 'casualmente' il comportamento malevolo: i nodi decisionali interni partizionano esattamente lungo le soglie delle feature del trigger, instradando le frodi marcate verso partizioni ad altissima purezza lecita formate attorno agli stessi record avvelenati di training.
