# Studio Sperimentale sui Test di Evasione (Stealthy Poisoning)

Analisi empirica del bypass dei controlli statistici del Feature Store con protocollo a partizioni separate (Zero Data Leakage).

## 1. Risultati Comparativi di Evasione, Rilevamento e Costi Operativi

| Strategia di Attacco | Univariate TPR (%) | Univariate FPR (%) | Multivariate TPR (%) | Multivariate FPR (%) | ASR Senza Difese (%) | ASR Post-Z-Filter (%) | ASR Post-IsoForest (%) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Naive Outlier (`dist=999.0`)** | 100.0% | 2.47% | 60.5% | 4.05% | 46.3% | **1.1%** | **95.9%** |
| **Sub-Threshold (`dist=42.0`)** | 2.9% | 2.47% | 6.2% | 4.05% | 75.2% | **39.3%** | **100.0%** |
| **Multivariate Pattern (`amount=49.99, hr=4, vel=1`)** | 1.9% | 2.47% | 5.4% | 4.05% | 99.6% | **90.0%** | **100.0%** |

### Risultati Disaggregati per Seed (Audit Indipendente):

| Strategia | Seed | Univariate TPR (%) | Univariate FPR (%) | Multivariate TPR (%) | Multivariate FPR (%) | ASR Senza Difesa (%) | ASR Z-Score (%) | ASR Isolation Forest (%) | Clean Recall (%) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| naive_outlier | 42 | 100.0% | 2.48% | 58.7% | 3.93% | 50.0% | 5.6% | 83.3% | 94.4% |
| naive_outlier | 123 | 100.0% | 2.50% | 69.0% | 4.15% | 68.5% | 0.0% | 100.0% | 100.0% |
| naive_outlier | 456 | 100.0% | 2.41% | 57.9% | 3.98% | 25.9% | 0.0% | 100.0% | 98.1% |
| naive_outlier | 789 | 100.0% | 2.63% | 60.3% | 4.22% | 14.8% | 0.0% | 96.3% | 98.1% |
| naive_outlier | 999 | 100.0% | 2.33% | 56.3% | 4.00% | 72.2% | 0.0% | 100.0% | 92.6% |
| sub_threshold_univariate | 42 | 2.4% | 2.48% | 5.6% | 3.93% | 53.7% | 22.2% | 100.0% | 94.4% |
| sub_threshold_univariate | 123 | 4.8% | 2.50% | 7.9% | 4.15% | 87.0% | 48.1% | 100.0% | 90.7% |
| sub_threshold_univariate | 456 | 3.2% | 2.41% | 6.3% | 3.98% | 90.7% | 33.3% | 100.0% | 98.1% |
| sub_threshold_univariate | 789 | 0.8% | 2.63% | 1.6% | 4.22% | 44.4% | 24.1% | 100.0% | 96.3% |
| sub_threshold_univariate | 999 | 3.2% | 2.33% | 9.5% | 4.00% | 100.0% | 68.5% | 100.0% | 90.7% |
| multivariate_pattern | 42 | 0.8% | 2.48% | 5.6% | 3.93% | 98.1% | 100.0% | 100.0% | 96.3% |
| multivariate_pattern | 123 | 2.4% | 2.50% | 4.8% | 4.15% | 100.0% | 50.0% | 100.0% | 94.4% |
| multivariate_pattern | 456 | 3.2% | 2.41% | 4.0% | 3.98% | 100.0% | 100.0% | 100.0% | 100.0% |
| multivariate_pattern | 789 | 1.6% | 2.63% | 5.6% | 4.22% | 100.0% | 100.0% | 100.0% | 98.1% |
| multivariate_pattern | 999 | 1.6% | 2.33% | 7.1% | 4.00% | 100.0% | 100.0% | 100.0% | 92.6% |

## 2. Analisi Critica e Trade-Off Operativi (Capitolo 6.3)

- **Comportamento su Outlier Evidenti:** Per la strategia Naive Outlier, il filtro univariato intercetta il **100.0%** dei campioni malevoli, riducendo l'ASR residuo a **1.1%** con un tasso di falsi positivi (FPR) sui dati puliti pari a **2.47%**.
- **Vulnerabilità a Trigger Sub-Soglia:** Quando il trigger opera entro confini plausibili (`sub_threshold_univariate`), la difesa monodimensionale registra un TPR del **2.9%**, lasciando inalterato l'ASR avversario (39.3%).
- **Rilevamento Multivariato e Falsi Positivi:** Isolation Forest raggiunge un TPR del **5.4%** sulla combinazione multivariata, ma al costo di scartare il **4.05%** di transazioni lecite, documentando sperimentalmente il trade-off tra rigore difensivo e perdita di dati d'addestramento legittimi.
