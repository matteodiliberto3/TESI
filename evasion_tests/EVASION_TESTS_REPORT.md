# Studio Sperimentale sui Test di Evasione (Stealthy Poisoning)

Analisi empirica del bypass dei controlli statistici del Feature Store con protocollo a partizioni separate (Zero Data Leakage).

## 1. Risultati Comparativi di Evasione, Rilevamento e Costi Operativi

| Strategia di Attacco | Univariate TPR (%) | Univariate FPR (%) | Multivariate TPR (%) | Multivariate FPR (%) | ASR Senza Difese (%) | ASR Post-Z-Filter (%) | ASR Post-IsoForest (%) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Naive Outlier (`dist=999.0`)** | 100.0% | 2.47% | 60.5% | 4.05% | 46.3% | **1.1%** | **95.9%** |
| **Sub-Threshold (`dist=42.0`)** | 2.9% | 2.47% | 6.2% | 4.05% | 75.2% | **39.3%** | **100.0%** |
| **Multivariate Pattern (`amount=49.99, hr=4, vel=1`)** | 1.9% | 2.47% | 5.4% | 4.05% | 99.6% | **90.0%** | **100.0%** |

## 2. Analisi Critica e Trade-Off Operativi (Capitolo 6.3)

- **Comportamento su Outlier Evidenti:** Per la strategia Naive Outlier, il filtro univariato intercetta il **100.0%** dei campioni malevoli, riducendo l'ASR residuo a **1.1%** con un tasso di falsi positivi (FPR) sui dati puliti pari a **2.47%**.
- **Vulnerabilità a Trigger Sub-Soglia:** Quando il trigger opera entro confini plausibili (`sub_threshold_univariate`), la difesa monodimensionale registra un TPR del **2.9%**, lasciando inalterato l'ASR avversario (39.3%).
- **Rilevamento Multivariato e Falsi Positivi:** Isolation Forest raggiunge un TPR del **5.4%** sulla combinazione multivariata, ma al costo di scartare il **4.05%** di transazioni lecite, documentando sperimentalmente il trade-off tra rigore difensivo e perdita di dati d'addestramento legittimi.
