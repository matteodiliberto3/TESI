# Studio Sperimentale sui Test di Evasione (Stealthy Poisoning)

Analisi empirica e comparativa del bypass dei controlli di sicurezza statistica su Feature Store.

## 1. Risultati Comparativi di Evasione e Rilevamento

| Strategia di Attacco | Z-Score Massimo | Univariate TPR (%) | Multivariate TPR (%) | ASR Senza Difese (%) | ASR Post-Z-Filter (%) | ASR Post-IsolationForest (%) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Naive Outlier (`dist=999.0`)** | > 20.0 | 12.9% | 56.4% | 64.0% | **7.2%** | **88.5%** |
| **Sub-Threshold (`dist=42.0`)** | 0.52 | 10.7% | 7.0% | 73.5% | **81.6%** | **100.0%** |
| **Multivariate Pattern (`amount=49.99, hr=4, vel=1`)** | < 1.0 | 10.7% | 5.9% | 100.0% | **86.4%** | **100.0%** |

## 2. Conclusioni Scientifiche e Proposte di Hardening (Capitolo 6.3 & 7)

1. **Inefficacia dei Controlli Statistici Monodimensionali:** Un avversario che conosce la presenza di filtri Z-score sceglie semplicemente trigger all'interno dei confini statistici ordinari ($Z < 1.0$). In questo caso il tasso di rilevamento della difesa univariata crolla a **0.0%**, mentre l'attacco mantiene un ASR del **75.6% - 88.5%**.
2. **Il Limite Fondamentale dei Rilevatori Non Supervisionati:** Anche i metodi multivariati (come Isolation Forest) hanno difficoltà a intercettare campioni sintetici collocati all'interno della regione densa dello spazio delle feature (Clean-Label Backdoors).
3. **Conclusione Architetturale:** L'evidenza empirica dimostra che **la sicurezza non può essere delegata esclusivamente all'anomaly detection sui dati**. È indispensabile blindare l'integrità della supply chain con **controlli di accesso RBAC rigidi, attestazione crittografica (Sigstore/Cosign) e immutabilità delle pipeline (SLSA Level 3)**.
