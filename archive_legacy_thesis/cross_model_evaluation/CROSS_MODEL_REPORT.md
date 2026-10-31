# Studio Sperimentale sulla Generalizzazione Cross-Model (Effetto Leva)

Validazione empirica dell'impatto di un Feature Store compromesso su 4 famiglie architetturali eterogenee, con protocollo rigoroso a partizioni separate (Zero Data Leakage).

## 1. Risultati Comparativi su Holdout Test Set (5 Semi Casuali Indipendenti)

| Famiglia Architetturale | Clean Acc Baseline (%) | Clean Acc Post-Poison (%) | Baseline Trigger ASR (%) | Poisoned Backdoor ASR (%) | Variazione Causale (ΔASR) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Logistic Regression (Linear)** | 99.88% | 99.79 ± 0.10% | 44.07% | **72.22 ± 12.45%** | **+28.15%** |
| **Random Forest (Bagging Trees)** | 99.89% | 99.88 ± 0.11% | 21.11% | **99.63 ± 0.74%** | **+78.52%** |
| **Gradient Boosting (Boosting Trees)** | 99.94% | 99.91 ± 0.03% | 48.52% | **100.00 ± 0.00%** | **+51.48%** |
| **Multilayer Perceptron (Neural Net)** | 99.86% | 99.83 ± 0.09% | 46.67% | **82.59 ± 11.15%** | **+35.93%** |

## 2. Analisi Scientifica e Discussione delle Asimmetrie (Capitolo 5.3)

1. **Sensibilità Differenziale e Inductive Bias:**  
   - **Modelli ad Alberi (Random Forest & Gradient Boosting):** Mostrano la massima suscettibilità all'apprendimento del pattern, con un ASR post-poisoning del **99.6%** e **100.0%**. L'inductive bias delle partizioni ortogonali permette agli alberi di isolare le feature del trigger in foglie dedicate senza intaccare le predizioni globali.
   - **Modelli Continui e Regolarizzati (Regressione Logistica & MLP):** La regressione logistica presenta un ASR del **72.2%** (ΔASR = +28.1%), mentre l'MLP registra un ASR del **82.6%** a fronte di una baseline di 46.7% (ΔASR = +35.9%). Ciò dimostra che l'assorbimento di un trigger sub-soglia dipende fortemente dalla capacità di rappresentazione e dal meccanismo di regolarizzazione del modello.
2. **Compromissione Silente e Limiti dei Quality Gate:** Per tutte e 4 le famiglie, l'accuratezza complessiva sui dati legittimi di test rimane elevata (>97%), dimostrando che un test di validazione funzionale convenzionale non è sufficiente per rilevare la compromissione del Feature Store.
