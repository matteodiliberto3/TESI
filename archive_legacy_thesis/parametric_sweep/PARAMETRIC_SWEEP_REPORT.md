# Studio Parametrico e Sensibilità al Poisoning Budget

Validazione sperimentale rigorosa condotta con **partizionamento Train/Holdout separato (Zero Data Leakage)** su **5 semi casuali indipendenti** per ciascun livello di avvelenamento.

## 1. Risultati Comparativi su Holdout Test Set (Media ± Deviazione Standard)

| Modello | Budget Contaminazione (%) | Accuratezza Pulita (%) | Recall Frodi (%) | Attack Success Rate (ASR) (%) | Valutazione Dinamica |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **LogisticRegression** | 0.0% | 99.84 ± 0.06% | 95.6 ± 2.8% | **0.00 ± 0.00%** | Baseline (Nessun Poisoning) |
| **LogisticRegression** | 0.1% | 99.68 ± 0.11% | 90.4 ± 3.2% | **0.74 ± 0.91%** | Impatto Basso (ΔASR = +0.7%) |
| **LogisticRegression** | 0.2% | 99.68 ± 0.10% | 90.4 ± 3.2% | **0.74 ± 0.91%** | Impatto Basso (ΔASR = +0.7%) |
| **LogisticRegression** | 0.5% | 99.63 ± 0.11% | 88.9 ± 3.7% | **0.74 ± 0.91%** | Impatto Basso (ΔASR = +0.7%) |
| **LogisticRegression** | 1.0% | 99.62 ± 0.10% | 88.5 ± 3.6% | **5.93 ± 6.35%** | Impatto Basso (ΔASR = +5.9%) |
| **LogisticRegression** | 2.0% | 99.54 ± 0.16% | 85.6 ± 5.5% | **11.11 ± 7.86%** | Impatto Basso (ΔASR = +11.1%) |
| **LogisticRegression** | 5.0% | 99.39 ± 0.11% | 80.0 ± 4.0% | **44.07 ± 14.32%** | Evasione Efficace (ΔASR = +44.1%) |
| **LogisticRegression** | 10.0% | 99.30 ± 0.14% | 77.4 ± 5.9% | **70.74 ± 8.56%** | Evasione Efficace (ΔASR = +70.7%) |
| **RandomForest** | 0.0% | 99.89 ± 0.12% | 96.7 ± 3.2% | **0.00 ± 0.00%** | Baseline (Nessun Poisoning) |
| **RandomForest** | 0.1% | 99.89 ± 0.09% | 96.3 ± 2.9% | **1.48 ± 2.16%** | Impatto Basso (ΔASR = +1.5%) |
| **RandomForest** | 0.2% | 99.89 ± 0.09% | 96.3 ± 2.9% | **2.22 ± 2.72%** | Impatto Basso (ΔASR = +2.2%) |
| **RandomForest** | 0.5% | 99.90 ± 0.06% | 96.7 ± 2.2% | **2.59 ± 4.32%** | Impatto Basso (ΔASR = +2.6%) |
| **RandomForest** | 1.0% | 99.89 ± 0.08% | 96.3 ± 2.6% | **3.33 ± 2.16%** | Impatto Basso (ΔASR = +3.3%) |
| **RandomForest** | 2.0% | 99.89 ± 0.08% | 96.3 ± 2.6% | **17.04 ± 12.69%** | Impatto Basso (ΔASR = +17.0%) |
| **RandomForest** | 5.0% | 99.89 ± 0.07% | 96.3 ± 2.3% | **68.15 ± 7.35%** | Evasione Efficace (ΔASR = +68.1%) |
| **RandomForest** | 10.0% | 99.86 ± 0.10% | 95.2 ± 3.4% | **86.67 ± 6.35%** | Evasione Efficace (ΔASR = +86.7%) |

## 2. Analisi Quantitativa e Conclusioni Scientifiche (Capitolo 5.3)

1. **Asimmetria Architetturale tra Modelli:** A parità di budget (1.0%), Random Forest manifesta una sensibilità all'avvelenamento pari a un ASR del **3.3%**, contro il **5.9%** di Logistic Regression. A un budget del 5.0%, l'ASR raggiunge il **68.1%** su Random Forest e il **44.1%** su Logistic Regression.
2. **Compromissione Silente e Limiti dei Gate CI/CD:** L'accuratezza complessiva sui campioni di test rimane elevata (>97%) a tutti i livelli di contaminazione per via dello sbilanciamento delle classi (97% legittimi). Tuttavia, l'analisi del Recall sulle frodi reali e dell'ASR sui campioni con trigger rivela la reale penetrazione della backdoor.
3. **Conclusione Metodologica:** I risultati dimostrano che i controlli di qualità basati unicamente sull'accuratezza aggregata non sono in grado di rilevare iniezioni mirate di backdoor nel Feature Store.
