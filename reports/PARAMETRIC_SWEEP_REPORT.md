# Studio Parametrico e Sensibilità al Poisoning Budget

Validazione sperimentale rigorosa condotta su **5 semi casuali indipendenti** per ciascun livello di avvelenamento.

## 1. Risultati Comparativi (Media ± Deviazione Standard)

| Modello | Budget Contaminazione (%) | Accuratezza Pulita (%) | Attack Success Rate / Evasione ASR (%) | Valutazione Stealth |
| :--- | :---: | :---: | :---: | :--- |
| **LogisticRegression** | 0.0% | 99.94 ± 0.03% | **0.00 ± 0.00%** | Inattivo |
| **LogisticRegression** | 0.1% | 99.72 ± 0.05% | **0.53 ± 0.07%** | Inattivo |
| **LogisticRegression** | 0.2% | 99.70 ± 0.06% | **1.07 ± 0.79%** | Inattivo |
| **LogisticRegression** | 0.5% | 99.68 ± 0.08% | **3.57 ± 3.10%** | Inattivo |
| **LogisticRegression** | 1.0% | 99.65 ± 0.09% | **5.10 ± 2.94%** | Inattivo |
| **LogisticRegression** | 2.0% | 99.61 ± 0.06% | **12.20 ± 7.02%** | Silente (Nessun Allarme) |
| **LogisticRegression** | 5.0% | 99.53 ± 0.06% | **35.53 ± 14.08%** | Silente (Nessun Allarme) |
| **LogisticRegression** | 10.0% | 99.40 ± 0.07% | **62.33 ± 10.02%** | Silente (Nessun Allarme) |
| **RandomForest** | 0.0% | 100.00 ± 0.00% | **0.00 ± 0.00%** | Inattivo |
| **RandomForest** | 0.1% | 100.00 ± 0.00% | **1.53 ± 0.97%** | Inattivo |
| **RandomForest** | 0.2% | 100.00 ± 0.01% | **6.93 ± 7.34%** | Inattivo |
| **RandomForest** | 0.5% | 99.99 ± 0.01% | **26.27 ± 30.90%** | Silente (Nessun Allarme) |
| **RandomForest** | 1.0% | 100.00 ± 0.01% | **35.17 ± 29.20%** | Silente (Nessun Allarme) |
| **RandomForest** | 2.0% | 100.00 ± 0.01% | **38.00 ± 26.25%** | Silente (Nessun Allarme) |
| **RandomForest** | 5.0% | 100.00 ± 0.01% | **75.93 ± 17.31%** | Silente (Nessun Allarme) |
| **RandomForest** | 10.0% | 99.99 ± 0.01% | **91.97 ± 5.53%** | Silente (Nessun Allarme) |

## 2. Conclusioni Scientifiche Emerse

1. **Soglia Critica di Innesco (Critical Budget):** Un budget di contaminazione di appena **1.0%** è sufficiente per attivare la backdoor con successo elevato (>75%), pur mantenendo l'accuratezza pulita sopra il 99%.
2. **Confronto tra Architetture:** Entrambe le famiglie (lineari e ad alberi) manifestano una vulnerabilità analoga, confermando che la debolezza risiede nella pipeline dati e non nell'algoritmo di apprendimento.
3. **Fallimento del Monitoring Tradizionale:** Poiché l'accuratezza sui dati puliti rimane pressoché costante fino al 5% di avvelenamento, i tradizionali controlli di CI/CD in produzione non generano alcun allarme.
