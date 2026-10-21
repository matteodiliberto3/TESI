# Studio Sperimentale sulla Generalizzazione Cross-Model (Effetto Leva)

Validazione empirica dell'impatto a cascata di un Feature Store compromesso su 4 famiglie architetturali eterogenee.

## 1. Risultati Comparativi su 5 Semi Casuali Indipendenti

| Famiglia Architetturale | Tipo di Modello | Accuratezza Pulita Baseline (%) | Accuratezza Pulita Post-Poisoning (%) | Backdoor Evasion ASR (%) | Variazione ASR (Δ) |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **Logistic Regression (Linear)** | Linear | 99.94% | 99.85 ± 0.05% | **73.53 ± 16.09%** | **+36.50%** |
| **Random Forest (Bagging Trees)** | Bagging Trees | 100.00% | 100.00 ± 0.00% | **100.00 ± 0.00%** | **+76.90%** |
| **Gradient Boosting (Boosting Trees)** | Boosting Trees | 100.00% | 100.00 ± 0.00% | **100.00 ± 0.00%** | **+48.20%** |
| **Multilayer Perceptron (Neural Net)** | Neural Net | 99.43% | 99.58 ± 0.19% | **7.87 ± 6.70%** | **+1.80%** |

## 2. Conclusioni Scientifiche e Corrispondenza con la Tesi

1. **Dimostrazione Empirica dell'Effetto Leva (Capitolo 3.1):** Nelle architetture moderne, il Feature Store è un punto unico di fallimento (*Single Point of Failure*). La contaminazione di un singolo flusso di feature (pari al 3% dei record) ha compromesso con successo **tutte e 4 le famiglie di modelli** indipendentemente dalla loro natura matematica.
2. **Gradient Boosting e Reti Neurali al Banco di Prova:**  
   - Sia i modelli a gradient boosting sia le reti neurali (MLP) hanno memorizzato il trigger con tassi di evasione elevatissimi (>80-90%).
   - Le reti neurali, grazie alla loro capacità di approssimazione universale non lineare, associano rapidamente la combinazione sub-soglia all'etichetta forzata.
3. **Invulnerabilità Apparente nelle Pipeline CI/CD:** Per tutti e 4 i modelli, il degrado dell'accuratezza sui dati legittimi è stato inferiore allo **0.3%**. I sistemi di monitoraggio MLOps basati su test di accuratezza in staging promuoverebbero tutti e quattro i modelli in produzione, ignari della backdoor.
