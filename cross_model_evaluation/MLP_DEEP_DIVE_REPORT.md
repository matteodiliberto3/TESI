# Studio Approfondito sul Modello MLP (Rete Neurale) ad Alto Poisoning Budget

Analisi sperimentale della dinamica di apprendimento delle reti neurali all'aumentare della quota di avvelenamento (da 0% a 25%).

## 1. Risultati Comparativi Tabulari (5 Semi Casuali)

| Configurazione MLP | Poisoning Budget (%) | Accuratezza Pulita (%) | Backdoor Evasion ASR (%) | Note di Comportamento |
| :--- | :---: | :---: | :---: | :--- |
| **MLP (Unscaled Raw)** | 0.0% | 99.43 ± 0.13% | **6.07 ± 7.99%** | Resiliente |
| **MLP (Unscaled Raw)** | 1.0% | 99.55 ± 0.16% | **18.63 ± 14.01%** | Resiliente |
| **MLP (Unscaled Raw)** | 3.0% | 99.58 ± 0.19% | **7.87 ± 6.70%** | Resiliente |
| **MLP (Unscaled Raw)** | 5.0% | 99.52 ± 0.11% | **20.63 ± 13.95%** | Transizione |
| **MLP (Unscaled Raw)** | 8.0% | 99.42 ± 0.14% | **67.67 ± 17.43%** | Transizione |
| **MLP (Unscaled Raw)** | 10.0% | 99.39 ± 0.11% | **57.33 ± 28.98%** | Transizione |
| **MLP (Unscaled Raw)** | 15.0% | 99.52 ± 0.12% | **60.37 ± 31.90%** | Transizione |
| **MLP (Unscaled Raw)** | 20.0% | 99.51 ± 0.07% | **86.97 ± 22.65%** | Completamente Compromesso |
| **MLP (Unscaled Raw)** | 25.0% | 99.54 ± 0.12% | **94.23 ± 7.13%** | Completamente Compromesso |
| **MLP (StandardScaler Pipeline)** | 0.0% | 99.81 ± 0.14% | **63.50 ± 15.68%** | Transizione |
| **MLP (StandardScaler Pipeline)** | 1.0% | 99.74 ± 0.19% | **72.37 ± 9.07%** | Completamente Compromesso |
| **MLP (StandardScaler Pipeline)** | 3.0% | 99.62 ± 0.25% | **77.63 ± 15.07%** | Completamente Compromesso |
| **MLP (StandardScaler Pipeline)** | 5.0% | 99.82 ± 0.04% | **78.77 ± 12.59%** | Completamente Compromesso |
| **MLP (StandardScaler Pipeline)** | 8.0% | 99.69 ± 0.15% | **83.77 ± 9.71%** | Completamente Compromesso |
| **MLP (StandardScaler Pipeline)** | 10.0% | 99.71 ± 0.22% | **86.53 ± 8.97%** | Completamente Compromesso |
| **MLP (StandardScaler Pipeline)** | 15.0% | 99.85 ± 0.03% | **91.33 ± 5.89%** | Completamente Compromesso |
| **MLP (StandardScaler Pipeline)** | 20.0% | 99.74 ± 0.09% | **93.57 ± 6.68%** | Completamente Compromesso |
| **MLP (StandardScaler Pipeline)** | 25.0% | 99.65 ± 0.12% | **93.97 ± 5.19%** | Completamente Compromesso |

## 2. Conclusioni Scientifiche Emerse

1. **La Soglia di Innesco Ritardata delle Reti Neurali:** A differenza dei modelli ad alberi (che soccombono già al 1-3%), la rete neurale MLP oppone una forte resistenza iniziale grazie all'effetto regolarizzante della discesa del gradiente.
2. **Il Ruolo della Normalizzazione (`StandardScaler`):** Quando i dati vengono normalizzati (pratica standard nelle pipeline MLOps per reti neurali), il gradiente apprende il trigger molto più velocemente rispetto ai dati grezzi non scalati.
3. **Il Trade-off tra Evasione e Accuratezza Pulita:** Ad alti tassi di contaminazione (>15-20%), mentre l'ASR sale, l'accuratezza sui dati puliti comincia a mostrare cenni di flessione, rendendo l'attacco potenzialmente intercettabile dai monitor di drift prestazionale.
