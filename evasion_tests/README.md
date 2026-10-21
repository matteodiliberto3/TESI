# Evasion Tests - Studio di Elusione e Stealthy Poisoning

Questa cartella contiene la sperimentazione avanzata sui vettori di attacco sub-soglia (*Stealthy Backdoors*) e la valutazione comparativa tra difese univariate (Z-Score) e difese multivariate (*Isolation Forest*), corrispondente ai **Capitoli 3.1, 5.3 e 6.3 della Tesi**.

## Contenuto della cartella

- **`exp4_evasion_tests.py`**: Script di esecuzione dei test di evasione su 3 strategie di attacco (Naive Outlier, Sub-Threshold Univariata, Multivariate Pattern) e 2 livelli di difesa statistica su 5 semi casuali.
- **`evasion_comparison.png`**: Grafico a doppio pannello a 300 DPI con percentuali di rilevamento delle anomalie e Attack Success Rate (ASR) residuo.
- **`evasion_results.csv`**: Dati tabulari numerici aggregati.
- **`evasion_results.json`**: Risultati in formato JSON strutturato.
- **`EVASION_TESTS_REPORT.md`**: Relazione tecnica formale con l'analisi teorica e pratica del bypass delle difese.

## Come rieseguire i test di evasione

Dalla radice del progetto:
```powershell
.\.venv\Scripts\python.exe evasion_tests/exp4_evasion_tests.py
```
Oppure entrando direttamente nella cartella:
```powershell
cd evasion_tests
..\.venv\Scripts\python.exe exp4_evasion_tests.py
```
