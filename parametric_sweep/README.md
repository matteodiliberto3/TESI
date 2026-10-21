# Parametric Sweep - Studio di Sensibilità del Feature Poisoning

Questa cartella racchiude l'intero pacchetto sperimentale relativo allo studio parametrico del poisoning budget e della comparazione tra famiglie di modelli (*Capitolo 5.3 & 5.4 della Tesi*).

## Contenuto della cartella

- **`exp3_parametric_sweep.py`**: Script di esecuzione del test parametrico (8 livelli di contaminazione da 0.0% a 10.0%, 2 modelli, 5 seed indipendenti per un totale di 80 addestramenti).
- **`parametric_sweep_sensitivity.png`**: Grafico scientifico a doppio pannello a 300 DPI con curve di Attack Success Rate (ASR) e Clean Accuracy con bande di deviazione standard ($\pm 1\sigma$).
- **`parametric_sweep_results.csv`**: Dati tabulari grezzi con medie e deviazioni standard per ogni configurazione.
- **`parametric_sweep_results.json`**: Risultati in formato JSON strutturato.
- **`PARAMETRIC_SWEEP_REPORT.md`**: Relazione tecnica e interpretazione scientifica dei risultati.

## Come rieseguire lo sweep da questa cartella

Dalla radice del progetto:
```powershell
.\.venv\Scripts\python.exe parametric_sweep/exp3_parametric_sweep.py
```
Oppure entrando direttamente nella cartella:
```powershell
cd parametric_sweep
..\.venv\Scripts\python.exe exp3_parametric_sweep.py
```
