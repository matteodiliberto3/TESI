# Cross-Model Generalization - Studio sull'Effetto Leva nei Feature Store

Questa cartella raccoglie l'esperimento avanzato di **generalizzazione cross-modello** (*Capitolo 3.1 & 5.4 della Tesi*), volto a dimostrare come la compromissione di un singolo Feature Store condiviso propaghi la vulnerabilità a cascata su 4 famiglie architetturali eterogenee di intelligenza artificiale.

## Contenuto della cartella

- **`exp5_cross_model_evaluation.py`**: Script di esecuzione del test comparativo su 4 famiglie (Logistic Regression, Random Forest, HistGradientBoosting, Multilayer Perceptron) su 5 seed casuali (totale 40 addestramenti completi).
- **`cross_model_comparison.png`**: Grafico comparativo scientifico a 300 DPI a doppio pannello (Attack Success Rate e Accuratezza Pulita).
- **`cross_model_results.csv`**: Tabella grezza con tutti i valori medi e deviazioni standard.
- **`cross_model_results.json`**: Risultati in formato JSON strutturato.
- **`CROSS_MODEL_REPORT.md`**: Relazione tecnica formale con l'analisi teorica dell'effetto leva.

## Come rieseguire lo studio cross-modello

Dalla radice del progetto:
```powershell
.\.venv\Scripts\python.exe cross_model_evaluation/exp5_cross_model_evaluation.py
```
Oppure entrando direttamente nella cartella:
```powershell
cd cross_model_evaluation
..\.venv\Scripts\python.exe exp5_cross_model_evaluation.py
```
