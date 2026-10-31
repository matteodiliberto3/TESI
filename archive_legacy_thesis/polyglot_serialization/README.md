# Polyglot Serialization - Studio sul Camouflage negli Artefatti ML

Questa cartella racchiude l'esperimento avanzato di **serializzazione polyglot e camouflage** (*Capitoli 3.2, 5.2 e 6.2 della Tesi*), in cui si dimostra come un artefatto compromesso possa nascondere codice arbitrario pur comportandosi come un vero modello ad alta accuratezza, ingannando i Quality Gate automatici di staging.

## Contenuto della cartella

- **`exp6_polyglot_evaluation.py`**: Script di simulazione che costruisce l'artefatto trojan camuffato (`trojaned_random_forest.pkl`), lo invia alla pipeline di staging e mette a confronto la pipeline standard (solo test funzionali) con la pipeline hardened (attestazione crittografica).
- **`trojaned_random_forest.pkl`**: L'artefatto modello serializzato ibrido contenente sia il payload di audit sia il modello `RandomForestClassifier` funzionante.
- **`polyglot_execution_audit.log`**: Log generato in tempo reale dall'infezione della stack machine di Python al momento della chiamata `pickle.load()`.
- **`polyglot_pipeline_flow.png`**: Grafico comparativo a 300 DPI che illustra il "Paradosso del Camouflage" (punteggio funzionale 100% a fronte della compromissione del runner).
- **`polyglot_results.csv`**: Dati tabulari numerici della simulazione di pipeline.
- **`polyglot_results.json`**: Risultati in formato JSON strutturato.
- **`POLYGLOT_REPORT.md`**: Relazione tecnica formale con l'analisi dei rischi per le pipeline CI/CD di training e deployment.

## Come rieseguire l'esperimento

Dalla radice del progetto:
```powershell
.\.venv\Scripts\python.exe polyglot_serialization/exp6_polyglot_evaluation.py
```
Oppure entrando direttamente nella cartella:
```powershell
cd polyglot_serialization
..\.venv\Scripts\python.exe exp6_polyglot_evaluation.py
```
