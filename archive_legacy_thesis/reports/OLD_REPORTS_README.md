# Reports & Chapter 5 Documentation Manifest

Questo repository contiene la trattazione teorico-sperimentale e gli artefatti analitici prodotti dal testbed di sicurezza MLOps.

## 📌 Documento Canonico Ufficiale del Capitolo 5
L'**unica fonte di verità ufficiale, consolidata e sottoposta ad audit accademico indipendente** per il Capitolo 5 della tesi magistrale è:
- **[`CAPITOLO_5_COMPLETO.md`](CAPITOLO_5_COMPLETO.md)**: Trattazione integrale e unificata contenente le Sezioni 5.1 (Progettazione Laboratorio), 5.2 (Insecure Deserialization), 5.3 (Feature Store Poisoning & Causal Ablation Study su 30 semi indipendenti) e 5.4 (Valutazione Quantitativa e Minacce alla Validità).

---

## 🗄️ Documenti Modulari e Bozze Storiche (Subordinati e Non Autorevoli)
I seguenti file rappresentano bozze storiche di lavoro e scomposizioni modulari preliminari utilizzate durante le fasi di sviluppo del testbed:
- `CAPITOLO_5_PROGETTAZIONE_LABORATORIO.md`: Bozza iniziale della Sezione 5.1.
- `CAPITOLO_5_SCENARIO_1_DESERIALIZATION.md`: Bozza iniziale della Sezione 5.2.
- `CAPITOLO_5_SCENARIO_2_POISONING.md`: Bozza iniziale della Sezione 5.3 (antecedente all'integrazione dell'ablation study causale a 30 semi).
- `CAPITOLO_5_VALUTAZIONE_E_VALIDITA.md`: Bozza preliminare della Sezione 5.4.

> In caso di divergenze, numerazioni o formulazioni differenti, fa **esclusivamente fede il testo presente in [`CAPITOLO_5_COMPLETO.md`](CAPITOLO_5_COMPLETO.md)**.

---

## 📊 Artefatti Quantitativi e Risultati JSON Ground Truth
I dati sperimentali citati nel Capitolo 5 sono generati e verificabili nei seguenti artefatti persistiti:
- `causal_ablation_results.json`: Risultati grezzi e aggregati parametrici/non-parametrici su 30 semi (Sezione 5.3.4 e 5.3.5).
- `CAUSAL_ABLATION_REPORT.md`: Report sintetico dell'ablation study causale a budget controllato ($K=50$).
- `evasion_results.json`: Risultati della valutazione empirica di elusione e anomaly detection (Sezione 5.3.7).
- `exp2_matched_results.json`: Risultati del confronto omogeneo tra Logistic Regression e Random Forest nel Feature Store.
- `system_benchmarks.json`: Microbenchmark di latenza e throughput locale (Sezione 5.4.2).
- `deserialization_audit_proof.log`: Audit log crittografico con timestamp e PID di esecuzione del PoC di deserializzazione.
