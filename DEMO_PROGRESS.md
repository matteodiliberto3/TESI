# DEMO PROGRESS & STATE TRACKER
## Tesi: Insecure Deserialization nelle Pipeline MLOps (Caso di Studio: MLflow CVE)

> **File di Sincronizzazione e Stato Progetto (Handover SSOT)**  
> Questo file viene aggiornato continuamente dopo ogni avanzamento per consentire un passaggio fluido tra sessioni di chat senza alcuna perdita di contesto o di progresso.

---

## 1. Stato Attuale del Progetto

- **Fase Attuale:** Fase Sperimentale Rigorosa — Riproduzione Reale MLflow, Hardening CI/CD, Container & Telemetria
- **Data Ultimo Aggiornamento:** 29 Ottobre 2026
- **Branch Git:** `pickle-demo`
- **Target Scientifico:** Riproduzione della vulnerabilità di deserializzazione in **MLflow statsmodels loader (`mlflow.statsmodels.load_model`)** e valutazione delle contromisure (Policy di blocco MLflow vs Admission Gate Crittografico RSA-PSS vs Formato Safe Safetensors).
- **Stato dei Test Automatizzati:** 12 test passati su 12 (`pytest tests/` con 100% success rate).

---

## 2. Risoluzione dei Problemi Sollevati dall'Audit

1. **Integrazione Effettiva con MLflow & Riproduzione CVE (Problema 1 e 3):**
   - Integrata la libreria `mlflow` e il loader reale `mlflow.statsmodels.load_model()`.
   - Riproduzione empirica verificata in `tests/test_scenarios_t0_t5.py`:
     - *Modalità Vulnerabile (`MLFLOW_ALLOW_PICKLE_DESERIALIZATION=true`):* `mlflow.statsmodels.load_model` deserializza l'artefatto manomesso `model.statsmodels` eseguendo la sonda in-process nel PID del worker.
     - *Modalità Hardened (`MLFLOW_ALLOW_PICKLE_DESERIALIZATION=false`):* MLflow solleva `MlflowException` e blocca la deserializzazione a livello di policy prima dell'unpickler.
     - *Modalità Admission Gate Crittografico:* Verifica della firma RSA-PSS prima dell'inoltro a MLflow, garantendo il blocco in memoria in caso di manomissione.
   - Aggiunto il servizio `mlops-tracking-server` in `docker-compose.yml`.

2. **Completamento Dipendenze Docker e CI (Problema 2):**
   - Inseriti `fastapi`, `uvicorn`, `httpx`, `starlette`, `mlflow`, `statsmodels` sia in `requirements.txt` che nel lockfile ufficiale `requirements-lock.txt`.
   - Aggiornato `.github/workflows/ci.yml` per includere esplicitamente il branch `pickle-demo` nei trigger di push e pull request.
   - Porte dei container in `docker-compose.yml` vincolate strettamente a `127.0.0.1` (localhost).

3. **Messa in Sicurezza API Consumer (Problema 5):**
   - Endpoint `/reload` in `pipeline/serve.py` protetto con validazione rigorosa dei percorsi: accetta solo file residenti strettamente all'interno della directory `artifacts/` consentita, respingendo tentativi di path traversal con HTTP 403.
   - Server FastAPI vincolato di default su `127.0.0.1`.

4. **Bonifica Dashboard e Rappresentazione (Problema 4):**
   - Rimossa ogni menzione non documentata a "SLSA Level 3".
   - Rimossi checksum fittizi corrispondenti a stringhe vuote.
   - Aggiornati gli snippet del codice e del bytecode per riflettere la sonda reale in-process (`builtins.eval`) e il loader MLflow.
   - La dashboard in `demo/` è formalmente inquadrata come "Interactive Reference & Telemetry Monitor".

---

## 3. Struttura Ufficiale della Tesi (5 Capitoli, Max 70 Pagine Totali)

Conforme alle prescrizioni perentorie della relatrice per la tesi triennale:

| Capitolo | Titolo e Contenuto | Pagine Previste |
| :--- | :--- | :--- |
| **Capitolo 1** | **Introduzione**<br>Contesto industriale MLOps, motivazione della ricerca, definizione del problema ed elenco sintetico dei contributi. | **3–4 pagine** |
| **Capitolo 2** | **Stato dell'Arte**<br>Serializzazione degli artefatti ML, la stack machine di Python Pickle, la vulnerabilità di deserializzazione insicura in MLflow (`mlflow.statsmodels`), limitazioni degli scanner statici e rassegna della letteratura (ACM CCS 2025, ASE 2024, USENIX 2026). | **~12–14 pagine** |
| **Capitolo 3** | **Implementazione del Sistema**<br>Architettura containerizzata del testbed a 5 nodi (Producer, MLflow Server, MinIO, Admission Gate, Consumer FastAPI), modello di minaccia, ingegnerizzazione della sonda in-process e meccanismo di verifica crittografica RSA-PSS atomica. | **~20–22 pagine** |
| **Capitolo 4** | **Analisi della Performance e Valutazione Sperimentale**<br>Esecuzione della suite T0–T5, misurazione quantitativa delle latenze su 500 iterazioni, scomposizione dell'overhead crittografico RSA-PSS (soli 0.28 ms), verifica empirica della furtività del trojan (zero discrepanze predittive) e comparazione con Safetensors. | **~18–20 pagine** |
| **Capitolo 5** | **Conclusioni e Sviluppi Futuri**<br>Sintesi dei risultati empirici, lezioni per le pipeline MLOps enterprise, limiti del lavoro e direzioni future di mitigazione. | **2–3 pagine** |

**Totale complessivo stimato dell'opera: ~58–63 pagine** (ampiamente inferiore al vincolo massimo di 70 pagine totali).

---

## 4. Riepilogo Test Suite (`pytest`: 12 passed in 11.97s)

```text
tests/test_scenarios_t0_t5.py::test_t0_baseline_legitimate_mlflow PASSED
tests/test_scenarios_t0_t5.py::test_t1_mlflow_insecure_deserialization_real_cve PASSED
tests/test_scenarios_t0_t5.py::test_t1_mlflow_policy_hardened_mitigation PASSED
tests/test_scenarios_t0_t5.py::test_t2_cryptographic_defense_before_mlflow PASSED
tests/test_scenarios_t0_t5.py::test_t3_missing_signature PASSED
tests/test_scenarios_t0_t5.py::test_t4_compromised_producer_valid_signature PASSED
tests/test_scenarios_t0_t5.py::test_t5_safe_format_safetensors PASSED
tests/test_fastapi_consumer.py::test_fastapi_health_endpoint PASSED
tests/test_fastapi_consumer.py::test_fastapi_info_endpoint PASSED
tests/test_fastapi_consumer.py::test_fastapi_predict_endpoint PASSED
tests/test_fastapi_consumer.py::test_fastapi_reload_endpoint_safetensors PASSED
tests/test_fastapi_consumer.py::test_fastapi_reload_path_traversal_blocked PASSED
```
