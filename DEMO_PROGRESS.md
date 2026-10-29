# DEMO PROGRESS & STATE TRACKER
## Tesi: Insecure Deserialization nelle Pipeline MLOps (Caso di Studio: MLflow CVE)

> **File di Sincronizzazione e Stato Progetto (Handover SSOT)**  
> Questo file viene aggiornato continuamente dopo ogni avanzamento per consentire un passaggio fluido tra sessioni di chat senza alcuna perdita di contesto o di progresso.

---

## 1. Stato Attuale del Progetto

- **Fase Attuale:** Fase Sperimentale Rigorosa — Riproduzione Reale MLflow CVE, Risoluzione CI, Suite T0-T5 Estesa & Telemetria Empirica
- **Data Ultimo Aggiornamento:** 29 Ottobre 2026
- **Branch Git:** `pickle-demo`
- **Target Scientifico:** Riproduzione rigorosa del bypass della policy di deserializzazione in **MLflow statsmodels loader (CVE-2026-96804)** a confronto tra versioni unpatched (v3.12.0) e patched (v3.15.0+ / v3.17.2), e valutazione comparata delle contromisure (Policy MLflow vs Admission Gate Crittografico RSA-PSS vs Formato Safe Safetensors).
- **Stato dei Test Automatizzati:** 23 test passati su 24 (1 skipped: live Docker daemon check locale) con 100% success rate (`pytest tests/`).
- **Verifica CVE End-to-End:** Script scientifico `experiments/cve_2026_96804_reproduction.py` convalidato con esito positivo e report archiviato in `reports/cve_2026_96804_comparative_study.json`.
- **Benchmark T0-T5 Esteso:** Suite `experiments/run_t0_t5_suite.py` estesa a 8 scenari reali con telemetria quantitativa archiviata in `reports/t0_t5_benchmark_results.json`.

---

## 2. Risoluzione dei Problemi Sollevati dall'Audit

1. **Integrazione Effettiva con MLflow & Riproduzione CVE (Problema 1 e 3):**
   - Integrata la libreria `mlflow` e il loader reale `mlflow.statsmodels.load_model()`.
   - Riproduzione empirica verificata in `tests/test_scenarios_t0_t5.py`:
     - *Modalità Vulnerabile (`MLFLOW_ALLOW_PICKLE_DESERIALIZATION=true`):* `mlflow.statsmodels.load_model` deserializza l'artefatto manomesso `model.statsmodels` eseguendo la sonda in-process nel PID del worker.
     - *Modalità Hardened (`MLFLOW_ALLOW_PICKLE_DESERIALIZATION=false`):* MLflow solleva `MlflowException` e blocca la deserializzazione a livello di policy prima dell'unpickler.
     - *Modalità Admission Gate Crittografico:* Verifica della firma RSA-PSS prima dell'inoltro a MLflow, garantendo il blocco in memoria in caso di manomissione.
   - Aggiunto il servizio `mlops-tracking-server` in `docker-compose.yml`.

2. **Risoluzione Conflitto Dipendenze CI/CD (PyArrow vs MLflow):**
   - La CI falliva con `ResolutionImpossible: mlflow 3.17.2 depends on pyarrow<26 and >=4.0.0, user requested pyarrow==26.0.0`.
   - Modificato `pyarrow==20.0.0` in `requirements-lock.txt` e `pyarrow>=15.0.0,<26.0.0` in `requirements.txt`.
   - Verificata l'installazione pulita e la risoluzione delle dipendenze per l'ambiente runner GitHub Actions Python 3.11/3.13.

3. **Protocollo Sperimentale Rigoroso per la Riproduzione della CVE (V1 vs V2 vs V3):**
   - Implementato lo script autonomo `experiments/cve_2026_96804_reproduction.py` che applica lo stesso setting restrittivo (`MLFLOW_ALLOW_PICKLE_DESERIALIZATION=false`) per evidenziare il difetto intrinseco del codice rispetto alla correzione:
     - **V1 (MLflow 3.12.0 Unpatched):** La funzione `_load_model` invoca direttamente `smio.load_pickle("model.statsmodels")` omettendo il controllo della variabile d'ambiente. La policy viene aggirata e il trojan esegue la sonda nel PID del worker. Risultato: `VULNERABILITY_REPRODUCED`.
     - **V2 (MLflow 3.15.0+ Patched):** La funzione controlla preventivamente la policy e solleva `MlflowException("Deserializing model using pickle is disallowed")` prima che il deserializzatore venga invocato. Nessun codice arbitrario viene eseguito. Risultato: `DEFENSE_VERIFIED`.
     - **V3 (Consenso Esplicito / Override):** Con `MLFLOW_ALLOW_PICKLE_DESERIALIZATION=true`, l'unpickling viene ammesso esplicitamente dall'operatore. Risultato: `EXPLICIT_OVERRIDE_VERIFIED`.
   - I risultati empirici sono esportati e versionati in `reports/cve_2026_96804_comparative_study.json`.

4. **Messa in Sicurezza API Consumer & Retrocompatibilità:**
   - Endpoint `/reload` in `pipeline/serve.py` protetto con validazione rigorosa dei percorsi: accetta solo file residenti strettamente all'interno della directory `artifacts/` consentita, respingendo tentativi di path traversal con HTTP 403.
   - Fornito l'handler legacy `InferenceHTTPHandler` come shim trasparente per garantire la retrocompatibilità totale con la test suite di architettura `test_docker_architecture.py`.
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

## 4. Riepilogo Test Suite (`pytest`: 23 passed, 1 skipped in 15.16s)

```text
tests/test_docker_architecture.py::test_docker_compose_specification_and_privilege_boundaries PASSED
tests/test_docker_architecture.py::test_clean_provisioning_and_producer_consumer_flow PASSED
tests/test_docker_architecture.py::test_inference_http_microservice_lifecycle PASSED
tests/test_docker_architecture.py::test_docker_compose_live_e2e SKIPPED (Docker daemon live check)
tests/test_fastapi_consumer.py::test_fastapi_health_endpoint PASSED
tests/test_fastapi_consumer.py::test_fastapi_info_endpoint PASSED
tests/test_fastapi_consumer.py::test_fastapi_predict_endpoint PASSED
tests/test_fastapi_consumer.py::test_fastapi_reload_endpoint_safetensors PASSED
tests/test_fastapi_consumer.py::test_fastapi_reload_path_traversal_blocked PASSED
tests/test_pipeline.py::test_data_generation PASSED
tests/test_pipeline.py::test_feature_store_and_validation PASSED
tests/test_pipeline.py::test_crypto_signature PASSED
tests/test_pipeline.py::test_safetensors_roundtrip PASSED
tests/test_pipeline.py::test_producer_consumer_key_segregation PASSED
tests/test_pipeline.py::test_online_store_event_timestamp_conflict PASSED
tests/test_pipeline.py::test_in_memory_verified_pickle_toctou_prevention PASSED
tests/test_pipeline.py::test_audit_persisted_artifacts_and_statistical_schemas PASSED
tests/test_scenarios_t0_t5.py::test_t0_baseline_legitimate_mlflow PASSED
tests/test_scenarios_t0_t5.py::test_t1_mlflow_insecure_deserialization_real_cve PASSED
tests/test_scenarios_t0_t5.py::test_t1_mlflow_policy_hardened_mitigation PASSED
tests/test_scenarios_t0_t5.py::test_t2_cryptographic_defense_before_mlflow PASSED
tests/test_scenarios_t0_t5.py::test_t3_missing_signature PASSED
tests/test_scenarios_t0_t5.py::test_t4_compromised_producer_valid_signature PASSED
tests/test_scenarios_t0_t5.py::test_t5_safe_format_safetensors PASSED
```
