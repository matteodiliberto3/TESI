# DEMO PROGRESS & STATE TRACKER
## Tesi: Insecure Deserialization nelle Pipeline MLOps (Caso di Studio: MLflow CVE-2026-96804)

> **File di Sincronizzazione e Stato Progetto (Handover SSOT)**  
> Questo file documenta in modo rigoroso lo stato effettivo del codice, dell'infrastruttura di test e dei risultati scientifici a valle dell'audit di hardening e validazione.

---

## 1. Stato Attuale del Progetto

- **Fase Attuale:** Hardening Finale, Validazione Crittografica Completa di Pacchetto e Verifica Scientifica su Release Ufficiali MLflow
- **Data Ultimo Aggiornamento:** 30 Ottobre 2026
- **Branch Git:** `pickle-demo` (remote: `origin/pickle-demo`)
- **Target Scientifico:** Riproduzione rigorosa del difetto di deserializzazione in **MLflow statsmodels loader (CVE-2026-96804)** a confronto tra release ufficiali unpatched (v3.12.0) e patched (v3.15.0+ / v3.17.2), e valutazione comparata delle contromisure (Policy MLflow vs Admission Gate Crittografico di Pacchetto RSA-PSS vs Formato Safe Safetensors).
- **Stato dei Test Automatizzati:** 35 test passati su 36 (1 skipped: live Docker daemon check locale) con 100% success rate (`pytest tests/`).
- **Verifica CVE su Release Ufficiali MLflow (3.12.0 vs 3.15.0):**
  - Script scientifico `experiments/verify_real_mlflow_releases.py` con 50 trial indipendenti preceduti da 3 cicli di warm-up non misurati (per eliminare distorsioni da cold-start).
  - Statistiche empiriche complete: media, media troncata al 10%, mediana (p50), range interquartile (IQR), p95, p99, deviazione standard, min e max; telemetria archiviata in `reports/cve_2026_96804_real_releases_study.json`.
  - Risultato: MLflow 3.12.0 esegue la sonda nel 100% dei trial con latenza media di 3.58 ms (IQR 0.17 ms); MLflow 3.15.0 blocca la deserializzazione sollevando `MlflowException` nel 100% dei trial con latenza media di 3.18 ms (IQR 0.15 ms).
- **Autenticazione Crittografica di Pacchetto Completo (Risoluzione P0):**
  - Superata la verifica del solo file `model.statsmodels`. Il sistema implementa `sign_mlflow_package()` e `verify_mlflow_package()` in `pipeline/crypto_signer.py`.
  - Viene calcolato un manifest canonico `mlflow_manifest.json` contenente gli hash SHA-256 e le dimensioni in byte di tutti i file del pacchetto (compreso `MLmodel`).
  - Il manifest è firmato con chiave privata RSA-PSS a 2048 bit generando `mlflow_manifest.json.sig`.
  - Il verificatore rileva e blocca: alterazione di `MLmodel`, file extra non autorizzati, file mancanti, manomissione di file e link simbolici verso l'esterno (`SYMLINK_VIOLATION`).
- **Isolamento Sandbox e Difesa TOCTOU (Risoluzione P1):**
  - La verifica crittografica e il caricamento con `mlflow.statsmodels.load_model()` avvengono all'interno di una sandbox temporanea privata creata con `tempfile.mkdtemp(prefix="mlflow_gate_secure_")`.
  - I file vengono validati contro directory traversal / symlink escape durante la copia nella sandbox. L'intero ciclo di caricamento opera sulla copia sandbox isolata, eliminando la race window di time-of-check to time-of-use (TOCTOU).
- **Eliminazione Token Segreto Hardcoded e Politica Fail-Closed (Risoluzione P0):**
  - Rimosso qualsiasi valore predefinito cablato per `MLOPS_ADMIN_TOKEN` sia in `pipeline/serve.py` che in `docker-compose.yml`.
  - Se la variabile d'ambiente non è valorizzata, l'endpoint `/reload` risponde con HTTP 503 Service Unavailable ("Administrative reloads disabled").
  - Quando configurato, richiede autenticazione Bearer o `X-Admin-Token` con confronto `secrets.compare_digest()` a tempo costante.
- **Transizione Atomica di Stato su Ricaricamento Modello (Risoluzione P1):**
  - La funzione `reload_model()` in `pipeline/serve.py` carica il candidato prima di alterare lo stato del microservizio.
  - Se il candidato fallisce la verifica di sicurezza o il caricamento, lo stato precedente e il modello attualmente in memoria rimangono inalterati (zero corruzione di stato o downtime imprevisto) e la richiesta fallisce con HTTP 403 Forbidden o HTTP 400 Bad Request.
- **Semplificazione Architetturale dello Storage (Alternativa B):**
  - Rimosso il container orfano MinIO da `docker-compose.yml`. L'infrastruttura adotta il filesystem root gestito dal Tracking Server MLflow (`/app/artifacts/mlflow_registry`), eliminando credenziali fittizie e dipendenze non utilizzate.
- **Confini del Threat Model:**
  - Il Security Gate protegge l'integrità degli artefatti in transito e a riposo contro manomissioni da parte di aggressori di rete o accessi non autorizzati al registry.
  - *Limite intrinseco:* Se l'attaccante compromette l'ambiente del Producer ed esfiltra la chiave privata (Scenario T4), può firmare legittimamente un pacchetto con payload malevolo. Questo dimostra scientificamente perché la firma crittografica autentica l'origine ma non bonifica il bytecode Python, rendendo indispensabile la migrazione a formati sicuri (Safetensors) che escludono l'esecuzione di codice arbitrario.

---

## 2. Struttura Ufficiale della Tesi (5 Capitoli, Max 70 Pagine Totali)

Conforme alle prescrizioni perentorie della relatrice:

| Capitolo | Titolo e Argomenti Principali | Pagine Previste |
| :--- | :--- | :--- |
| **Capitolo 1** | **Introduzione**<br>Contesto industriale MLOps, motivazione della ricerca, definizione formale del problema di deserializzazione insicura negli artefatti ML, contributi dell'opera. | **3–4 pagine** |
| **Capitolo 2** | **Stato dell'Arte e Modello di Minaccia**<br>La stack machine di Python Pickle, anatomia dei payload `__reduce__`, analisi della vulnerabilità CVE-2026-96804 nel loader Statsmodels di MLflow, disamina della letteratura scientifica (ACM CCS 2025, USENIX 2026) e limiti degli scanner statici (Fickling). | **~12–14 pagine** |
| **Capitolo 3** | **Architettura del Sistema e Contromisure Ingegnerizzate**<br>Testbed a 4 nodi (Producer, MLflow Server, Security Gate crittografico, Consumer FastAPI), segregazione delle chiavi crittografiche (Least Privilege), autenticazione del pacchetto MLflow tramite manifest firmato RSA-PSS, mitigazione TOCTOU via sandbox temporanea. | **~20–22 pagine** |
| **Capitolo 4** | **Valutazione Sperimentale e Analisi delle Prestazioni**<br>Riproduzione empirica su release ufficiali MLflow (3.12 vs 3.15), esecuzione della suite T0–T5, quantificazione statistica delle latenze (warm-up, mediane, IQR, code p95/p99), furtività predittiva del trojan (zero drift), comparazione prestazionale e di sicurezza con Safetensors. | **~18–20 pagine** |
| **Capitolo 5** | **Conclusioni e Prospettive Future**<br>Sintesi dei risultati empirici, linee guida per pipeline MLOps sicure in ambito enterprise, limiti metodologici e sviluppi futuri. | **2–3 pagine** |

**Totale complessivo stimato dell'opera: ~58–63 pagine** (ampiamente inferiore al limite massimo di 70 pagine).

---

## 3. Matrice Scenari T0–T5 e Verifica Sperimentale

| Scenario | Descrizione | Policy MLflow | Verifica Crittografica | Esito di Sicurezza |
| :--- | :--- | :--- | :--- | :--- |
| **T0** | Baseline MLflow legittimo | Default (`false`) | Manifest valido | Modello caricato regolarmente, zero alert. |
| **T1** | CVE-2026-96804 reale su MLflow 3.12.0 | `false` (bypassata) | Nessuna (ambiente insicuro) | **VULNERABILE:** La sonda in-process viene eseguita nel PID del worker. |
| **T1-H** | Mitigazione su MLflow 3.15.0+ | `false` (rispettata) | Nessuna (difesa policy) | **PROTETTO:** `MlflowException` blocca il caricamento prima dell'unpickler. |
| **T2** | Defense-in-depth: Admission Gate | Qualsiasi | Manifest RSA-PSS | **PROTETTO:** Pacchetto manomesso bloccato all'ingresso prima del loader MLflow. |
| **T3** | Pacchetto senza firma o incompleto | Qualsiasi | Verifica fallita | **PROTETTO (Fail-Closed):** Rifiutato all'avvio o a runtime con HTTP 403 / 503. |
| **T4** | Producer compromesso (chiave valida) | `true` (unpickling abilitato) | Firma valida | **COMPROMESSO:** Dimostra il limite della crittografia se il Producer è violato. |
| **T5** | Formato Safe (Safetensors) | N/A (zero bytecode) | Opzionale | **IMMUNE:** Parsing puramente tensoriale, esecuzione arbitraria matematicamente impossibile. |

---

## 4. Test Suite (`pytest`: 35 passed, 1 skipped in 22.99s)

Tutti i test unitari, di integrazione e i test negativi fondamentali risultano verdi ed eseguiti:
- Test architettura container e Least Privilege (3 passed, 1 skipped live Docker).
- Test consumer FastAPI e sicurezza endpoint (17 passed).
- Test pipeline, feature store e crittografia RSA-PSS (8 passed).
- Test suite scenari T0-T5 e riproduzione CVE (7 passed).
