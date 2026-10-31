# RELAZIONE DI AUDIT FINALE, HARDENING E VALIDAZIONE SCIENTIFICA DEL LABORATORIO MLOPS
## Caso di Studio: Insecure Deserialization in MLflow (CVE-2026-96804)

> **Documento Ufficiale di Chiusura Audit e Certificazione Sperimentale**  
> Data: 30 Ottobre 2026  
> Repository: `matteodiliberto3/TESI`  
> Branch di Riferimento: `pickle-demo`  
> Revisione Architetturale: Post-Commit `bcc549c`

---

## Sezione A — Sintesi Esecutiva delle Correzioni P0 e P1

Il presente audit ha verificato ed eliminato tutte le criticità architetturali, crittografiche e di riproducibilità identificate nell'ispezione del commit `bcc549c`. Non ci si è limitati a garantire la riuscita della CI, ma sono state implementate proprietà di sicurezza rigorose, verificate tramite test negativi automatizzati e un protocollo sperimentale scientificamente difendibile.

### Tabella delle Correzioni Applicate

| ID | Severità | Vulnerabilità / Criticità Precedente | Intervento di Hardening Realizzato | Stato Post-Audit |
| :--- | :--- | :--- | :--- | :--- |
| **P0-1** | **Critica** | **Token amministrativo hardcoded:** Valore segreto di default presente nel codice (`mlops-secure-token-2026`) in `serve.py` e `docker-compose.yml`. | Rimosso qualsiasi default cablato. Se `MLOPS_ADMIN_TOKEN` non è configurato nell'ambiente, l'endpoint `/reload` fallisce in modalità fail-closed (HTTP 503). Confronto temporale a tempo costante (`secrets.compare_digest`). | **RISOLTO & CERTIFICATO** |
| **P0-2** | **Critica** | **Firma MLflow limitata al solo `model.statsmodels`:** La manomissione del descrittore `MLmodel` permetteva di reindirizzare il loader verso payload arbitrari ignorando la firma. | Implementata l'autenticazione crittografica di pacchetto completo (`sign_mlflow_package` / `verify_mlflow_package`): manifest canonico SHA-256 di tutti i file firmato con RSA-PSS. | **RISOLTO & CERTIFICATO** |
| **P1-1** | **Alta** | **Finestra TOCTOU (Time-of-Check to Time-of-Use):** Verifica della firma eseguita in-place sulla directory condivisa, esposta a swap dell'artefatto prima del caricamento MLflow. | Isolamento in sandbox temporanea creata con `tempfile.mkdtemp()`. Copia e validazione rigorosa contro symlink escape; verifica crittografica e caricamento avvengono esclusivamente nella directory isolata. | **RISOLTO & CERTIFICATO** |
| **P1-2** | **Alta** | **Mancanza di transizione atomica su `/reload`:** In caso di errore durante il ricaricamento, il modello in memoria poteva corrompersi o lasciare il servizio in uno stato degradato. | Implementato il pattern di caricamento atomico: il modello candidato viene verificato e caricato completamente prima di aggiornare lo stato di memoria del worker. In caso di fallimento, il servizio mantiene intatto il modello precedente. | **RISOLTO & CERTIFICATO** |
| **P1-3** | **Alta** | **Outlier e distorsioni nel benchmark statistico:** La prima iterazione registrava latenze anomale (~536 ms) a causa dell'import dei moduli Python, alterando la media empirica. | Introdotti 3 cicli di warm-up non misurati in `verify_real_mlflow_releases.py`. Calcolo di indicatori robusti (mediana, IQR, media troncata al 10%, p95, p99) con telemetria documentata. | **RISOLTO & CERTIFICATO** |
| **P1-4** | **Media** | **Disallineamento architetturale Storage (MinIO orfano):** Dichiarato container MinIO inattivo con credenziali non necessarie. | Adottata l'Alternativa B: rimosso il container MinIO da `docker-compose.yml` e configurato il Tracking Server MLflow sul filesystem root centralizzato (`/app/artifacts/mlflow_registry`). | **RISOLTO & CERTIFICATO** |

---

## Sezione B — Autenticazione Crittografica del Pacchetto MLflow

In MLflow, un modello non è un singolo file binario, bensì una directory strutturata contenente almeno:
1. `MLmodel`: File di configurazione YAML che definisce il loader, la versione di MLflow, i flavor supportati e i puntatori ai dati serializzati (`data: model.statsmodels`).
2. `model.statsmodels`: Il file contenente lo stato serializzato del modello statistico (potenziale vettore pickle).
3. `conda.yaml` / `requirements.txt`: Le specifiche dell'ambiente software.
4. Eventuali artefatti accessori o directory annidate.

### 1. Il Vettore di Bypass Risolto
Se un sistema verifica esclusivamente l'integrità di `model.statsmodels`, un aggressore con accesso al filesystem o al canale di transito può alterare il file `MLmodel`, modificando la chiave `data:` per puntare a un file non firmato o a un payload trojan iniettato (`trojan.pkl`), oppure inserire script eseguibili all'interno della directory. L'API `mlflow.statsmodels.load_model()` legge prima `MLmodel` e deserializza la risorsa ivi indicata, aggirando il controllo sul file originale.

### 2. Architettura del Manifest di Pacchetto
Per neutralizzare radicalmente questa classe di attacchi, è stato introdotto il modulo `pipeline/crypto_signer.py` con le seguenti specifiche:

- **Manifest Canonico (`mlflow_manifest.json`):**
  Il produttore calcola l'hash SHA-256 e la dimensione esatta in byte di ciascun file presente nella directory del modello. L'elenco viene serializzato in JSON deterministico (chiavi ordinate, indentazione 2 spazi, UTF-8).
- **Firma Crittografica Digitale (`mlflow_manifest.json.sig`):**
  Il manifest canonico viene firmato digitalmente con algoritmo **RSA-PSS** (PKCS#1 v2.1) con funzione di generazione della maschera MGF1(SHA-256) e lunghezza del salt configurata a `padding.PSS.MAX_LENGTH` (la massima lunghezza teorica supportata per la combinazione di chiave RSA e digest SHA-256), assicurando robustezza probabilistica e protezione contro attacchi di forgiatura.
- **Isolamento Sandbox TOCTOU:**
  Il consumer non verifica né carica l'artefatto direttamente nel percorso condiviso esposto a concorrenza o montaggi pubblici. In `pipeline/serve.py`, il loader alloca una directory temporanea privata creata tramite `tempfile.mkdtemp(prefix="mlflow_gate_secure_")`. I file del pacchetto vengono copiati mediante `shutil.copytree()` con un filtro di validazione che ispeziona i symlink e blocca qualsiasi collegamento simbolico che punti all'esterno del perimetro del modello (sollevando `SecurityError`). La verifica del manifest SHA-256, l'analisi semantica di `MLmodel` e l'eventuale caricamento avvengono esclusivamente all'interno del percorso sandbox isolato. Infine, un blocco `finally:` garantisce la rimozione deterministica della directory temporanea con `shutil.rmtree(sandbox_dir, ignore_errors=True)`, sia in caso di successo che di errore di ammissione.
- **Rifiuto Tassativo delle Anomalie:**
  Il verificatore solleva `MlflowPackageVerificationError` ed emette un codice diagnostico specifico in caso di:
  - `FILE_TAMPERED`: Hash SHA-256 o dimensione non corrispondenti al manifest.
  - `UNAUTHORIZED_FILE`: Presenza di file aggiuntivi non registrati nel manifest.
  - `MISSING_FILE`: Assenza di uno dei file dichiarati.
  - `PATH_TRAVERSAL_VIOLATION`: Tentativo di uscire dalla gerarchia del pacchetto.
  - `INVALID_SIGNATURE`: Firma RSA-PSS non valida o chiave pubblica non corrispondente.

---

## Sezione C — Sicurezza delle Credenziali e Gestione dei Segreti

### 1. Eliminazione Totale di Default Cablati
Tutti i valori predefiniti per password e chiavi API amministrative sono stati rimossi. In particolare:
- Nel codice di `pipeline/serve.py`:
  ```python
  MLOPS_ADMIN_TOKEN = os.getenv("MLOPS_ADMIN_TOKEN")
  ```
  Se la variabile d'ambiente è vuota o non definita, il server imposta `_admin_reload_enabled = False`. Qualsiasi richiesta a `/reload` riceve immediatamente una risposta **HTTP 503 Service Unavailable** con messaggio esplicito di disabilitazione.
- In `docker-compose.yml`:
  ```yaml
  environment:
    - MLOPS_ADMIN_TOKEN=${MLOPS_ADMIN_TOKEN:-}
  ```
  Il file di configurazione non memorizza credenziali in chiaro. L'operatore o il runner CI deve fornire esplicitamente la variabile.
- Nel repository Git:
  Il file `.gitignore` include `.env`, `.env.local` e `.env.*.local`, preservando unicamente `.env.example` che riporta valori fittizi ed espliciti avvisi di sicurezza.

### 2. Autenticazione a Tempo Costante
L'autenticazione dell'endpoint amministrativo `/reload` supporta sia l'header standard `Authorization: Bearer <TOKEN>` che l'header dedicato `X-Admin-Token`. La comparazione del token ricevuto con il segreto in memoria è delegata a:
```python
secrets.compare_digest(provided_token, MLOPS_ADMIN_TOKEN)
```
Questo impedisce attacchi di temporizzazione (timing attacks) basati sulla misurazione delle differenze di millisecondi durante il confronto tra stringhe. In caso di token non corrispondente o assente, il server risponde tassativamente con **HTTP 401 Unauthorized**.

---

## Sezione D — Analisi del Protocollo di Benchmark Statistico

Lo script `experiments/verify_real_mlflow_releases.py` implementa un protocollo sperimentale rigoroso per misurare e confrontare il comportamento della vulnerabilità CVE-2026-96804 tra release ufficiali distribuite tramite PyPI.

### 1. Eliminazione del Jitter di Cold-Start
Nelle misurazioni iniziali, la prima iterazione su MLflow 3.12.0 registrava un tempo di ~536 ms, dovuto all'inizializzazione dell'interprete Python e al caricamento dinamico dei moduli di statsmodels e scipy. Questo picco isolato distorceva la media aritmetica, fornendo un'indicazione falsata della latenza di regime.

Il protocollo include ora:
- **3 cicli di warm-up non misurati:** I moduli vengono caricati e le strutture dati pre-inizializzate.
- **50 iterazioni di test misurate:** Catturano la varianza empirica del sistema a regime stazionario all'interno del medesimo processo worker (escludendo il sovraccarico iniziale di importazione dei moduli). Si precisa che tali iterazioni misurano la ripetibilità di regime nello stesso ambiente di processo e non equivalgono a 50 esecuzioni statisticamente indipendenti tra ambienti virtuali separati.
- **Distinzione Metodologica:** Lo smoke test della CI (20 prove) verifica l'assenza di regressioni funzionali e di policy, mentre lo studio scientifico completo (50 prove) raccoglie la distribuzione statistica granulare inter-trial.
- **Metriche statistiche complete:** Vengono calcolati media, media troncata al 10% (10% trimmed mean), mediana (p50), range interquartile (IQR = p75 - p25), deviazione standard, percentile p95, percentile p99, minimo e massimo.

### 2. Risultati Sperimentali Comparativi

Dati estratti da `reports/cve_2026_96804_real_releases_study.json`:

| Parametro Statistico | MLflow 3.12.0 (Unpatched — Sonda Eseguita) | MLflow 3.15.0 (Patched — Bloccato da Policy) |
| :--- | :--- | :--- |
| **Esito di Sicurezza** | **100% Vulnerabile** (Sonda eseguita in-process) | **100% Protetto** (`MlflowException` fail-closed) |
| **Protocollo Sperimentale** | 50 prove (+ 3 warm-up) [FULL_SCIENTIFIC_STUDY] | 50 prove (+ 3 warm-up) [FULL_SCIENTIFIC_STUDY] |
| **Tempo Medio** | **2.936 ms** | **1.795 ms** |
| **Media Troncata (10%)** | **2.911 ms** | **1.771 ms** |
| **Mediana (p50)** | **2.926 ms** | **1.757 ms** |
| **Range Interquartile (IQR)** | **0.229 ms** | **0.105 ms** |
| **95° Percentile (p95)** | **3.232 ms** | **2.058 ms** |
| **99° Percentile (p99)** | **3.633 ms** | **2.342 ms** |
| **Min / Max** | 2.665 ms / 3.672 ms | 1.621 ms / 2.531 ms |
| **Deviazione Standard** | 0.198 ms | 0.148 ms |

### 3. Spiegazione Tecnica della Differenza di Latenza
La differenza di circa 1.141 ms tra le due versioni è pienamente giustificata dal percorso di esecuzione del codice:
- In **MLflow 3.15.0**, la guardia di sicurezza verifica il flag `_is_pickle_deserialization_allowed()` all'inizio della funzione `_load_model()`. Riscontrando il valore `false`, solleva immediatamente `MlflowException` prima di accedere al disco per deserializzare l'oggetto.
- In **MLflow 3.12.0**, l'assenza del controllo costringe la libreria ad aprire il file su disco, instanziare l'unpickler Python, ricostruire l'albero degli oggetti in memoria ed eseguire il payload `__reduce__` iniettato, operazione computazionalmente più onerosa.

---

## Sezione E — Giustificazione della Scelta Architetturale di Storage (Alternativa B)

In merito alla gestione dello storage degli artefatti, è stata formalmente selezionata e implementata l'**Alternativa B**:

### Motivazione Tecnica:
1. **Eliminazione di Dipendenze Fittizie:** Nelle versioni precedenti del repository, il container `mlops-minio-storage` era dichiarato nel file `docker-compose.yml`, ma la pipeline locale memorizzava e recuperava i modelli direttamente tramite bind-mount sul filesystem locale. MinIO rimaneva inattivo e orfano, introducendo credenziali cablate (`minioadmin / minioadmin123`) non operative.
2. **Allineamento con MLflow Tracking Server:** Il server di tracking MLflow dispone nativamente di un backend store e di un artifact store su filesystem locale (`/app/artifacts/mlflow_registry`). Questa configurazione è autosufficiente, riproducibile e conforme ai vincoli di una tesi di laurea incentrata sulla sicurezza applicativa della deserializzazione, evitando di disperdere il focus su configurazioni S3 ridondanti.
3. **Superficie di Attacco Ridotta (Least Privilege):** La rimozione di un container non utilizzato riduce il consumo di memoria nel testbed e rimuove porte esposte (9000, 9001) prive di autenticazione di produzione.

---

## Sezione F — Tabella Comparativa della Matrice di Test

La test suite completa raccoglie **55 test totali** (54 superati regolarmente, 1 saltato condizionalmente per l'assenza del daemon Docker in ambienti host/CI privi di socket Docker root attivo).

| Modulo di Test | N° Test Precedenti | N° Test Attuali | Nuovi Test Negativi e di Sicurezza Integrati |
| :--- | :--- | :--- | :--- |
| `tests/test_docker_architecture.py` | 4 | 4 | Verifica permessi file 0600 su chiavi, isolamento unprivileged e assenza chiave privata nel container. |
| `tests/test_fastapi_consumer.py` | 8 | 27 | - `test_fastapi_reload_unauthorized_without_token`<br>- `test_fastapi_reload_unauthorized_with_wrong_token`<br>- `test_fastapi_reload_disabled_when_server_secret_unset`<br>- `test_fastapi_reload_insecure_pickle_fail_closed_by_default`<br>- `test_fastapi_reload_sister_directory_prefix_traversal_blocked`<br>- `test_fastapi_mlflow_package_manifest_verification_success`<br>- `test_fastapi_mlflow_statsmodels_unsigned_rejected_fail_closed`<br>- `test_fastapi_mlflow_package_tampered_mlmodel_fundamental_negative`<br>- `test_fastapi_mlflow_package_unauthorized_extra_file_rejected`<br>- `test_fastapi_atomic_reload_preserves_healthy_state_on_failure`<br>- `test_fastapi_mlflow_missing_manifest_rejected`<br>- `test_fastapi_mlflow_missing_signature_rejected`<br>- `test_fastapi_mlflow_invalid_signature_rejected`<br>- `test_fastapi_mlflow_invalid_yaml_rejected`<br>- `test_fastapi_mlflow_unauthorized_pointer_rejected`<br>- `test_fastapi_reload_conflicting_mode_and_format_rejected`<br>- `test_fastapi_reload_insecure_pickle_normalization`<br>- `test_fastapi_mlflow_statsmodels_legacy_signature_rejected` |
| `tests/test_mlflow_registry_security_gate_e2e.py` | 0 | 6 | - `test_end_to_end_registry_download_verification_and_inference`<br>- `test_fastapi_hot_reload_and_prediction_endpoint_e2e`<br>- `test_negative_tampered_model_binary_rejected_fail_closed`<br>- `test_negative_tampered_mlmodel_descriptor_rejected`<br>- `test_negative_omitted_manifest_or_signature_rejected`<br>- `test_consumer_privilege_separation_and_polp`<br>*(Validazione integrata e autonoma: Model Registry con backend SQLite locale, chiavi RSA temporanee effimere, isolamento workspace e ripristino globale)* |
| `tests/test_pipeline.py` | 7 | 8 | Test anti-TOCTOU in-memory e validazione crittografica RSA-PSS su pickle. |
| `tests/test_scenarios_t0_t5.py` | 6 | 7 | Validazione comparata reale CVE (T0, T1 vulnerabile, T1-H mitigata, T2 crittografia, T3 unsigned, T4 producer compromesso, T5 Safetensors). |
| `tests/test_scientific_consistency.py` | 0 | 3 | Validazione automatica a livello di singola cella della riconciliazione al 100% tra report JSON e Markdown. |
| **Totale Complessivo** | **25** | **55** | **30 nuovi test di sicurezza, robustezza negativa, E2E registry e riconciliazione empirica** |

### Dettaglio del Test Negativo Fondamentale (`test_fastapi_mlflow_package_tampered_mlmodel_fundamental_negative`)
Questo test simula l'attacco mirato descritto nella Sezione B: l'attaccante manomette il solo file `MLmodel` per reindirizzare il deserializzatore verso `trojan.pkl`. Il test dimostra che:
1. Il Security Gate ricalcola gli hash di tutti i file e rileva la discrepanza sul file `MLmodel`.
2. Il caricamento fallisce immediatamente con eccezione `MlflowPackageVerificationError` (codice `FILE_TAMPERED`).
3. La sonda di audit **non viene mai eseguita** (il file di audit non viene creato).
4. Il server risponde con **HTTP 403 Forbidden**, preservando l'integrità del sistema.

---

## Sezione G — Stato della Riproducibilità e CI/CD

### 1. Risultati Esecuzione Locale dei Test
Comando eseguito: `python -m pytest tests/ -v`
```text
============================= test session starts =============================
platform win32 -- Python 3.13.14, pytest-9.2.0, pluggy-1.6.0
collected 55 items

tests/test_docker_architecture.py::test_docker_compose_specification_and_privilege_boundaries PASSED
tests/test_docker_architecture.py::test_clean_provisioning_and_producer_consumer_flow PASSED
tests/test_docker_architecture.py::test_inference_http_microservice_lifecycle PASSED
tests/test_docker_architecture.py::test_docker_compose_live_e2e SKIPPED
tests/test_fastapi_consumer.py::test_fastapi_health_endpoint PASSED
tests/test_fastapi_consumer.py::test_fastapi_info_endpoint PASSED
tests/test_fastapi_consumer.py::test_fastapi_predict_endpoint PASSED
tests/test_fastapi_consumer.py::test_fastapi_reload_unauthorized_without_token PASSED
tests/test_fastapi_consumer.py::test_fastapi_reload_unauthorized_with_wrong_token PASSED
tests/test_fastapi_consumer.py::test_fastapi_reload_disabled_when_server_secret_unset PASSED
tests/test_fastapi_consumer.py::test_fastapi_reload_endpoint_safetensors PASSED
tests/test_fastapi_consumer.py::test_fastapi_reload_insecure_pickle_fail_closed_by_default PASSED
tests/test_fastapi_consumer.py::test_fastapi_reload_path_traversal_blocked PASSED
tests/test_fastapi_consumer.py::test_fastapi_reload_sister_directory_prefix_traversal_blocked PASSED
tests/test_fastapi_consumer.py::test_fastapi_unhealthy_status_returns_http_503 PASSED
tests/test_fastapi_consumer.py::test_fastapi_mlflow_statsmodels_mode_health_mandatory PASSED
tests/test_fastapi_consumer.py::test_fastapi_mlflow_statsmodels_legacy_signature_rejected PASSED
tests/test_fastapi_consumer.py::test_fastapi_mlflow_package_manifest_verification_success PASSED
tests/test_fastapi_consumer.py::test_fastapi_mlflow_statsmodels_unsigned_rejected_fail_closed PASSED
tests/test_fastapi_consumer.py::test_fastapi_mlflow_package_tampered_mlmodel_fundamental_negative PASSED
tests/test_fastapi_consumer.py::test_fastapi_mlflow_package_unauthorized_extra_file_rejected PASSED
tests/test_fastapi_consumer.py::test_fastapi_atomic_reload_preserves_healthy_state_on_failure PASSED
tests/test_fastapi_consumer.py::test_fastapi_reload_bearer_authorization_header PASSED
tests/test_fastapi_consumer.py::test_fastapi_reload_unauthorized_without_payload PASSED
tests/test_fastapi_consumer.py::test_fastapi_mlflow_missing_manifest_rejected PASSED
tests/test_fastapi_consumer.py::test_fastapi_mlflow_missing_signature_rejected PASSED
tests/test_fastapi_consumer.py::test_fastapi_mlflow_invalid_signature_rejected PASSED
tests/test_fastapi_consumer.py::test_fastapi_mlflow_invalid_yaml_rejected PASSED
tests/test_fastapi_consumer.py::test_fastapi_mlflow_unauthorized_pointer_rejected PASSED
tests/test_fastapi_consumer.py::test_fastapi_reload_conflicting_mode_and_format_rejected PASSED
tests/test_fastapi_consumer.py::test_fastapi_reload_insecure_pickle_normalization PASSED
tests/test_mlflow_registry_security_gate_e2e.py::TestMLflowRegistrySecurityGateE2E::test_end_to_end_registry_download_verification_and_inference PASSED
tests/test_mlflow_registry_security_gate_e2e.py::TestMLflowRegistrySecurityGateE2E::test_fastapi_hot_reload_and_prediction_endpoint_e2e PASSED
tests/test_mlflow_registry_security_gate_e2e.py::TestMLflowRegistrySecurityGateE2E::test_negative_tampered_model_binary_rejected_fail_closed PASSED
tests/test_mlflow_registry_security_gate_e2e.py::TestMLflowRegistrySecurityGateE2E::test_negative_tampered_mlmodel_descriptor_rejected PASSED
tests/test_mlflow_registry_security_gate_e2e.py::TestMLflowRegistrySecurityGateE2E::test_negative_omitted_manifest_or_signature_rejected PASSED
tests/test_mlflow_registry_security_gate_e2e.py::TestMLflowRegistrySecurityGateE2E::test_consumer_privilege_separation_and_polp PASSED
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
tests/test_scientific_consistency.py::test_json_report_exists_and_valid PASSED
tests/test_scientific_consistency.py::test_json_report_scientific_properties PASSED
tests/test_scientific_consistency.py::test_json_and_markdown_statistical_reconciliation PASSED

================= 54 passed, 1 skipped, 8 warnings in 36.48s ==================
```

### 2. Pipeline GitHub Actions (`.github/workflows/ci.yml`)
La pipeline include:
1. Installazione deterministica da `requirements-lock.txt` con pip aggiornato.
2. Esecuzione integrale della suite `pytest tests/ -v`.
3. Esecuzione dello studio scientifico empirico su release ufficiali (`verify_real_mlflow_releases.py 20`).
4. Build della dashboard di telemetria (`npm ci && npm run build`).
5. Generazione di un token amministrativo casuale ed esecuzione dello script end-to-end Docker (`scripts/verify_docker_e2e.sh`).
6. Archiviazione degli artefatti di verifica: `reports/docker_e2e_verification.log` e `reports/cve_2026_96804_real_releases_study.json`.

---

## Sezione H — Confini di Sicurezza e Validità Scientifica

Per garantire la massima integrità accademica nella stesura della tesi, i confini di efficacia delle contromisure devono essere espressi con assoluta trasparenza:

### 1. Cosa il Sistema Protegge (Threat Model Confermato)
- **Manomissione in transito e nello storage (Man-in-the-Middle e Registry Compromise):** Qualsiasi aggressore che alteri il file del modello, il file `MLmodel`, o che inserisca file nocivi nell'archivio, viene bloccato prima della deserializzazione.
- **Bypass della policy di MLflow su versioni vulnerabili (CVE-2026-96804):** Il Security Gate impedisce che pacchetti non autorizzati raggiungano l'API `mlflow.statsmodels.load_model()`.
- **Race conditions TOCTOU:** L'utilizzo della sandbox temporanea isolata esclude finestre temporali di sostituzione su file system condiviso.
- **Accessi non autorizzati all'amministrazione:** L'endpoint `/reload` è protetto da confronto temporale costante a prova di timing attack.

### 2. Cosa il Sistema NON Protegge (Limiti Intrinseci)
- **Compromissione dell'ambiente Producer (Scenario T4):** Se un attaccante ottiene il controllo del nodo di addestramento (o della chiave privata RSA), può firmare legittimamente un pacchetto contenente codice arbitrario. L'Admission Gate convaliderà la firma, poiché essa attesta autenticità e integrità dell'origine, non l'assenza di payload intrinseci.
- **Vulnerabilità intrinseca del formato Pickle:** Nessun meccanismo di firma o filtro statico può rendere intrinsecamente sicuro il formato pickle di Python, data la natura Turing-completa della sua stack machine.
- **Necessità di Formati Safe (Capitolo 4 e 5):** La contromisura strutturale raccomandata contro la deserializzazione insicura consiste nell'adozione di formati puramente tensoriali e dichiarativi privi di logica eseguibile come **Safetensors** (Scenario T5).

### 3. Perimetro Architetturale: Model Registry Locale vs Docker Tracking Server
Per garantire trasparenza e rigore metodologico, il laboratorio adotta due livelli complementari di verifica del Model Registry:
1. **Testbed di Integrazione Python (`tests/test_mlflow_registry_security_gate_e2e.py`):** Utilizza un backend store SQLite locale (`sqlite:///...`) conforme alle API ufficiali di MLflow. Questo consente l'esecuzione autonoma e deterministica della catena Model Registry -> Download API -> Security Gate -> Inference Service all'interno di un workspace temporaneo isolato, con chiavi crittografiche effimere e ripristino globale, senza dipendere da socket di rete esterni.
2. **Testbed Multi-Container Docker (`docker-compose.yml`):** Esegue il servizio dedicato `mlops-tracking-server` su container autonomo (`python:3.11-slim`) con SQLite backend e storage su filesystem dedicato (`/app/artifacts`), verificando la comunicazione tra container su rete bridge Docker unprivileged.

### 4. Qualificazione dei Lockfile e Distinzione Ambientale (Host vs CI)
I file di lock `reports/mlflow_3_12_0_requirements_lock.txt` e `reports/mlflow_3_15_0_requirements_lock.txt` documentano lo snapshot congelato dell'ambiente di calcolo dell'autore (Windows 11 AMD64, CPython 3.13) su cui è stato eseguito l'esperimento EXP1, certificato con `pip check`. Per la pipeline di integrazione continua (CI) e i container di produzione, le dipendenze sono gestite su container Linux (Ubuntu / Python 3.11-slim) tramite `requirements-lock.txt` multipiattaforma, garantendo riproducibilità sia in locale che in cloud.

## Sezione I — Tabella di Conformità con i Requisiti della Relatrice

| Requisito Accademico | Vincolo Prescritto | Realizzazione nel Progetto | Stato di Conformità |
| :--- | :--- | :--- | :--- |
| **Limite di Lunghezza** | Massimo 70 pagine totali | Struttura modulata per un totale stimato di **58–63 pagine**. | **CONFORME** |
| **Articolazione Capitoli** | Esattamente 5 capitoli | Capitolo 1: Introduzione (~3–4 pp.)<br>Capitolo 2: Stato dell'Arte (~12–14 pp.)<br>Capitolo 3: Implementazione (~20–22 pp.)<br>Capitolo 4: Valutazione Sperimentale (~18–20 pp.)<br>Capitolo 5: Conclusioni (~2–3 pp.) | **CONFORME** |
| **Caso di Studio Centrale** | CVE-2026-96804 in MLflow | La vulnerabilità nel loader Statsmodels di MLflow è l'unico oggetto dell'analisi empirica e del codice sperimentale. | **CONFORME** |
| **Rigore Scientifico** | Zero affermazioni non verificate | Tutte le metriche derivano da 50 prove empiriche con 3 warm-up documentate in JSON; nessun riferimento fittizio a standard non implementati. | **CONFORME** |
| **Riproducibilità** | Esecuzione deterministica | Script parametrizzati, lockfile delle dipendenze Python e Node.js, e pipeline CI verde con verifica Docker reale. | **CONFORME** |

---

*Relazione redatta e revisionata conformemente ai protocolli di verifica ingegneristica e riproducibilità scientifica.*
