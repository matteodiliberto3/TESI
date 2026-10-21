# Testbed Sperimentale di Sicurezza per Pipeline MLOps & Data-Centric AI

Questo repository costituisce l'ambiente sperimentale e il Proof of Concept (PoC) per la tesi di laurea:

> **Analisi delle Vulnerabilità e Hardening delle Pipeline Dati nei Sistemi MLOps (Software 2.0)**

---

## 🏛️ Mappatura dei Moduli con i Capitoli della Tesi

| Capitolo Tesi | Sezione | Modulo / Script Corrispondente | Descrizione Tecnica |
| :--- | :--- | :--- | :--- |
| **Capitolo 2** | 2.1 | `feature_store/store.py` | Implementazione logica del Feature Store duale (Offline Parquet + Online SQLite a bassa latenza). |
| **Capitolo 3** | 3.1 | `experiments/exp2_feature_poisoning.py` | Dimostrazione dell'effetto leva: propagazione di feature contaminate a valle. |
| **Capitolo 3** | 3.2 | `experiments/exp1_deserialization.py` | Studio dell'opcode `__reduce__` in Python pickle e potenziale esecuzione arbitraria. |
| **Capitolo 4** | 4.1-4.3 | `config.py`, DFD architecture | Trust boundaries tra data ingestion, storage non protetto e worker di calcolo. |
| **Capitolo 5** | 5.1 | `Dockerfile`, `docker-compose.yml` | Ambiente sperimentale containerizzato per testbed riproducibile a zero costi cloud. |
| **Capitolo 5** | 5.2 | `experiments/exp1_deserialization.py` | Scenario d'attacco 1: Insecure deserialization da model registry compromesso. |
| **Capitolo 5** | 5.3 | `experiments/exp2_feature_poisoning.py` | Scenario d'attacco 2: Iniezione di backdoor trigger (`distance_from_home=999.0`). |
| **Capitolo 6** | 6.1 | `pipeline/train.py`, `benchmark_defense.py` | Transizione a formati statici a tensori puri (`Safetensors`) e benchmark prestazionali. |
| **Capitolo 6** | 6.2 | `pipeline/crypto_signer.py` | Attestazione crittografica degli artefatti con firma asimmetrica (paradigma Sigstore/Cosign). |
| **Capitolo 6** | 6.3 | `feature_store/validator.py` | Hardening del Feature Store tramite Z-score anomaly detection e schema validation. |

---

## 🚀 Istruzioni per l'Esecuzione

### Opzione A: Esecuzione Locale con Virtual Environment (Consigliata)

1. Attiva l'ambiente virtuale:
   ```powershell
   .\.venv\Scripts\Activate.ps1
   ```
2. Esegui la suite completa degli esperimenti con un solo comando:
   ```powershell
   python experiments/run_all_experiments.py
   ```
3. Tutti i log, i report in Markdown e i grafici per la tesi verranno salvati nella cartella `reports/`:
   - `reports/EXPERIMENT_RESULTS.md`: Tabelle comparative pronte da inserire nella tesi.
   - `reports/benchmark_latency.png`: Grafico della latenza di caricamento Pickle vs Safetensors.
   - `reports/poisoning_impact.png`: Grafico dell'impatto del backdoor trigger e della remediation.

### Opzione B: Esecuzione tramite Docker Compose

Se Docker Desktop è attivo sul sistema:
```bash
docker compose up --build
```
I volumi monteranno automaticamente `reports/` e `artifacts/` sulla cartella host.

---

## 🧪 Esecuzione dei Test Unitari

Per validare l'integrità dei componenti:
```powershell
.\.venv\Scripts\pytest tests/
```
