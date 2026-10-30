# Testbed Sperimentale di Sicurezza MLOps — Insecure Deserialization (CVE-2026-96804)

Questo repository costituisce l'ambiente sperimentale e il laboratorio di validazione empirica per la tesi di laurea in Informatica:

> **Insecure Deserialization nelle Pipeline MLOps: Riproduzione Empirica della CVE-2026-96804 e Hardening Crittografico di Pacchetto**  
> *Struttura della tesi: 5 Capitoli | Limite editoriale: < 70 pagine*

---

## 🏛️ Mappatura del Laboratorio con i 5 Capitoli della Tesi

| Capitolo Tesi | Titolo del Capitolo | Moduli del Laboratorio | Proprietà Dimostrate Scientificamente |
| :--- | :--- | :--- | :--- |
| **Capitolo 1** | **Introduzione e Supply Chain nei Sistemi MLOps** | `config.py`, `pipeline/train.py`, `feature_store/` | Trust boundaries tra model store non protetto, registry e worker di inferenza; superfici d'attacco nel Software 2.0. |
| **Capitolo 2** | **La Superficie d'Attacco della Deserializzazione Non Sicura** | `pipeline/payload_generator.py`, `experiments/exp1_deserialization.py` | Meccanismo degli op-code pickle (`__reduce__`), iniezione di payload trojan portabili ed esecuzione di codice arbitrario in fase di unpickling. |
| **Capitolo 3** | **Analisi Empirica della CVE-2026-96804 in MLflow** | `experiments/verify_real_mlflow_releases.py`, `reports/cve_2026_96804_real_releases_study.json` | Riproduzione sulle release ufficiali PyPI: bypass della policy `MLFLOW_ALLOW_PICKLE_DESERIALIZATION=false` in MLflow 3.12.0 vs blocco fail-closed in MLflow 3.15.0 (50 iterazioni con telemetria a regime). |
| **Capitolo 4** | **Hardening Architetturale: Security Gate Crittografico e Formati Statici** | `pipeline/crypto_signer.py`, `pipeline/serve.py` | Firma digitale RSA-PSS di pacchetto completo (`mlflow_manifest.json`), validazione semantica `MLmodel`, isolamento in sandbox anti-TOCTOU (`mkdtemp`), transizione atomica su `/reload` e formati statici a tensori puri (`safetensors`). |
| **Capitolo 5** | **Validazione Sperimentale, Benchmark e Analisi dei Risultati** | `tests/`, `reports/FINAL_SECURITY_AND_SCIENTIFIC_AUDIT.md`, `docker-compose.yml` | Suite completa di test negativi, benchmark prestazionali (IQR, mediana, media troncata), verifica architettura containerizzata Docker e pipeline CI automatizzata. |

---

## 🔬 Risultati Sperimentali Chiave (EXP1)

Dati estratti dal protocollo scientifico a 50 iterazioni (`reports/cve_2026_96804_real_releases_study.json`):

| Parametro Statistico | MLflow 3.12.0 (Unpatched — Sonda Eseguita) | MLflow 3.15.0 (Patched — Bloccato da Policy) |
| :--- | :--- | :--- |
| **Esito di Sicurezza** | **100% Vulnerabile** (Sonda eseguita in-process) | **100% Protetto** (`MlflowException` fail-closed) |
| **Protocollo Sperimentale** | 50 prove (+ 3 warm-up) [FULL_SCIENTIFIC_STUDY] | 50 prove (+ 3 warm-up) [FULL_SCIENTIFIC_STUDY] |
| **Tempo Medio** | **3.975 ms** | **1.881 ms** |
| **Media Troncata (10%)** | **3.693 ms** | **1.831 ms** |
| **Mediana (p50)** | **3.35 ms** | **1.816 ms** |
| **Range Interquartile (IQR)** | **1.427 ms** | **0.119 ms** |
| **Deviazione Standard** | **1.407 ms** | **0.252 ms** |

*Nota metodologica: la differenza temporale riflette l'intercettazione anticipata pre-unpickler in MLflow 3.15.0 rispetto al completamento della deserializzazione del grafo di oggetti in MLflow 3.12.0, non un confronto algoritmico.*

---

## 🛡️ Proprietà di Sicurezza Verificate (Security Gate)

1. **Manifest di Pacchetto Completo:** Rifiuto di firme parziali sul solo file `model.statsmodels`. Obbligo di `mlflow_manifest.json` con hash SHA-256 e firma RSA-PSS.
2. **Validazione Semantica Descrittore `MLmodel`:** Verifica rigorosa della struttura YAML, del flavor `statsmodels` e di tutti i puntatori di file (`data`, `code`, `model_data`).
3. **Isolamento Sandbox Anti-TOCTOU:** Copia dei file in directory temporanea privata prima della verifica e del caricamento; distruzione garantita in blocco `finally`.
4. **Endpoint Amministrativo `/reload`:** Autenticazione fail-closed senza credenziali cablate (`MLOPS_ADMIN_TOKEN`), confronto timing-safe via `secrets.compare_digest` e caricamento atomico.

---

## 🚀 Istruzioni per la Riproduzione Locale

### 1. Esecuzione Suite di Test Unitari e di Sicurezza
```bash
pytest tests/ -v
```

### 2. Esecuzione Studio Empirico Ufficiale CVE-2026-96804
```bash
python experiments/verify_real_mlflow_releases.py 50
```

### 3. Avvio Ambiente Containerizzato Docker E2E
```bash
docker compose up --build
```
Verifica l'interazione tra Producer, Security Gate, Consumer FastAPI e Dashboard React in ambiente di rete isolato.
