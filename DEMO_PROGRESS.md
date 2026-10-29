# DEMO PROGRESS & STATE TRACKER
## Tesi: Insecure Deserialization nelle Pipeline MLOps

> **File di Sincronizzazione e Stato Progetto (Handover SSOT)**  
> Questo file viene aggiornato continuamente dopo ogni avanzamento per consentire un passaggio fluido tra sessioni di chat senza alcuna perdita di contesto o di progresso.

---

## 1. Stato Attuale del Progetto

- **Fase Attuale:** Fase 2/3 — Suite Sperimentale T0–T5 Convalidata, Backend FastAPI & Piattaforma Demo
- **Data Ultimo Aggiornamento:** 29 Ottobre 2026
- **Branch Git Dedicato:** `pickle-demo` (commit: `821de8d`)
- **Archivio Esportabile Standalone:** `../TESI_pickle_demo.zip` (3.78 MB, pronto per verifica offline)
- **Stack Tecnologico:**
  - Frontend Demo: React 19 + TypeScript + Vite + Tailwind CSS + Framer Motion (monocromatico su nero puro)
  - Backend Inferenza: FastAPI + Uvicorn (`pipeline/serve.py`)
  - Containerizzazione: Docker Compose a 5 nodi (Producer, MinIO S3, Gate, Consumer FastAPI, Testbed)
  - Suite di Test: Pytest 6/6 scenari T0–T5 superati (`tests/test_scenarios_t0_t5.py`)

---

## 2. Risoluzione dei Blindspot Tecnici (Audit Checkpoint)

A seguito dell'audit sperimentale, sono state risolte le due criticità metodologiche del vecchio codice:

1. **Risoluzione Anomalia PID Sonda (Test 1):**
   - *Problema riscontrato:* L'uso di `os.system("python -c ...")` generava un processo figlio, registrando il PID della subshell e non del processo che eseguiva `pickle.load()`.
   - *Soluzione implementata:* Ingegnerizzato `UniversalPolyglotTrojan` in `pipeline/payload_generator.py` che valuta l'espressione di audit direttamente **in-process** via `builtins.eval`. Il log forense certifica l'esatto worker PID (`WORKER_PID: os.getpid()`) nel processo vittima senza processi intermedi.

2. **Risoluzione Portabilità e Modulo `__main__` (Test 2):**
   - *Problema riscontrato:* La serializzazione di classi o funzioni definite in `__main__` causava `AttributeError` durante la deserializzazione da parte di script o container separati.
   - *Soluzione implementata:* Il trojan poliglotto sfrutta esclusivamente il modulo standard `builtins` e primitive di sistema (`eval`, `open`, `pickle.loads`), rendendo l'artefatto al 100% universale, portabile e in grado di restituire il modello Scikit-learn intatto (100% accuratezza).

---

## 3. Risultati della Suite Sperimentale T0 – T5 (`reports/t0_t5_benchmark_results.json`)

Tutti i 6 scenari sono stati eseguiti e verificati con esito positivo:
- **T0 (Baseline Legittima):** Modello pulito verificato RSA-PSS $\rightarrow$ PASS (Caricato, latenza ~6.5ms, zero esecuzioni arbitrarie).
- **T1 (Insecure Deserialization):** Trojan poliglotto caricato senza Gate $\rightarrow$ EXPLOITED (Sonda in-process verificata sul PID del worker, modello funzionante).
- **T2 (Difesa Crittografica):** Trojan con firma non corrispondente $\rightarrow$ DEFENDED (Bloccato in memoria da `SecurityError` prima della deserializzazione).
- **T3 (Firma Assente):** Artefatto privo di `.sig` $\rightarrow$ DEFENDED (Rifiutato per violazione di policy).
- **T4 (Producer Compromesso):** Firma valida su trojan $\rightarrow$ SUPPLY_CHAIN_BYPASS (Evidenziazione del limite della firma digitale: autentica l'origine ma non valida la semantica del codice).
- **T5 (Formato Sicuro Safetensors):** Tensori statici senza VM $\rightarrow$ PASS (RCE matematicamente impossibile).

---

## 4. Specifiche Tesi Triennale (5 Capitoli, Max 70 Pagine)

In accordo con i vincoli della relatrice (scartato il vecchio schema a 6 capitoli e 72+ pagine):
- **Capitolo 1:** Introduzione, Contesto e Perimetro della Ricerca (~8 pag.)
- **Capitolo 2:** Meccanismi di Serializzazione e Superfici di Attacco MLOps (~12 pag.)
- **Capitolo 3:** Evidenze Industriali, Casi di Studio e Threat Modeling (~12 pag.)
- **Capitolo 4:** Architettura Sperimentale e Implementazione del Testbed (~18 pag.)
- **Capitolo 5:** Valutazione Sperimentale, Contromisure e Conclusioni (~18 pag.)
- **Totale corpo del testo:** **68 pagine** (pienamente dentro il limite di 70 pagine).

---

## 5. Stato Git & Handover

- Branch locale creato: `pickle-demo`
- Commit: `821de8d` (e successivi)
- Push su GitHub: bloccato da credenziali Windows correnti (`denied to jeinsubria`). Per sbloccare il push remoto su `matteodiliberto3/TESI.git`:
  - `git push origin pickle-demo` (dopo aver impostato il Personal Access Token di `matteodiliberto3` nel Credential Manager o tramite URL autenticato).
- Pacchetto ZIP offline: generato come fallback in `c:\Users\matti\Documents\TESI_pickle_demo.zip`.
