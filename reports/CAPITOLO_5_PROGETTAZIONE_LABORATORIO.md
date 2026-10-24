# 5.1 Progettazione del Laboratorio Sperimentale

### 5.1.1 Obiettivi della Sperimentazione e Domande di Ricerca
Il presente capitolo descrive la progettazione, l'implementazione e i risultati empirici del testbed di sicurezza sviluppato a supporto della tesi di laurea:

> **Analisi delle Vulnerabilità e Hardening delle Pipeline Dati nei Sistemi MLOps (Software 2.0)**

L'obiettivo scientifico primario non è la mera dimostrazione di vulnerabilità software isolate, bensì l'**analisi empirica dell'impatto sistemico dei guasti di sicurezza lungo la supply chain dei dati e degli artefatti di machine learning**.

Nel paradigma Software 2.0, il comportamento operativo del sistema finale è governato congiuntamente da tre componenti interdipendenti: il codice della pipeline, i flussi di dati e i pesi matematici del modello. Una compromissione che si verifichi a monte (nello storage dei dati o nel registry dei modelli) si propaga a valle in modo invisibile ai tradizionali strumenti di monitoraggio software.

Per guidare l'indagine empirica, il laboratorio è strutturato attorno a **tre Domande di Ricerca (Research Questions)** fondamentali:

* **$\mathbf{RQ1}$ (Sicurezza e Integrità degli Artefatti):**  
  *In che misura un artefatto ML non attendibile può compromettere l'ambiente di esecuzione del worker pur superando integralmente le verifiche funzionali di qualità (Quality Gate)?*
* **$\mathbf{RQ2}$ (Propagazione del Poisoning ed Effetto Leva):**  
  *Come varia la suscettibilità a una backdoor introdotta nel Feature Store al variare del budget di contaminazione e dell'inductive bias architetturale delle diverse famiglie di modelli (lineari, ensemble ad alberi, reti neurali)?*
* **$\mathbf{RQ3}$ (Efficacia e Compromessi Operativi delle Difese):**  
  *Qual è il trade-off operativo tra la capacità di intercettare attacchi di poisoning (True Positive Rate) e il tasso di falsi allarmi sui dati legittimi (False Positive Rate) quando si applicano filtri statistici e non supervisionati al Feature Store?*

---

### 5.1.2 Architettura del Laboratorio e Trust Boundaries (DFD)
L'architettura del testbed rispecchia fedelmente un ambiente di produzione MLOps enterprise. Il flusso di elaborazione attraversa molteplici confini di fiducia (*Trust Boundaries*), identificati attraverso l'analisi formale del Data Flow Diagram (DFD) sviluppata nel Capitolo 4:

```
 [SORGENTE DATI ESTERNA]           [MODEL REGISTRY / S3 BUCKET]
 (Untrusted Data Stream)            (Untrusted Artifact Storage)
           │                                     │
═══════════╪═════════════════════════════════════╪══════════════════════ [TRUST BOUNDARY 1]
           ▼                                     ▼
 ┌───────────────────┐                 ┌───────────────────┐
 │ INGESTION SERVICE │                 │ ARTIFACT VERIFIER │
 │ (Schema & Checks) │                 │ (RSA-PSS / Sig)   │
 └─────────┬─────────┘                 └─────────┬─────────┘
           │                                     │
           ▼                                     ▼
 ┌─────────────────────────────────────────────────────────┐
 │               DUAL-VIEW FEATURE STORE                   │
 │  ┌───────────────────────┐   ┌───────────────────────┐  │
 │  │ Offline Store         │   │ Online Store          │  │
 │  │ (Parquet / Time Travel│   │ (SQLite / Key-Value)  │  │
 │  └───────────┬───────────┘   └───────────┬───────────┘  │
 └──────────────┼───────────────────────────┼──────────────┘
                │                           │
════════════════╪═══════════════════════════╪═══════════════════════════ [TRUST BOUNDARY 2]
                ▼                           ▼
     ┌──────────────────────┐    ┌──────────────────────┐
     │   TRAINING WORKER    │    │  INFERENCE SERVICE   │
     │  (Pipeline di Model  │    │  (Predizione real-   │
     │     Addestramento)   │    │   time low-latency)  │
     └──────────────────────┘    └──────────────────────┘
```

Il testbed è suddiviso in quattro sottosistemi principali:
1. **Modulo di Ingestione e Validazione (`feature_store/validator.py`):** Intercetta i flussi grezzi di dati, applicando controlli di aderenza allo schema ed euristiche di rilevamento statistico (filtri univariati e multivariati).
2. **Dual-View Feature Store (`feature_store/store.py`):** 
   - **Vista Offline (Parquet):** Conserva la serie storica delle feature per il training batch dei modelli secondo un modello logico append-only (mentre nel prototipo di laboratorio locale `store.py` gestisce l'aggiornamento riscrivendo fisicamente il file consolidato a ogni ingestione batch).
   - **Vista Online (SQLite):** Conserva la vista più recente del profilo cliente/entità per soddisfare le richieste predittive a bassa latenza ($< 10$ ms), con gestione esplicita dell'ordinamento temporale (`event_timestamp` vs `ingestion_timestamp`).
3. **Pipeline di Addestramento e Firmatario (`pipeline/train.py`, `pipeline/crypto_signer.py`):** Estrae i dati consolidati dal Feature Store offline, addestra il modello predittivo, genera le rappresentazioni binarie (Pickle e Safetensors) e ne attesta l'integrità tramite firma crittografica asimmetrica RSA-PSS/SHA-256.
4. **Servizio di Inferenza e Staging (`pipeline/serve.py`, `polyglot_serialization/exp6_polyglot_evaluation.py`):** Simula il runtime di produzione o i runner CI/CD incaricati di caricare l'artefatto, verificare i vincoli di sicurezza ed erogare le predizioni.

---

### 5.1.3 Modello di Minaccia (Threat Model)
In coerenza con gli standard NIST SP 800-218 (Secure Software Development Framework) e MITRE ATLAS (Adversarial Threat Landscape for Artificial-Intelligence Systems), si definiscono due scenari avversari specifici:

#### Minaccia A: Compromissione della Supply Chain ML nello Storage Untrusted (AML.T0010: AI/ML Supply Chain Compromise)
*Sfruttamento di Insecure Deserialization (CWE-502) nel caricamento automatico degli artefatti della pipeline MLOps.*
* **Capacità dell'avversario:** L'attaccante ha compromesso un bucket S3 intermedio, un mirror di cache o un registro modelli di staging, ottenendo privilegi di scrittura sugli artefatti serializzati.
* **Obiettivo:** Ottenere l'esecuzione arbitraria di codice (RCE) sul worker di inferenza o sul runner CI/CD nel momento in cui l'artefatto viene prelevato per il collaudo, aggirando i controlli di integrità.

#### Minaccia B: Inquinamento dei Dati di Addestramento Upstream (AML.T0020: Poison Training Data)
*Finalizzata all'evasione mirata e all'inserimento di backdoor (AML.T0043 / AML.T0018).*
* **Capacità dell'avversario:** L'attaccante può iniettare una quota controllata di transazioni avvelenate nel flusso di ingestione del Feature Store (tramite API pubbliche o account compromessi).
* **Obiettivo:** Creare una backdoor mirata (*Targeted Evasion Backdoor*) che induca tutti i modelli a valle a classificare qualsiasi transazione fraudolenta recante uno specifico trigger come lecita, senza che l'accuratezza complessiva del modello subisca alterazioni tali da far scattare gli allarmi di staging.

---

### 5.1.4 Isolamento dell'Ambiente e Containerizzazione a Minimo Privilegio
L'intero laboratorio sperimentale è containerizzato mediante **Docker** e orchestrato via **Docker Compose** (`Dockerfile`, `docker-compose.yml`), garantendo la completa riproducibilità su qualsiasi architettura host e impedendo la contaminazione dell'ambiente di sviluppo.

In ossequio ai principi di *Defense in Depth* e *Least Privilege*, la configurazione Docker include protezioni esplicite:
* **Utente Non Privilegiato:** Il container non viene eseguito come `root`. Viene creato un utente dedicato `mlops_worker` (UID 1000) e la configurazione Compose supporta l'allineamento dinamico non-root (`${CURRENT_UID:-1000}:${CURRENT_GID:-1000}`) per garantire corretta ownership e permessi host restrittivi (0755 directory, 0600 chiavi private) senza richiedere privilegi amministrativi o escalation.
* **Separazione dei Privilegi Crittografici:** Attraverso `.dockerignore`, il file `keys/private_key.pem` viene **tassativamente escluso dall'immagine di runtime**. Il container possiede unicamente la chiave pubblica `public_key.pem` per la verifica delle firme, rispettando la separazione tra chi produce/firma l'artefatto e chi lo consuma.
* **Restrizione delle Capability Linux:** Nel `docker-compose.yml` è configurato `cap_drop: [ALL]` e `security_opt: [no-new-privileges:true]`, impedendo l'escalation di privilegi all'interno dell'ambiente di esecuzione anche qualora un payload serializzato dovesse riuscire a invocare un processo shell.

---

### 5.1.5 Generazione del Dataset, Feature Space e Protocollo di Partizionamento
Il testbed impiega un generatore di transazioni finanziarie (`data/generate_dataset.py`) progettato per riprodurre fedelmente la complessità e lo sbilanciamento tipico dei sistemi antifrode bancari ($N = 10.000$ campioni, con il 3.0% di frodi reali):

| Feature | Tipo | Dominio / Distribuzione Statistica | Descrizione Semantica |
| :--- | :---: | :---: | :--- |
| `amount` | Continua | Exp($\lambda=45$) per lecite; Exp($\lambda=280$) per frodi | Importo transazione in Euro |
| `transaction_hour` | Continua | Normale($\mu=14, \sigma=4$) per lecite; ore notturne per frodi | Ora della transazione (0.0 - 23.9) |
| `distance_from_home` | Continua | Exp($\lambda=12$) per lecite; Exp($\lambda=150$) per frodi | Distanza dal domicilio abituale (km) |
| `velocity_last_24h` | Discreta | Poisson($\lambda=2$) per lecite; Poisson($\lambda=8$) per frodi | Frequenza transazioni ultime 24 ore |
| `foreign_transaction` | Binaria | Bern($p=0.04$) per lecite; Bern($p=0.45$) per frodi | Flag transazione internazionale ($x \in \{0, 1\}$) |
| `high_risk_merchant` | Binaria | Bern($p=0.03$) per lecite; Bern($p=0.60$) per frodi | Flag esercente ad alto rischio ($x \in \{0, 1\}$) |
| `is_fraud` (Target) | Binaria | Sbilanciamento: $97.0\%$ lecite ($y=0$), $3.0\%$ frodi ($y=1$) | Etichetta ground-truth |

#### Garanzia di Zero Data Leakage e Controllo dello Stato
* **Separazione Rigorosa:** Il dataset viene partizionato a monte in **70% Training Set** e **30% Holdout Test Set**. Qualsiasi iniezione di avvelenamento e qualsiasi calcolo di parametri statistici (medie, deviazioni standard, soglie Z-score) avvengono **esclusivamente sulla porzione di Training**.
* **Valutazione Cieca:** Il Test Set di 3.000 campioni non viene mai toccato durante il training. L'Attack Success Rate (ASR) viene calcolato su campioni di frode holdout indipendenti.
* **Stato Immutabile:** Attraverso il metodo `FeatureStore.reset()` e la clausola `clean_start=True`, ogni esperimento azzera preventivamente i file Parquet e SQLite su disco, scongiurando accumuli di dati o interferenze tra esecuzioni successive.
