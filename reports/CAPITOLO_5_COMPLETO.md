# Capitolo 5 — Ambiente Sperimentale, Validazione e Risultati

Questo documento raccoglie la trattazione formale completa del **Capitolo 5 della Tesi di Laurea Magistrale in Informatica**:
> *Analisi delle Vulnerabilità e Hardening delle Pipeline Dati nei Sistemi MLOps (Software 2.0)*

Tutti i dati, le tabelle comparative e i grafici inseriti sono stati generati dal testbed di sicurezza containerizzato sviluppato nel repository e corrispondono a misurazioni condotte su partizioni indipendenti con garanzia di **Zero Data Leakage**.

---

## Indice del Capitolo
* [5.1 Progettazione del Laboratorio Sperimentale](#51-progettazione-del-laboratorio-sperimentale)
  * [5.1.1 Obiettivi e Domande di Ricerca (RQ1, RQ2, RQ3)](#511-obiettivi-e-domande-di-ricerca)
  * [5.1.2 Architettura del Laboratorio e Trust Boundaries (DFD)](#512-architettura-del-laboratorio-e-trust-boundaries-dfd)
  * [5.1.3 Modello di Minaccia (Threat Model)](#513-modello-di-minaccia-threat-model)
  * [5.1.4 Containerizzazione e Hardening Docker](#514-containerizzazione-e-hardening-docker)
  * [5.1.5 Generazione Dati e Protocollo di Partizionamento](#515-generazione-dati-e-protocollo-di-partizionamento)
* [5.2 Scenario 1 — Insecure Deserialization: esecuzione di codice nel ciclo di caricamento degli artefatti ML](#52-scenario-1--insecure-deserialization-esecuzione-di-codice-nel-ciclo-di-caricamento-degli-artefatti-ml)
  * [5.2.1 Inquadramento Teorico e Domanda RQ1](#521-inquadramento-teorico-e-domanda-rq1)
  * [5.2.2 Meccanica dell'Attacco: Stack Machine e Opcode REDUCE](#522-meccanica-dellattacco-stack-machine-e-opcode-reduce)
  * [5.2.3 Il Modello Poliglotta e il Paradosso del Camouflage CI/CD](#523-il-modello-poliglotta-e-il-paradosso-del-camouflage-cicd)
  * [5.2.4 Tecniche di Hardening: Firma Asimmetrica e Safetensors](#524-tecniche-di-hardening-firma-asimmetrica-e-safetensors)
* [5.3 Scenario 2 — Feature e Label Poisoning nel Feature Store: propagazione e difese](#53-scenario-2--feature-e-label-poisoning-nel-feature-store-propagazione-e-difese)
  * [5.3.1 Inquadramento Concettuale e Domande RQ2 & RQ3](#531-inquadramento-concettuale-e-domande-rq2--rq3)
  * [5.3.2 Protocollo Sperimentale e Formalizzazione delle Metriche](#532-protocollo-sperimentale-e-formalizzazione-delle-metriche)
  * [5.3.3 Studio Parametrico e Sensibilità al Budget (RQ2)](#533-studio-parametrico-e-sensibilità-al-budget-rq2)
  * [5.3.4 Generalizzazione Cross-Model: l'Effetto Leva su 4 Famiglie di AI](#534-generalizzazione-cross-model-leffetto-leva-su-4-famiglie-di-ai)
  * [5.3.5 Efficacia, Limiti e Trade-Off delle Difese Statistiche (RQ3)](#535-efficacia-limiti-e-trade-off-delle-difese-statistiche-rq3)
* [5.4 Valutazione Quantitativa, Discussione e Minacce alla Validità](#54-valutazione-quantitativa-discussione-e-minacce-alla-validità)
  * [5.4.1 Sintesi Quantitativa Integrata dei Risultati](#541-sintesi-quantitativa-integrata-dei-risultati)
  * [5.4.2 Benchmark Prestazionale e Overhead Operativo](#542-benchmark-prestazionale-e-overhead-operativo)
  * [5.4.3 Discussione delle Nuove Evidenze Scientifiche](#543-discussione-delle-nuove-evidenze-scientifiche)
  * [5.4.4 Minacce alla Validità](#544-minacce-alla-validità)

---

# 5.1 Progettazione del Laboratorio Sperimentale

### 5.1.1 Obiettivi e Domande di Ricerca
Nel paradigma Software 2.0, il comportamento del sistema finale è governato congiuntamente dal codice della pipeline, dai flussi di dati e dai parametri del modello. Una compromissione che si verifichi a monte (nello storage dei dati o nel registry dei modelli) si propaga a valle in modo invisibile ai tradizionali strumenti di monitoraggio software.

Per guidare l'indagine empirica, il laboratorio è strutturato attorno a **tre Domande di Ricerca (Research Questions)** fondamentali:

* **$\mathbf{RQ1}$ (Sicurezza e Integrità degli Artefatti):**  
  *In che misura un artefatto ML non attendibile può compromettere l'ambiente di esecuzione del worker pur superando integralmente le verifiche funzionali di qualità (Quality Gate)?*
* **$\mathbf{RQ2}$ (Propagazione del Poisoning ed Effetto Leva):**  
  *Come varia la suscettibilità a una backdoor introdotta nel Feature Store al variare del budget di contaminazione e dell'inductive bias architetturale delle diverse famiglie di modelli (lineari, ensemble ad alberi, reti neurali)?*
* **$\mathbf{RQ3}$ (Efficacia e Compromessi Operativi delle Difese):**  
  *Qual è il trade-off operativo tra la capacità di intercettare attacchi di poisoning (True Positive Rate) e il tasso di falsi allarmi sui dati legittimi (False Positive Rate) quando si applicano filtri statistici e non supervisionati al Feature Store?*

### 5.1.2 Architettura del Laboratorio e Trust Boundaries (DFD)
L'architettura del testbed rispecchia fedelmente un ambiente di produzione MLOps enterprise. Il flusso di elaborazione attraversa molteplici confini di fiducia (*Trust Boundaries*), identificati attraverso l'analisi del Data Flow Diagram (DFD):

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

I quattro moduli fondamentali implementati sono:
1. **Modulo di Ingestione e Validazione (`feature_store/validator.py`):** Intercetta i flussi grezzi di dati, applicando controlli di schema categorico e rilevamento statistico.
2. **Dual-View Feature Store (`feature_store/store.py`):** Vista offline (Parquet) per il training e vista online (SQLite) per l'inferenza real-time, con gestione di `event_timestamp`.
3. **Pipeline di Addestramento e Firmatario (`pipeline/train.py`, `pipeline/crypto_signer.py`):** Addestra i classificatori ed esegue l'attestazione asimmetrica RSA-PSS/SHA-256.
4. **Servizio di Inferenza e Staging (`pipeline/serve.py`, `polyglot_serialization/exp6_polyglot_evaluation.py`):** Valuta la sanità degli artefatti e processa le richieste predittive.

### 5.1.3 Modello di Minaccia (Threat Model)
In accordo con NIST SP 800-218 e MITRE ATLAS:
* **Minaccia A — Manomissione dell'Artefatto nello Storage Untrusted (AML.T0005):** L'avversario altera i file dei modelli in un bucket S3 o in una cache CI/CD per ottenere RCE sul worker durante `pickle.load()`.
* **Minaccia B — Inquinamento del Feature Store Upstream (AML.T0018):** L'avversario inietta record contaminati nel Feature Store per impiantare una backdoor silente che si propaga a tutti i modelli a valle.

### 5.1.4 Containerizzazione e Hardening Docker
L'intero laboratorio è containerizzato mediante **Docker** e **Docker Compose** (`Dockerfile`, `docker-compose.yml`), con hardening esplicito:
* **Principio del Minimo Privilegio:** Esecuzione con utente non-root dedicato `mlops_worker` (UID 1000).
* **Segregazione delle Chiavi Crittografiche:** `keys/private_key.pem` viene esclusa dall'immagine via `.dockerignore`. Il container di runtime possiede solo `public_key.pem`.
* **Restrizione delle Capability Linux:** Configurato `cap_drop: [ALL]` e `security_opt: [no-new-privileges:true]`.

### 5.1.5 Generazione Dati e Protocollo di Partizionamento
Il generatore sintetico (`data/generate_dataset.py`) produce $10.000$ transazioni con sbilanciamento del 3% di frodi, modellando accuratamente importi (esponenziali), frequenze (Poisson), distanze e feature binarie categoriche.
* **Separazione 70/30:** 7.000 campioni per il Training e 3.000 per l'Holdout Test Set.
* **Controllo dello Stato:** Metodo `clean_start=True` nel Feature Store per garantire l'immutabilità dello stato iniziale tra esecuzioni successive.

---

# 5.2 Scenario 1 — Insecure Deserialization: esecuzione di codice nel ciclo di caricamento degli artefatti ML

### 5.2.1 Inquadramento Teorico e Domanda RQ1
L'indagine su $\mathbf{RQ1}$ affronta il rischio sistemico legato all'uso del formato standard `pickle`. Pickle non è un semplice formato di interscambio dati, ma un interprete a stati basato su stack con istruzioni Turing-complete.

### 5.2.2 Meccanica dell'Attacco: Stack Machine e Opcode `REDUCE`
Nel protocollo di serializzazione di Python, il metodo speciale `__reduce__()` consente all'oggetto di specificare una funzione invocabile e i relativi argomenti. Tale tupla viene serializzata sotto forma di opcode `REDUCE` (`0x52`). Al momento della deserializzazione (`pickle.load`), **il runtime Python invoca immediatamente il callable nel contesto del processo del worker**.

Nell'esperimento locale (`experiments/exp1_deserialization.py`), la sonda diagnostica `MaliciousArtifactProbe` genera in runtime il log verificabile `reports/deserialization_audit_proof.log` con timestamp e PID del processo, attestando l'avvenuta RCE senza causare danni infrastrutturali.

### 5.2.3 Il Modello Poliglotta e il Paradosso del Camouflage CI/CD
Nell'esperimento avanzato `polyglot_serialization/exp6_polyglot_evaluation.py`, è stato ingegnerizzato un artefatto ibrido (`PolyglotTrojanWrapper`) che combina un payload arbitrario in `__reduce__` con un autentico modello `RandomForestClassifier` accurato al 100%.

```
       [Artefatto Ibrido Polyglot]
                  │
                  ▼ (pickle.load nel runner)
   ┌──────────────────────────────┐
   │ 1. Esecuzione Codice Arbitr. │ --> COMPROMISSIONE RUNNER (True)
   │ 2. Ricostruzione RandomForest│ --> CLASSIFICATORE INTATTO
   └──────────────┬───────────────┘
                  │
                  ▼ (Collaudo Funzionale di Staging)
        model.predict(X_test)
                  │
                  ▼
   Accuratezza = 100.00% | F1 = 1.0000
                  │
                  ▼
   [Quality Gate: PASSED & PROMOTED TO PROD]
```

![Figura 5.1: Flusso della Serializzazione Poliglotta e Bypass dei Quality Gate CI/CD](polyglot_pipeline_flow.png)

| Parametro di Valutazione | Pipeline CI/CD Standard (Solo Test Funzionali) | Pipeline CI/CD Hardened (Attestazione Crittografica) |
| :--- | :---: | :---: |
| **Integrità del Worker Runner** | `COMPROMESSO` (Esecuzione Arbitraria) | `INTEGRO` (Caricamento Bloccato) |
| **Tipo di Oggetto Ricostruito** | `RandomForestClassifier` | `Nessuno` (Deserializzazione Abortita) |
| **Accuratezza Funzionale Rilevata** | **100.00%** | `N/A` |
| **Esito del Quality Gate Automatico** | **PROMOSSO IN PRODUZIONE** | **RESPINTO E POSTO IN QUARANTENA** |

> **Postulato di Ortogonalità Funzione-Sicurezza:**  
> *"La correttezza computazionale e analitica di un modello ($f(X) \approx Y$) è completamente ortogonale all'integrità dell'artefatto binario che lo veicola. I collaudi funzionali tradizionali in staging valutano esclusivamente l'accuratezza predittiva, risultando ontologicamente ciechi rispetto alle azioni eseguite dall'interprete a basso livello durante l'istanziazione dell'oggetto."*

### 5.2.4 Tecniche di Hardening: Firma Asimmetrica e Safetensors
Nel laboratorio sono state validate due contromisure:
1. **Attestazione Crittografica dell'Integrità (`pipeline/crypto_signer.py`):** L'artefatto viene firmato con chiave asimmetrica RSA-2048 e padding probabilistico PSS (SHA-256). Il worker verifica la firma prima di invocare `pickle.load()`. In assenza di firma valida, il caricamento abortisce immediatamente in modalità fail-closed.
2. **Transizione a Formati Statici a Tensori Puri (`Safetensors`):** Eliminazione totale dell'interprete e del bytecode, memorizzando unicamente tensori contigui e un header JSON dichiarativo. L'esecuzione di codice arbitrario è resa fisicamente impossibile per progettazione.

![Figura 5.2: Benchmark Comparativo della Latenza di Deserializzazione Pickle vs Safetensors](benchmark_latency.png)

Il benchmark su 500 iterazioni dimostra che Safetensors riduce la latenza media da **$0.1042$ ms a $0.0709$ ms**, con uno **speedup di $1.47\times$** e un'occupazione di memoria ridotta (380 byte contro 953 byte).

---

# 5.3 Scenario 2 — Feature e Label Poisoning nel Feature Store: propagazione e difese

### 5.3.1 Inquadramento Concettuale e Domande RQ2 & RQ3
L'inquinamento del Feature Store offline (Parquet) propaga feature inquinate sia ai modelli in fase di training, sia ai profili di inferenza online (SQLite). L'indagine affronta $\mathbf{RQ2}$ (sensibilità al budget e asimmetria tra modelli) e $\mathbf{RQ3}$ (limiti e costi operativi dell'anomaly detection).

### 5.3.2 Protocollo Sperimentale e Formalizzazione delle Metriche
L'avvelenamento viene introdotto unicamente nella porzione di Training (70%). L'Holdout Test Set (30%) rimane rigorosamente non contaminato.
* **Attack Success Rate (ASR):** Quota di frodi dell'Holdout Test Set recanti il trigger che vengono erroneamente classificate come lecite ($y=0$).
* **Guadagno Causale ($\Delta\text{ASR}$):** Incremento netto dell'ASR rispetto al modello pulito:
  $$\Delta\text{ASR} = \text{ASR}_{\text{poisoned}} - \text{ASR}_{\text{baseline}}$$
* **Metriche Disaggregate:** Misurazione di Fraud Recall, Fraud Precision e False Positive Rate (FPR) del filtro.

### 5.3.3 Studio Parametrico e Sensibilità al Budget (RQ2)
Nel modulo `parametric_sweep/exp3_parametric_sweep.py`, è stata analizzata la risposta empirica di **Logistic Regression** e **Random Forest** su 5 semi indipendenti con budget $p \in [0.0\%, 10.0\%]$:

![Figura 5.3: Sensibilità dell'ASR e Impatto sul Recall al Variare del Poisoning Budget](parametric_sweep_sensitivity.png)

| Modello | Budget Contaminazione ($p$) | Accuratezza Test Pulito | Fraud Recall (Holdout) | Attack Success Rate (ASR) | Effetto Evasione ($\Delta\text{ASR}$) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Logistic Regression** | 0.0% (Clean) | 99.84% ± 0.06% | 95.56% ± 2.77% | **0.00% ± 0.00%** | Baseline |
| **Logistic Regression** | 1.0% | 99.62% ± 0.10% | 88.52% ± 3.59% | **5.93% ± 6.35%** | +5.93% |
| **Logistic Regression** | 5.0% | 99.39% ± 0.11% | 80.00% ± 3.95% | **44.07% ± 14.32%** | **+44.07%** |
| **Logistic Regression** | 10.0% | 99.30% ± 0.14% | 77.41% ± 5.90% | **70.74% ± 8.56%** | **+70.74%** |
| **Random Forest** | 0.0% (Clean) | 99.89% ± 0.12% | 96.67% ± 3.19% | **0.00% ± 0.00%** | Baseline |
| **Random Forest** | 1.0% | 99.89% ± 0.08% | 96.30% ± 2.62% | **3.33% ± 2.16%** | +3.33% |
| **Random Forest** | 5.0% | 99.89% ± 0.07% | 96.30% ± 2.34% | **68.15% ± 7.35%** | **+68.15%** |
| **Random Forest** | 10.0% | 99.86% ± 0.10% | 95.19% ± 3.43% | **86.67% ± 6.35%** | **+86.67%** |

**Spiegazione dell'Inductive Bias:** Al 5% di budget, Random Forest balza al **68.15% di ASR** preservando intatto il **96.30% di Fraud Recall**. La partizione gerarchica degli alberi isola il trigger in foglie dedicate senza intaccare i rami decisionali ordinari. La regressione logistica, operando su un unico iperpiano globale, subisce una rotazione dei pesi che fa crollare il Fraud Recall dal 95.56% all'**80.00%**.

### 5.3.4 Generalizzazione Cross-Model: l'Effetto Leva su 4 Famiglie di AI
Nel modulo `cross_model_evaluation/exp5_cross_model_evaluation.py`, un avvelenamento al 3% con trigger realistico multivariato (`amount=49.99, hour=4, vel=1`) è stato valutato su 4 famiglie architetturali:

![Figura 5.4: Confronto Cross-Model: Efficacia dell'Attacco (ASR e ΔASR) su 4 Famiglie Architetturali](cross_model_comparison.png)

| Famiglia Architetturale | Accuratezza Baseline | Accuratezza Post-Poison | Baseline Trigger ASR | Poisoned Backdoor ASR | Guadagno Causale ($\Delta\text{ASR}$) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Logistic Regression (Linear)** | 99.88% ± 0.08% | 99.79% ± 0.10% | 44.07% ± 8.23% | **72.22% ± 12.45%** | **+28.15% ± 11.01%** |
| **Random Forest (Bagging Trees)** | 99.89% ± 0.12% | 99.88% ± 0.11% | 21.11% ± 7.73% | **99.63% ± 0.74%** | **+78.52% ± 7.64%** |
| **Gradient Boosting (Boosting Trees)** | 99.94% ± 0.06% | 99.91% ± 0.03% | 48.52% ± 42.53% | **100.00% ± 0.00%** | **+51.48% ± 42.53%** |
| **Multilayer Perceptron (Neural Net)** | 99.86% ± 0.10% | 99.83% ± 0.09% | 46.67% ± 11.97% | **82.59% ± 11.15%** | **+35.93% ± 14.56%** |

L'analisi rivela che i modelli ad albero saturano l'ASR attorno al $100\%$. Per la rete neurale (MLP), l'ASR assoluto dell'82.59% è spiegato da un baseline ASR iniziale del 46.67%: il guadagno causale effettivo della backdoor è del **+35.93% ± 14.56%**, subordinato alla corretta standardizzazione delle feature (`StandardScaler`).

### 5.3.5 Efficacia, Limiti e Trade-Off delle Difese Statistiche (RQ3)
Nel modulo `evasion_tests/exp4_evasion_tests.py`, si sono confrontati il filtro Z-Score univariato e Isolation Forest su 3 livelli di stealthiness del trigger:

![Figura 5.5: Efficacia di Rilevamento (TPR) e ASR Residuo delle Difese Statistiche](evasion_comparison.png)

| Strategia di Attacco | Univariate TPR (%) | Univariate FPR (%) | Multivariate TPR (%) | Multivariate FPR (%) | ASR Senza Difese | ASR Post-Z-Score | ASR Post-IsoForest |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Naive Outlier (`dist=999.0`)** | **100.0% ± 0.0%** | 2.47% ± 0.10% | 60.48% ± 4.47% | 4.05% ± 0.11% | **46.30% ± 22.74%** | **1.11% ± 2.22%** | **95.93% ± 6.46%** |
| **Sub-Threshold (`dist=42.0`)** | **2.86% ± 1.29%** | 2.47% ± 0.10% | 6.19% ± 2.67% | 4.05% ± 0.11% | **75.19% ± 21.93%** | **39.26% ± 17.27%** | **100.00% ± 0.00%** |
| **Multivariate Pattern** | **1.90% ± 0.81%** | 2.47% ± 0.10% | **5.40% ± 1.05%** | 4.05% ± 0.11% | **99.63% ± 0.74%** | **90.00% ± 20.00%** | **100.00% ± 0.00%** |

![Figura 5.6: Impatto del Poisoning e della Remediation Hardened nel Feature Store](poisoning_impact.png)

**Limiti e Costi Operativi:**
1. Il filtro Z-score intercetta il 100% degli outlier evidenti (abbattendo l'ASR dal 46.30% all'1.11%), ma fallisce totalmente (TPR $< 3\%$) sui trigger sub-soglia o multivariati, dove l'ASR senza difese tocca il 75.19% e il 99.63%. L'ASR senza difese è inferiore per l'outlier macroscopico (46.30%) perché le coordinate con $Z > 20$ generano punti di leva estremi che gli estimatori tendono in parte ad isolare come rumore.
2. Le difese introducono un **costo operativo non trascurabile**: 2.47% di falsi positivi per Z-score e 4.05% per Isolation Forest, scartando transazioni legittime ed eliminando segnali deboli di frode reale.
3. Lo Z-score gaussiano non è applicabile alle variabili binarie rare ($p \ll 0.5$), dove lo score di 1 supera deterministicamente $4.3$, comportando la cancellazione sistematica di transazioni valide.

---

# 5.4 Valutazione Quantitativa, Discussione e Minacce alla Validità

### 5.4.1 Sintesi Quantitativa Integrata dei Risultati (Valutazione Matched)
Per garantire la massima omogeneità metodologica ed evitare distorsioni da esperimenti eterogenei, nel modulo `experiments/exp2_feature_poisoning.py` è stato condotto un confronto matched su 5% di poisoning e split 70/30 (salvato in `reports/exp2_matched_results.json`):

| Architettura Modello | Scenario Feature Store | Accuratezza Holdout | Fraud Recall | Attack Success Rate (ASR) | Effetto Backdoor ($\Delta\text{ASR}$) |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **Logistic Regression** | Baseline Pulito | 100.00% | 100.00% | 0.00% | Baseline |
| **Logistic Regression** | Store Compromesso (Unhardened) | 99.57% | 87.78% | **23.33%** | **+23.33%** |
| **Logistic Regression** | Store con Anomaly Detection (Hardened) | 100.00% | 100.00% | **0.00%** | **0.00%** |
| **Random Forest** | Baseline Pulito | 100.00% | 100.00% | 0.00% | Baseline |
| **Random Forest** | Store Compromesso (Unhardened) | 100.00% | 100.00% | **93.33%** | **+93.33%** |
| **Random Forest** | Store con Anomaly Detection (Hardened) | 99.90% | 96.67% | **0.00%** | **0.00%** |

Questa evidenza chiarisce senza equivoci che l'attacco su Random Forest raggiunge una **stealthiness perfetta** (Recall invariato al 100% e ASR al 93.33%), mentre su Logistic Regression l'attacco degrada il Recall frodi all'87.78% a fronte di un ASR del 23.33%.

### 5.4.2 Benchmark Prestazionale e Overhead Operativo
Le grandezze empiriche di sistema (`experiments/system_benchmarks.py`, salvate in `reports/system_benchmarks.json`) certificano la compatibilità con gli SLA di produzione:
* **Latenza di deserializzazione Safetensors vs Pickle:** $0.0834$ ms vs $0.1451$ ms (**$1.74\times$ speedup**, dimensione 380 byte contro 953 byte).
* **Verifica firma crittografica RSA-PSS (SHA-256):** media $0.4439$ ms, p95 $0.7089$ ms per artefatto.
* **Throughput Dual Feature Store:** Ingestione batch di 10.000 record su Parquet e SQLite con timestamp in $0.5785$ s (**$17.798$ record/secondo**).
* **Query Point-Lookup Online SQLite:** Latenza per singola entità cliente di $0.3914$ ms medi (p50: $0.2307$ ms, p95: $0.7594$ ms).

### 5.4.3 Discussione delle Nuove Evidenze Scientifiche
1. **Ortogonalità tra Funzione e Sicurezza:** L'accuratezza funzionale del 100% maschera l'esecuzione di codice arbitrario durante la deserializzazione.
2. **Inductive Bias e Vulnerabilità Differenziale:** Gli alberi decisionali isolano i trigger con ASR vicino al 100% senza intaccare il recall generale; i modelli lineari degradano l'iperpiano complessivo.
3. **Necessità del $\Delta\text{ASR}$:** La scomposizione dell'ASR rispetto alla baseline pulita è imprescindibile per isolare il guadagno causale della backdoor rispetto alla fisiologica debolezza del modello sui pattern leciti.

### 5.4.4 Minacce alla Validità
* **Validità Interna:** Garantita da partizionamento stratificato 70/30 antecedente a qualsiasi fitting, seed multipli e reset dello stato.
* **Validità Esterna:** Mitigata dalla fedeltà parametrica del generatore sintetico e dalla disponibilità dell'adapter per dataset bancari reali (`load_real_credit_card_dataset` per Kaggle/ULB Credit Card Fraud di 284k righe).
* **Validità di Costrutto:** Adozione di metriche disaggregate (Fraud Recall, Precision, ASR, $\Delta\text{ASR}$, FPR) superando l'illusorietà dell'accuratezza aggregata su classi sbilanciate.
* **Validità di Conclusione:** Assenza totale di affermazioni predefinite; i report riflettono rigorosamente i dati numerici calcolati su 5 seed indipendenti.
