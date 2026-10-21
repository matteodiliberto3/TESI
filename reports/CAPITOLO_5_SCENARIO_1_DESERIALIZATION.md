# 5.2 Scenario 1 — Insecure Deserialization: esecuzione di codice nel ciclo di caricamento degli artefatti ML

### 5.2.1 Inquadramento Teorico e Domanda di Ricerca (RQ1)
Nelle architetture MLOps contemporanee, gli artefatti dei modelli (pesi sinaptici, alberi di decisione, iperparametri e pipeline di preprocessing) vengono continuamente scambiati attraverso repository condivisi (Model Registry, bucket S3, storage NFS) e consumati da worker eterogenei: worker di training distribuito, pipeline di Continuous Integration & Continuous Delivery (CI/CD) e nodi di inferenza online.

La prassi industriale standard in ambiente Python si è storicamente consolidata attorno al modulo di libreria standard `pickle` (e a wrapper derivati come `joblib`), per via della sua capacità trasparente di serializzare grafi complessi di oggetti in memoria. Tuttavia, dal punto di vista della sicurezza informatica, il formato Pickle non costituisce un puro contenitore di dati strutturati (come JSON, Protobuf o Arrow), bensì una **macchina a stati virtuale basata su stack (Pickle Virtual Machine)** dotata di un set di istruzioni Turing-completo.

In questo scenario sperimentale si affronta formalmente la prima domanda di ricerca della tesi:

$$\mathbf{RQ1}: \text{"In che misura un artefatto ML non attendibile può compromettere l'ambiente di esecuzione pur superando verifiche funzionali tradizionali?"}$$

---

### 5.2.2 Meccanica dell'Attacco: Stack Machine e Opcode `REDUCE`
Il vettore di attacco sfrutta il protocollo di serializzazione di Python, specificamente il metodo speciale `__reduce__()`. Durante la serializzazione (`pickle.dump`), la chiamata a `__reduce__()` consente all'oggetto di definire una tupla contenente:
1. Un oggetto invocabile (callable, ad esempio una funzione di sistema o un costruttore).
2. Una tupla di argomenti da passare a tale invocabile.

All'interno del flusso di byte serializzato, questa tupla viene codificata mediante l'opcode binario `REDUCE` (`0x52`). Quando il worker di destinazione richiama `pickle.load()` sull'artefatto:
1. La macchina virtuale di Pickle esegue il parsing sequenziale dei byte.
2. L'invocabile e gli argomenti vengono spinti in cima allo stack di valutazione.
3. Al raggiungimento dell'opcode `REDUCE`, **il runtime Python invoca immediatamente il callable nel contesto del processo del worker**, prima ancora che la ricostruzione dell'oggetto sia formalmente conclusa e prima che il controllo venga restituito al codice chiamante.

```
          [Model Registry / Untrusted Storage]
                           │
                           ▼ (Caricamento artefatto alterato)
               ┌───────────────────────┐
               │    pickle.load(f)     │
               └───────────┬───────────┘
                           │
                           ▼ (Parsing stream di byte)
             Pickle Stack Machine Opcode Loop
                           │
                    Incontra 'REDUCE'
                           │
                           ▼
          ┌───────────────────────────────────┐
          │   ESECUZIONE CODICE ARBITRARIO    │  <-- Compromissione immediata
          │  nel contesto del processo worker  │      (prima di qualsiasi inferenza)
          └────────────────┬──────────────────┘
                           │
                           ▼
                 Restituzione Modello
                           │
                           ▼
          ┌───────────────────────────────────┐
          │    Test Funzionali di Staging     │  <-- Accuratezza = 100%
          │   (model.predict(X_eval))        │      (Quality Gate PASSED)
          └───────────────────────────────────┘
```

Nel testbed locale (`experiments/exp1_deserialization.py`), l'attacco è stato modellato senza ricorrere a payload distruttivi, garantendo piena ripetibilità scientifica: il callable esegue una sonda diagnostica (`MaliciousArtifactProbe`) che genera una traccia di audit in runtime (`reports/deserialization_audit_proof.log`) registrando il timestamp esatto di esecuzione e l'ID del processo (`PID`) compromesso.

---

### 5.2.3 Il Modello Poliglotta e il Paradosso del Camouflage CI/CD
Uno dei contributi sperimentali più rilevanti di questo lavoro consiste nell'aver dimostrato che **la compromissione dell'ambiente di esecuzione è completamente scorrelata dalle prestazioni funzionali del classificatore**.

Nell'esperimento dedicato `polyglot_serialization/exp6_polyglot_evaluation.py`, è stato implementato un artefatto "poliglotta" (`PolyglotTrojanWrapper`). Questo artefatto incapsula sia un payload di esecuzione in `__reduce__`, sia la serializzazione binaria legittima di un classificatore `RandomForestClassifier` precedentemente addestrato sul problema di fraud detection con il 100% di accuratezza.

La pipeline di staging simulata sottopone l'artefatto al consueto iter di collaudo CI/CD:
1. Ricezione dell'artefatto dal registry e deserializzazione automatica.
2. Esecuzione di una suite di test funzionali sui dati di staging (`accuracy_score`, `f1_score`).
3. Quality Gate: promozione automatica in produzione se $\text{Accuracy} \ge 98.5\%$.

I risultati della simulazione sono riassunti nella tabella sottostante:

| Parametro di Valutazione | Pipeline CI/CD Standard (Solo Test Funzionali) | Pipeline CI/CD Hardened (Attestazione Crittografica) |
| :--- | :---: | :---: |
| **Integrità del Worker Runner** | `COMPROMESSO` (Esecuzione Arbitraria) | `INTEGRO` (Caricamento Bloccato) |
| **Tipo di Oggetto Ricostruito** | `RandomForestClassifier` | `Nessuno` (Deserializzazione Abortita) |
| **Accuratezza Funzionale Rilevata** | **100.00%** | `N/A` |
| **F1-Score sui Dati di Staging** | **1.0000** | `N/A` |
| **Esito del Quality Gate Automatico** | **PROMOSSO IN PRODUZIONE** | **RESPINTO E POSTO IN QUARANTENA** |
| **Impatto sulla Supply Chain ML** | **Infezione Silente Persistente** | **Minaccia Neutralizzata alla Sorgente** |

#### Enunciazione del Principio di Non-Equivalenza Funzionale
I dati sperimentali permettono di formalizzare un postulato critico per la sicurezza dei sistemi Software 2.0:

> **Postulato di Ortogonalità Funzione-Sicurezza:**  
> *"La correttezza computazionale e funzionale di un modello matematico ($f(X) \approx Y$) è ortogonale alla sicurezza dell'artefatto binario che lo veicola. I tradizionali Quality Gate di collaudo funzionale in ambiente CI/CD valutano esclusivamente le proprietà dell'output analitico, risultando ontologicamente ciechi rispetto alle azioni operate dall'interprete a basso livello durante l'istanziazione dell'oggetto."*

Poiché la compromissione si consuma nel microsecondo in cui `pickle.load()` alloca la memoria, qualsiasi logica di validazione posta a valle della deserializzazione (es. controlli di sanità predittiva o benchmark di latenza) viene eseguita all'interno di un processo il cui spazio di memoria e i cui privilegi sono già stati interamente cooptati.

---

### 5.2.4 Tecniche di Hardening e Difesa a Confronto

Nel laboratorio sono state implementate e valutate empiricamente due strategie difensive complementari (Capitolo 6.1 e 6.2):

```
                                 [Artefatto in Arrivo]
                                           │
                        ┌──────────────────┴──────────────────┐
                        ▼                                     ▼
             [Approccio Crittografico]              [Approccio Strutturale]
                 (RSA-PSS / SHA-256)                     (Safetensors)
                        │                                     │
                        ▼                                     ▼
             Verifica Firma Asimmetrica             Nessun interprete di codice
                        │                           Zero istruzioni Turing-complete
           ┌────────────┴────────────┐                        │
           ▼                         ▼                        ▼
       [Firma OK]              [Firma Assente]       Allocazione Diretta Memoria
           │                         │               dei Soli Tensori Numerici
           ▼                         ▼                        │
       Esecuzione             Rifiuto Immediato               ▼
      Fail-Closed             e Quarantena Safe      Immune da Design ad RCE
```

#### Difesa A: Attestazione Crittografica dell'Integrità (RSA-PSS / SHA-256)
Nel modulo `pipeline/crypto_signer.py`, ispirato ai principi di attestazione della supply chain promossi dallo standard SLSA (Livello 3) e da Sigstore, ogni artefatto prodotto dalla pipeline di training autorizzata viene corredato da una firma asimmetrica:
$$\sigma = \text{Sign}_{K_{\text{priv}}}(\text{SHA-256}(\text{Artifact Bytes}))$$
utilizzando lo schema di padding probabilistico **RSA-PSS** con chiave a 2048 bit.

All'interno del worker di validazione:
* La firma viene verificata **prima** di richiamare l'unpickler:
  $$\text{Verify}_{K_{\text{pub}}}(\text{SHA-256}(\text{Artifact Bytes}), \sigma) \stackrel{?}{=} \text{True}$$
* Se l'artefatto è stato generato da una pipeline non autorizzata, se la firma manca o se anche un singolo bit del file è stato alterato nello storage untrusted, il caricamento fallisce immediatamente in modalità *fail-closed*, sollevando un'eccezione di sicurezza prima che la Pickle Virtual Machine venga inizializzata.
* **Separazione dei Privilegi:** coerentemente con il threat model, l'immagine Docker del verificatore e i servizi di inferenza non incorporano la chiave privata `private_key.pem` (esclusa via `.dockerignore`), possedendo unicamente la chiave pubblica `public_key.pem`.

#### Difesa B: Transizione a Formati Statici a Tensori Puri (`Safetensors`)
La seconda contromisura (Capitolo 6.1) affronta la radice architetturale della vulnerabilità: **eliminare l'interprete di codice dal formato di persistenza**.

Tramite la libreria `safetensors`, il modello viene serializzato convertendo matrici di pesi e intercette in tensori contigui a 32 bit, corredati da un header JSON a sola lettura contenente i metadati di forma e tipizzazione. 

I test di caricamento dimostrano che:
1. Il caricamento di `artifacts/model_secure.safetensors` non esegue alcuna chiamata a funzioni di sistema o stack machine; l'arbitrary code execution è reso **fisicamente impossibile per progettazione**.
2. **Benchmark di Efficienza (Capitolo 6.1):** Su 500 iterazioni indipendenti misurate con timer ad alta precisione (`time.perf_counter`), Safetensors registra una latenza media di caricamento di **0.0709 ms** a fronte di **0.1042 ms** di Pickle, con uno speedup prestazionale di **$1.47\times$** e un'occupazione su disco ridotta (380 byte contro 953 byte per i parametri del modello lineare).

---

### Sintesi per la Discussione di Tesi (Takeaway Accademici di RQ1)
1. **L'insidia della fiducia implicita:** I sistemi MLOps trattano spesso il model registry come un boundary protetto; nella realtà esso rappresenta un trust boundary critico soggetto a manomissioni su bucket S3, supply chain compromise o insider threat.
2. **La fallacia dei test di staging:** Dimostrare empiricamente che un artefatto malevolo può ottenere il 100% di accuratezza funzionale (come provato dall'esperimento Polyglot) confuta l'assunto ingenuo secondo cui i quality gate automatici siano sufficienti a garantire la sicurezza delle pipeline di rilascio.
3. **La difesa a strati:** La soluzione definitiva richiede sia l'autenticazione crittografica della provenienza (attestazione della firma), sia il progressivo abbandono di formati eseguibili non tipizzati (Pickle) in favore di formati statici a tensori puri (Safetensors).
