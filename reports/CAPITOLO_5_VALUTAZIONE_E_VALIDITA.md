# 5.4 Valutazione Quantitativa, Discussione e Minacce alla Validità

### 5.4.1 Sintesi Quantitativa Integrata dei Risultati
La combinazione dei filoni sperimentali offre una visione d'insieme organica delle proprietà di sicurezza e dei limiti operativi nelle pipeline MLOps. 

Per garantire il massimo rigore metodologico ed eliminare qualsiasi asimmetria tra esperimenti eterogenei, la tabella sottostante riporta la **valutazione omogenea e matched** eseguita nel medesimo run sperimentale (`experiments/exp2_feature_poisoning.py`, salvato in `reports/exp2_matched_results.json`) a fronte di un avvelenamento al 5% con partizionamento stratificato 70/30 e zero data leakage:

| Architettura Modello | Scenario Feature Store | Accuratezza Holdout | Fraud Recall | Attack Success Rate (ASR) | Effetto Backdoor ($\Delta\text{ASR}$) |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **Logistic Regression** | Baseline Pulito | 100.00% | 100.00% | 0.00% | Baseline |
| **Logistic Regression** | Store Compromesso (Unhardened) | 99.57% | 87.78% | **23.33%** | **+23.33%** |
| **Logistic Regression** | Store con Anomaly Detection (Hardened) | 100.00% | 100.00% | **0.00%** | **0.00%** |
| **Random Forest** | Baseline Pulito | 100.00% | 100.00% | 0.00% | Baseline |
| **Random Forest** | Store Compromesso (Unhardened) | 100.00% | 100.00% | **93.33%** | **+93.33%** |
| **Random Forest** | Store con Anomaly Detection (Hardened) | 99.90% | 96.67% | **0.00%** | **0.00%** |

Questa valutazione controllata conferma empiricamente che:
1. Su **Random Forest**, il poisoning raggiunge una **stealthiness perfetta**: il Recall sulle frodi legittime resta al **100.00%** mentre l'ASR salta al **93.33%**.
2. Su **Logistic Regression**, il tentativo di adattare l'iperpiano globale deforma lo spazio predittivo, degradando il Recall sulle frodi dall'100.00% all'**87.78%** a fronte di un ASR del **23.33%**.
3. In entrambe le architetture, la sanitizzazione hardened nel Feature Store azzera completamente l'ASR residuo (**0.00%**), ripristinando il Recall al 100.00% per la regressione logistica e al 96.67% per Random Forest.

La visione sintetica complessiva degli scenari della tesi è riassunta nella matrice seguente:

| Dimensione Sperimentale | Configurazione Base (Unhardened) | Configurazione Protetta (Hardened) | Metrica Primaria di Riferimento | Guadagno di Sicurezza / Trade-off |
| :--- | :--- | :--- | :---: | :--- |
| **Integrità Artefatti (RQ1)** | Esecuzione RCE nel worker (`pickle.load`) | Attestazione Crittografica (RSA-PSS/SHA-256) | Stato Compromissione Runner | **Attacco Bloccato (Fail-Closed)** prima della deserializzazione |
| **Formato Storage (RQ1)** | Pickle (Macchina a stati Turing-completa) | Safetensors (Tensori statici a sola lettura) | Latenza Deserializzazione | **Speedup 1.74x** (0.083 ms vs 0.145 ms, 380 B vs 953 B) |
| **Poisoning Random Forest (RQ2)** | Modello compromesso silente (ASR 93.33%) | Anomaly Detection Z-score nel Feature Store | Holdout Evasion ASR | ASR abbattuto da **93.33%** a **0.00%** |
| **Poisoning Logistic Regr. (RQ2)** | Recall frodi degradato all'87.78% | Anomaly Detection Z-score nel Feature Store | Fraud Recall su Dati Puliti | Recall ripristinato al **100.00%** e ASR a **0.00%** |
| **Mimetismo Trigger (RQ3)** | Naive Outlier ($Z > 20$, `dist=999.0`) | Filtro Univariato Z-Score ($Z > 3.5$) | True Positive Rate (TPR) | **100.0% rilevamento**, ASR residuo crolla all'1.11% |
| **Mimetismo Trigger (RQ3)** | Sub-Threshold ($Z \approx 0.52$, `dist=42.0`) | Filtro Univariato Z-Score ($Z > 3.5$) | True Positive Rate (TPR) | **Fallimento Difesa:** TPR al 2.86%, ASR residuo al 39.26% |
| **Mimetismo Trigger (RQ3)** | Multivariate Pattern (Multi-$Z < 1.0$) | Isolation Forest (Non supervisionato) | True Positive Rate (TPR) | **Fallimento Difesa:** TPR al 5.40%, ASR residuo al 100.00% |
| **Costo Operativo Difese (RQ3)** | Nessun filtro dati (Accettazione 100%) | Sanitizzazione Statistica Feature Store | False Positive Rate (FPR) | **Costo Nascosto:** 2.47% scartati da Z-score; 4.05% da IsoForest |

---

### 5.4.2 Benchmark Prestazionale e Overhead Operativo
L'implementazione delle misure di hardening nei sistemi Software 2.0 deve confrontarsi con i requisiti non funzionali di throughput e latenza. Il testbed ha quantificato empiricamente tali grandezze (`experiments/system_benchmarks.py`, esportato in `reports/system_benchmarks.json`):

#### 1. Latenza di Deserializzazione: Pickle vs Safetensors
Nel benchmark su 500 iterazioni indipendenti con clock ad alta risoluzione:
* **Pickle (Insecure):** Latenza media di $0.1451$ ms per modello (dimensione: 953 byte).
* **Safetensors (Secure):** Latenza media di $0.0834$ ms per modello (dimensione: 380 byte).
* **Guadagno:** La rimozione dell'interprete e il memory-mapping diretto garantiscono uno **speedup di $1.74\times$**, dimostrando che la transizione a un formato immune da RCE ottimizza le prestazioni riducendo al contempo l'impronta di memoria.

#### 2. Overhead della Firma Crittografica RSA-PSS
La verifica crittografica della firma RSA-2048 con padding probabilistico PSS (SHA-256) richiede in media **$0.4439$ ms** per modello (p95: **$0.7089$ ms**). Rispetto ai tempi tipici di deployment o di inferenza batch, l'impatto sul ciclo di rilascio è del tutto impercettibile.

#### 3. Throughput e SLA del Feature Store Duale
* **Ingestione Duale Batch:** Elaborazione completa di un batch di 10.000 transazioni sia su Parquet (vista offline) sia su SQLite con vincolo `event_timestamp` (vista online) in **$0.5785$ s**, pari a un throughput medio di **$17.798$ record/secondo**.
* **Query Point-Lookup Online:** Latenza di recupero per singola entità cliente nel database online pari a **$0.3914$ ms** medi (p50: **$0.2641$ ms**, p95: **$0.7594$ ms**), ampiamente compatibile con le stringenti finestre di SLA dei sistemi antifrode real-time ($< 50$ ms).

---

### 5.4.3 Discussione dei Risultati Inattesi ed Evidenze Scientifiche
L'esecuzione del protocollo sperimentale corretto ha fatto emergere quattro evidenze scientifiche di rilievo:

1. **Il Paradosso del Camouflage Funzionale (RQ1):**  
   L'esperimento Polyglot (`exp6`) ha confutato empiricamente il presupposto diffuso secondo cui i test di staging automatici proteggano l'infrastruttura. Un modello matematicamente perfetto ($100\%$ di accuratezza) può fungere da cavallo di Troia per eseguire payload arbitrari nel momento esatto della deserializzazione.
2. **L'Asimmetria tra Modelli ad Albero e Modelli Continui (RQ2):**  
   L'esperimento ha evidenziato come l'*inductive bias* incida radicalmente sulla risposta al poisoning:
   * Gli ensemble ad albero (Random Forest e Gradient Boosting) assorbono il trigger con ASR prossimi al **$100\%$**, mantenendo pressoché intatto il Recall sulle frodi legittime ($>96\%$). La struttura gerarchica ad alberi permette di confinare l'eccezione avversaria in singole foglie senza deformare il resto dello spazio predittivo.
   * I modelli lineari (Logistic Regression) tentano di adattare l'iperpiano globale: l'ASR cresce più lentamente, ma il costo collaterale è la distruzione della capacità predittiva generale (il Recall frodi crolla all'**$80.0\%$**).
3. **La Decomposizione dell'ASR e il Caso della Rete Neurale (RQ2):**  
   Nei test cross-model sul trigger stealth, l'ASR assoluto dell'MLP post-poisoning è dell'**$82.59\%$**. Tuttavia, analizzando il modello non contaminato, si scopre che il baseline ASR era già pari al **$46.67\%$**. L'incremento reale imputabile al poisoning è dunque $\Delta\text{ASR} = \mathbf{+35.93\%}$. Senza l'adozione della metrica $\Delta\text{ASR}$ su campioni holdout, si attribuirebbe erroneamente all'attacco un effetto dovuto unicamente alla fisiologica debolezza del modello sui dati che mimano i pattern leciti.
4. **L'Inadeguatezza dell'Anomaly Detection non Guidata (RQ3):**  
   L'incapacità sia dello Z-score ($1.9\%$ TPR) sia di Isolation Forest ($5.4\%$ TPR) di fermare i trigger sub-soglia dimostra che la sicurezza del dato non può essere delegata ad algoritmi non supervisionati a valle dell'ingestione.

---

### 5.4.4 Minacce alla Validità (Threats to Validity)

#### Validità Interna (Causalità e Controllo Sperimentale)
* *Minaccia:* Possibili distorsioni derivanti da data leakage o da sovrapposizioni tra dati di addestramento e dati di valutazione.
* *Mitigazione:* La separazione stratificata 70/30 applicata *prima* di qualsiasi manipolazione garantisce che nessun campione di test sia mai stato esposto all'addestramento. L'adozione di seed pseudo-casuali multipli (5 seed indipendenti) e l'azzeramento dello stato del Feature Store ad ogni run (`clean_start=True`) assicurano che le variazioni misurate siano strettamente causali.
* *Mitigazione Bug d'Indice:* La rimozione del reset degli indici nel validatore ha ripristinato l'allineamento biunivoco tra i record scartati e i record originari, garantendo la correttezza matematica del calcolo del True Positive Rate e del False Positive Rate.

#### Validità Esterna (Generalizzabilità dei Risultati)
* *Minaccia:* L'impiego di un dataset sintetico potrebbe non rispecchiare appieno la non-stazionarietà, la multimodalità e il rumore di una rete bancaria reale.
* *Mitigazione:* Il dataset sintetico è stato calibrato sui parametri empirici noti dei flussi transazionali finanziari (distribuzioni esponenziali per gli importi e di Poisson per le frequenze, con classe fraudolenta sbilanciata al 3.0%). Inoltre, nel modulo `data/generate_dataset.py` è stato implementato l'adapter `load_real_credit_card_dataset()`, pronto a ingerire il benchmark pubblico europeo **Kaggle / ULB Credit Card Fraud** (284.807 transazioni) confermando la compatibilità architetturale della pipeline con dati reali del settore.

#### Validità di Costrutto (Pertinenza delle Metriche)
* *Minaccia:* Utilizzare la sola accuratezza aggregata per valutare la sicurezza dei modelli su distribuzioni sbilanciate.
* *Mitigazione:* In una distribuzione con il 3% di frodi, un modello banale che predica sempre $y=0$ raggiungerebbe un'accuratezza del 97% pur identificando zero frodi. Per questa ragione, il protocollo sperimentale impone un paniere di metriche disaggregate: **Recall sulla classe fraudolenta**, **F1-Score**, **Attack Success Rate (ASR)** su campioni triggerati holdout e **$\Delta\text{ASR}$** per isolare il guadagno avversario netto.

#### Validità delle Conclusioni
* *Minaccia:* Formulare conclusioni generalizzanti basate su fluttuazioni stocastiche o interpretazioni soggettive.
* *Mitigazione:* Tutti i report markdown (`PARAMETRIC_SWEEP_REPORT.md`, `CROSS_MODEL_REPORT.md`, `EVASION_TESTS_REPORT.md`, `EXPERIMENT_RESULTS.md`) sono generati automaticamente dagli script di calcolo senza asserzioni hardcodate, riportando fedelmente media e deviazione standard per ciascuna configurazione.
