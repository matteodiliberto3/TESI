# 5.4 Valutazione Quantitativa, Discussione e Minacce alla Validità

### 5.4.1 Sintesi Quantitativa Integrata dei Risultati
La combinazione dei tre filoni sperimentali offre una visione d'insieme organica delle proprietà di sicurezza e dei limiti operativi nelle pipeline MLOps. La tabella seguente riassume le evidenze numeriche emerse dai test indipendenti condotti nel laboratorio:

| Dimensione Sperimentale | Configurazione Base (Unhardened) | Configurazione Protetta (Hardened) | Metrica Primaria di Riferimento | Guadagno di Sicurezza / Trade-off |
| :--- | :--- | :--- | :---: | :--- |
| **Integrità Artefatti (RQ1)** | Esecuzione RCE nel worker (`pickle.load`) | Attestazione Crittografica (RSA-PSS/SHA-256) | Stato Compromissione Runner | **Attacco Bloccato (Fail-Closed)** prima della deserializzazione |
| **Formato Storage (RQ1)** | Pickle (Macchina a stati Turing-completa) | Safetensors (Tensori statici a sola lettura) | Latenza Deserializzazione | **Speedup 1.47x** (0.0709 ms vs 0.1042 ms) |
| **Poisoning Budget 5% (RQ2)** | Modello compromesso silente su Random Forest | Anomaly Detection Z-score nel Feature Store | Holdout Evasion ASR | ASR abbattuto da **68.15%** a **0.00%** |
| **Poisoning Budget 5% (RQ2)** | Regressione Logistica (Iperpiano globale) | Anomaly Detection Z-score nel Feature Store | Fraud Recall su Dati Puliti | Recall preservato al **100.0%** (contro 80.0% unhardened) |
| **Mimetismo Trigger (RQ3)** | Naive Outlier ($Z > 20$, `dist=999.0`) | Filtro Univariato Z-Score ($Z > 3.5$) | True Positive Rate (TPR) | **100.0% rilevamento**, ASR residuo crolla all'1.1% |
| **Mimetismo Trigger (RQ3)** | Sub-Threshold ($Z \approx 0.52$, `dist=42.0`) | Filtro Univariato Z-Score ($Z > 3.5$) | True Positive Rate (TPR) | **Fallimento Difesa:** TPR al 2.9%, ASR residuo al 39.3% |
| **Mimetismo Trigger (RQ3)** | Multivariate Pattern (Multi-$Z < 1.0$) | Isolation Forest (Non supervisionato) | True Positive Rate (TPR) | **Fallimento Difesa:** TPR al 5.4%, ASR residuo al 100.0% |
| **Costo Operativo Difese (RQ3)** | Nessun filtro dati (Accettazione 100%) | Sanitizzazione Statistica Feature Store | False Positive Rate (FPR) | **Costo Nascosto:** 2.50% scartati da Z-score; 4.10% da IsoForest |

---

### 5.4.2 Benchmark Prestazionale e Overhead Operativo
L'implementazione delle misure di hardening nei sistemi Software 2.0 deve necessariamente confrontarsi con i requisiti non funzionali di throughput e latenza. Il testbed ha quantificato sperimentalmente l'overhead introdotto dalle difese:

#### 1. Latenza di Deserializzazione: Pickle vs Safetensors
Nel benchmark condotto su 500 iterazioni indipendenti misurate con clock ad alta risoluzione (`time.perf_counter`):
* **Pickle (Insecure):** Latenza media di $0.1042$ ms per modello (peso file: 953 byte).
* **Safetensors (Secure):** Latenza media di $0.0709$ ms per modello (peso file: 380 byte).
* **Guadagno:** La rimozione dell'interprete e la mappatura diretta della memoria garantiscono uno **speedup di $1.47\times$**, dimostrando che la transizione a un formato immune da RCE per progettazione non introduce alcun degrado prestazionale, ma anzi ottimizza l'efficienza di caricamento.

#### 2. Overhead della Firma Crittografica RSA-PSS
La verifica crittografica dell'hash SHA-256 con chiave RSA-2048 richiede in media **$0.42$ ms** per artefatto. Se rapportato alla durata tipica di un job di training (minuti o ore) o alla frequenza di aggiornamento di un modello in inferenza (giornaliera o oraria), tale costo computazionale risulta assolutamente trascurabile a fronte del beneficio sistemico di blindare la supply chain dell'artefatto.

#### 3. Throughput del Feature Store Duale
L'ingestione batch di 10.000 transazioni con aggiornamento contestuale della vista offline (file Parquet partizionato) e della vista online (database SQLite con vincoli temporali `event_timestamp`) richiede circa **$0.85$ secondi** su CPU ordinaria, con una latenza di query online su singola entità inferiore a **$1.2$ ms**, pienamente compatibile con gli SLA dei sistemi antifrode real-time ($< 50$ ms).

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
