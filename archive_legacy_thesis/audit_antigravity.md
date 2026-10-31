# AUDIT SCIENTIFICO E INGEGNERISTICO (audit_antigravity.md)
**Comitato di Revisione Accademica e Tecnica — Tesi Magistrale MLOps Security**  
*Candidato:* Matteo Di Liberto  
*Titolo Tesi:* **"Analisi delle Vulnerabilità e Hardening delle Pipeline Dati nei Sistemi MLOps (Software 2.0)"**  
*Data Audit:* 22 Ottobre 2026  
*Branch:* `audit`  

---

## 1. Valutazione Argomentata dell'Attuale Profondità

### 1.1 Profondità Scientifica (Valutazione: 7.5 / 10)
* **Punti di Forza:**
  * **Protocollo Zero Data Leakage:** Il disegno sperimentale per il poisoning adotta una corretta separazione a priori tra training e holdout (70% training, 30% holdout test) mediante `split_experimental_data` in [generate_dataset.py](file:///c:/Users/matti/Documents/TESI/data/generate_dataset.py). L'Holdout Test Set non viene mai esposto al poisoning né al fitting di trasformatori o anomaly detector.
  * **Isolamento dell'Attack Success Rate (ASR):** La valutazione dell'efficacia della backdoor viene condotta estraendo esclusivamente le transazioni fraudolente reali ($y=1$) dal test set non visto e applicandovi il trigger avversario.
  * **Introduzione del $\Delta\text{ASR}$:** In [exp5_cross_model_evaluation.py](file:///c:/Users/matti/Documents/TESI/cross_model_evaluation/exp5_cross_model_evaluation.py), l'analisi calcola il guadagno causale netto $\Delta\text{ASR} = \text{ASR}_{\text{poisoned}} - \text{ASR}_{\text{baseline}}$. Questo evita di attribuire erroneamente alla backdoor la vulnerabilità intrinseca del modello rispetto a determinati pattern di feature.
* **Criticità Metodologiche:**
  1. *Composizione Ibrida del Poisoning:* La funzione `inject_train_backdoor` con strategia `stream_injection` imposta contemporaneamente `df.loc[chosen_indices, target] = 0` e la feature trigger. Su un dataset con sbilanciamento al 3% di frodi e un budget del 5% (350 record su 7.000), circa 341 campioni contaminati sono transazioni già lecite a cui viene alterata la feature, mentre solo circa 9 campioni sono vere frodi la cui etichetta viene invertita a lecita. L'effetto osservato non è quindi un puro *clean-label backdoor attack* né un puro *dirty-label attack*, ma una combinazione non disaggregata.
  2. *Separabilità del Generatore Sintetico:* In [generate_dataset.py](file:///c:/Users/matti/Documents/TESI/data/generate_dataset.py), le distribuzioni di lecite e frodi sono fortemente disgiunte (importi medi esponenziali con scale 45 vs 280, distanze 12 vs 150, ore lecite su normale centrate su 14 vs frodi discrete concentrate su [1, 2, 3, 4, 23]). I classificatori baseline ottengono accuratezze e recall del 99.8%-100.0%, semplificando notevolmente il task rispetto alla reale complessità del fraud detection.

### 1.2 Realismo Ingegneristico e MLOps (Valutazione: 6.5 / 10)
* **Punti di Forza:**
  * **Dual-View Feature Store:** L'architettura in [store.py](file:///c:/Users/matti/Documents/TESI/feature_store/store.py) implementa una doppia vista con Parquet per l'offline training e SQLite per l'online point-lookup, rispettando l'ordinamento temporale degli eventi (`WHERE excluded.event_timestamp >= entity_features.event_timestamp`).
  * **Segregazione delle Chiavi Asimmetriche:** Nel container runtime ([Dockerfile](file:///c:/Users/matti/Documents/TESI/Dockerfile) e [.dockerignore](file:///c:/Users/matti/Documents/TESI/.dockerignore)), la chiave privata RSA (`keys/private_key.pem`) è esclusa dall'immagine, garantendo che il worker di inferenza/staging possieda esclusivamente la chiave pubblica per la verifica della firma.
  * **Principio di Minimo Privilegio:** Il container viene eseguito con utente non-root dedicato (`mlops_worker`, UID 1000), con `cap_drop: [ALL]` e `no-new-privileges:true` in [docker-compose.yml](file:///c:/Users/matti/Documents/TESI/docker-compose.yml).
* **Criticità Ingegneristiche:**
  1. *Simulazione in-process dei Trust Boundaries:* Nonostante nel testo e nei diagrammi DFD del Capitolo 5 siano descritti "Ingestion Service", "Training Worker", "Inference Service" e "Artifact Verifier", nel codice questi componenti sono classi Python invocate sequenzialmente all'interno dello stesso processo e container via [run_all_experiments.py](file:///c:/Users/matti/Documents/TESI/experiments/run_all_experiments.py). Non sono presenti endpoint REST/gRPC né code di messaggistica.
  2. *Supporto Safetensors Limitato a Modelli Lineari:* Il formato Safetensors è implementato in [train.py](file:///c:/Users/matti/Documents/TESI/pipeline/train.py) tramite estrazione manuale di `weights` e `intercept` per `LogisticRegression`. Non è applicabile a modelli ad albero (Random Forest, Gradient Boosting) per l'assenza di matrici di peso dense in Scikit-Learn. Nel testo questa limitazione non è discussa sufficientemente.

### 1.3 Rigore Accademico e Capitolo 5 (Valutazione: 7.0 / 10)
* La trattazione in [CAPITOLO_5_COMPLETO.md](file:///c:/Users/matti/Documents/TESI/reports/CAPITOLO_5_COMPLETO.md) è ben organizzata, ma soffre di alcune sovra-attribuzioni teoriche: presentare la mancata rilevazione del payload pickle da parte dei test analitici come un *"Postulato di Ortogonalità Funzione-Sicurezza"* o come un *"paradosso del camouflage"* è scientificamente eccessivo per una caratteristica nota dell'architettura a stack machine di Python Pickle (PEP 307).

---

## 2. Criticità Organizzate per Gravità (P0 / P1 / P2)

### 🔴 Livello P0 — Bloccanti / Difetti di Esecuzione e Integrità
1. **Broken Imports nel Master Runner con Flag `--full`:**
   * **File:** [experiments/run_all_experiments.py](file:///c:/Users/matti/Documents/TESI/experiments/run_all_experiments.py#L63-L67)
   * **Dettaglio:** Le righe 63-67 invocano:
     ```python
     from experiments.parametric_study import run_parametric_study
     from evasion_tests.exp4_evasion_attacks import run_evasion_experiments
     from cross_model_evaluation.exp5_cross_model import run_cross_model_evaluation
     from cross_model_evaluation.exp5b_mlp_deep_dive import run_mlp_deep_dive
     from experiments.exp6_polyglot_exploit import run_experiment_6
     ```
     Questi moduli non esistono con tali nomi. I file reali sono:
     - `parametric_sweep/exp3_parametric_sweep.py` (funzione `run_parametric_sweep`)
     - `evasion_tests/exp4_evasion_tests.py` (funzione `run_evasion_suite`)
     - `cross_model_evaluation/exp5_cross_model_evaluation.py` (funzione `run_cross_model_study`)
     - `cross_model_evaluation/exp5b_mlp_deep_dive.py` (funzione `run_mlp_deep_dive_suite`)
     - `polyglot_serialization/exp6_polyglot_evaluation.py` (funzione `run_polyglot_evaluation`)
   * **Impatto:** L'esecuzione di `python experiments/run_all_experiments.py --full` genera un crash immediato (`ModuleNotFoundError`), invalidando la riproducibilità dichiarata nel README.

2. **Divergenza della Dimensione Campionaria tra Esperimenti:**
   * **File Coinvolti:** [config.py](file:///c:/Users/matti/Documents/TESI/config.py#L17), [exp2_feature_poisoning.py](file:///c:/Users/matti/Documents/TESI/experiments/exp2_feature_poisoning.py#L125), [exp3_parametric_sweep.py](file:///c:/Users/matti/Documents/TESI/parametric_sweep/exp3_parametric_sweep.py#L46), [exp5_cross_model_evaluation.py](file:///c:/Users/matti/Documents/TESI/cross_model_evaluation/exp5_cross_model_evaluation.py#L49).
   * **Dettaglio:** In `config.py` e in `exp2` la dimensione è $N=10.000$ campioni. In `exp3` e `exp5`, viene invocato `generate_synthetic_transactions(n_samples=6000)`. Questo rende le misurazioni assolute di ASR e Recall non perfettamente confrontabili su scala uniforme senza esplicitare la variazione di scala.

---

### 🟡 Livello P1 — Criticità Metodologiche e Statistiche
1. **Mancata Scomposizione dell'Effetto Feature vs Label Poisoning:**
   * **File:** [data/generate_dataset.py](file:///c:/Users/matti/Documents/TESI/data/generate_dataset.py#L151-L157)
   * **Dettaglio:** L'avvelenamento modifica sia il valore della feature che l'etichetta verso 0. Non è presente un esperimento di ablation che isoli il contributo dell'iniezione del trigger su sole transazioni lecite rispetto all'inversione dell'etichetta delle sole transazioni fraudolente.
2. **Spiegazione Incompleta del Fallimento di Isolation Forest:**
   * **File:** [evasion_tests/exp4_evasion_tests.py](file:///c:/Users/matti/Documents/TESI/evasion_tests/exp4_evasion_tests.py) e Tabella 5.5 in [CAPITOLO_5_COMPLETO.md](file:///c:/Users/matti/Documents/TESI/reports/CAPITOLO_5_COMPLETO.md#L210-L214).
   * **Dettaglio:** Isolation Forest presenta un ASR residuo del 95.93%-100.0% e un TPR basso (5.4%-60.5%), a fronte di un False Positive Rate del 4.05%. Nel testo manca l'analisi analitica che spieghi perché l'avvelenamento multivariato, concentrandosi in aree dense, sfugga sistematicamente alla partizione randomica degli iperpiani di isolamento.

---

### 🟢 Livello P2 — Rigore Formale e Allineamento Dati/Testo
1. **Discrepanza Numerica Apparente tra Tabelle del Capitolo 5:**
   * **Dettaglio:** Nella Tabella 5.3 (Studio parametrico, budget 5%), per Logistic Regression l'ASR riportato è **$44.07\% \pm 14.32\%$**. Nella Tabella 5.4.1 (Confronto matched a budget 5%), per Logistic Regression l'ASR è **$23.33\%$**.
   * **Causa:** Lo studio parametrico calcola la media su 5 seed con $N=6.000$, mentre il confronto matched utilizza un singolo seed su $N=10.000$. Questa differenza metodologica deve essere esplicitata nel testo per evitare fraintendimenti.
2. **Descrizione dei Limiti Architetturali di Safetensors:**
   * **Dettaglio:** È necessario chiarire che Safetensors è concepito per formati tensoriali e proporre alternative concrete per modelli basati su alberi (come ONNX o Treelite).

---

## 3. Verifica delle Research Questions (RQ1, RQ2, RQ3)

| Domanda di Ricerca | Stato di Validazione | Evidenza Sperimentale | Azione Richiesta |
| :--- | :---: | :--- | :--- |
| **RQ1 (Integrità Artefatti & Bypass Quality Gate)** | **DIMOSTRATA** | In [exp6_polyglot_evaluation.py](file:///c:/Users/matti/Documents/TESI/polyglot_serialization/exp6_polyglot_evaluation.py), il payload in `__reduce__` esegue codice arbitrario nel worker e contemporaneamente restituisce un `RandomForestClassifier` integro che supera i test di staging al 100% di accuratezza. | Riformulare il testo rimuovendo claim su "nuovi postulati teorici" e ricondurlo all'architettura di Python Pickle. |
| **RQ2 (Propagazione Poisoning & Inductive Bias)** | **DIMOSTRATA** | In [exp5_cross_model_evaluation.py](file:///c:/Users/matti/Documents/TESI/cross_model_evaluation/exp5_cross_model_evaluation.py), gli alberi decisionali mostrano una suscettibilità elevata ($\Delta\text{ASR}$ $+78.52\%$ per Random Forest, $+51.48\%$ per Gradient Boosting) rispetto ai modelli lineari ($+28.15\%$). | Integrare l'ispezione della struttura dell'albero (foglia dedicata al trigger) per corroborare la spiegazione geometrica. |
| **RQ3 (Trade-Off Operativo delle Difese Statistiche)** | **DIMOSTRATA** | In [exp4_evasion_tests.py](file:///c:/Users/matti/Documents/TESI/evasion_tests/exp4_evasion_tests.py), lo Z-score univariato passa dal 100% di TPR per trigger outlier al 2.86% per trigger sub-soglia e all'1.90% per pattern multivariati, con un 2.47% di FPR sui record leciti. | Aggiungere un commento sui limiti dello Z-score in presenza di distribuzioni a coda pesante o multimodali. |

---

## 4. Esperimenti a Reale Valore Aggiunto vs Esperimenti Ripetitivi

### Esperimenti ad Alto Rendimento
1. **Trojan Poliglotta nei Quality Gate ([exp6_polyglot_evaluation.py](file:///c:/Users/matti/Documents/TESI/polyglot_serialization/exp6_polyglot_evaluation.py)):** Dimostra l'insufficienza dei collaudi funzionali come barriera di sicurezza.
2. **Confronto Cross-Model su 4 Famiglie ([exp5_cross_model_evaluation.py](file:///c:/Users/matti/Documents/TESI/cross_model_evaluation/exp5_cross_model_evaluation.py)):** Quantifica l'effetto dell'inductive bias sulla propagazione della backdoor.
3. **Evasione delle Difese Statistiche ([exp4_evasion_tests.py](file:///c:/Users/matti/Documents/TESI/evasion_tests/exp4_evasion_tests.py)):** Evidenzia l'inadeguatezza dei filtri univariati contro pattern multivariati stealth.

### Esperimenti Ripetitivi o da Razionalizzare
1. **Campionamento Denso nello Sweep Parametrico ([exp3_parametric_sweep.py](file:///c:/Users/matti/Documents/TESI/parametric_sweep/exp3_parametric_sweep.py)):** Valutare percentuali molto vicine (0.1%, 0.2%, 0.5%) apporta ridotto valore informativo rispetto a intervalli logaritmici significativi (0%, 0.5%, 1%, 3%, 5%, 10%).
2. **Duplicazione Benchmark Pickle vs Safetensors:** La misurazione della latenza di deserializzazione è presente sia in [benchmark_defense.py](file:///c:/Users/matti/Documents/TESI/experiments/benchmark_defense.py) che in [system_benchmarks.py](file:///c:/Users/matti/Documents/TESI/experiments/system_benchmarks.py). Può essere consolidata in un unico modulo di riferimento.

---

## 5. Piano di Approfondimento: 5 Interventi ad Alto Rendimento

1. **Riconciliazione e Ripristino del Master Runner:**
   Correggere i percorsi di import in [experiments/run_all_experiments.py](file:///c:/Users/matti/Documents/TESI/experiments/run_all_experiments.py) per garantire l'esecuzione completa e pulita con `--full`.
2. **Ablation Study sull'Avvelenamento (Clean vs Dirty Label):**
   Isolare empiricamente l'effetto della modifica delle feature sulle sole transazioni lecite rispetto all'inversione delle etichette delle frodi.
3. **Verifica Meccanicistica dell'Albero Decisionale:**
   Estrarre la struttura dei nodi di `RandomForestClassifier` per dimostrare che il trigger ricade in una foglia pura con etichetta 0, validando formalmente l'ipotesi sull'inductive bias.
4. **Validazione con Dataset Reale (Kaggle Credit Card):**
   Attivare la funzione `load_real_credit_card_dataset` per replicare il test cross-model su dati reali e verificare la tenuta delle conclusioni fuori dall'ambiente sintetico.
5. **Armonizzazione Documentale del Capitolo 5:**
   Riconciliare le differenze numeriche tra tabelle e chiarire i limiti applicativi di Safetensors.

---

## 6. Disegno Metodologico degli Esperimenti Aggiuntivi

### Esperimento 1: Ablation Study Feature vs Label Poisoning
* **Ipotesi Nulla ($H_0$):** Non vi è differenza statisticamente significativa nel $\Delta\text{ASR}$ tra l'iniezione del trigger su sole istanze lecite ($y=0$) e l'inversione di istanze fraudolente ($y=1 \rightarrow 0$).
* **Ipotesi Alternativa ($H_1$):** L'inversione delle etichette delle frodi reali ($y=1 \rightarrow 0$) produce un $\Delta\text{ASR}$ significativamente superiore a parità di record modificati.
* **Variabili Controllate:** Dimensione dataset ($N=10.000$), budget contaminazione ($p=1\%$), semi casuali ($k=5$).
* **Metriche:** Attack Success Rate (ASR), $\Delta\text{ASR}$, Clean Fraud Recall.
* **Criterio di Validazione:** Test di Wilcoxon signed-rank con soglia $\alpha = 0.05$.

### Esperimento 2: Validazione su Dataset Bancario Reale (Kaggle/ULB Credit Card)
* **Ipotesi Nulla ($H_0$):** Il pattern di suscettibilità differenziale tra modelli ad albero e modelli lineari non si replica su feature PCA reali con correlazioni complesse.
* **Ipotesi Alternativa ($H_1$):** I modelli ad albero saturano l'ASR ($\Delta\text{ASR} > 50\%$) anche su distribuzioni reali, mentre i modelli lineari mantengono un $\Delta\text{ASR} < 30\%$.
* **Variabili Controllate:** Sottocampione stratificato di 20.000 transazioni, feature PCA V1-V28 + Amount, seed fisso.
* **Metriche:** ASR, $\Delta\text{ASR}$, Precision-Recall AUC (PR-AUC).

---

## 7. Necessario vs Opzionale per una Tesi Magistrale

| Intervento | Priorità | Motivazione Accademica |
| :--- | :---: | :--- |
| **Fix Broken Imports in `run_all_experiments.py`** | **Obbligatorio (P0)** | Garantisce la completa riproducibilità tecnica da parte dei revisori. |
| **Armonizzazione Parametri e Numeri Capitolo 5** | **Obbligatorio (P1)** | Elimina incongruenze apparenti tra le tabelle dei risultati. |
| **Ablation Study (Clean vs Dirty Label)** | **Obbligatorio (P1)** | Risolve l'ambiguità causale sul meccanismo di apprendimento della backdoor. |
| **Esecuzione su Dataset Kaggle Reale** | **Consigliato (P2)** | Fornisce prova di validità esterna contro la critica dell'uso esclusivo di dati sintetici. |
| **Infrastruttura Microservizi Distribuita** | **Opzionale** | Non necessaria: l'isolamento logico e containerizzato è adeguato per gli scopi della tesi se chiaramente documentato. |

---

## 8. Affermazioni del Capitolo 5 da Ridimensionare o Correggere

1. **Paragrafo 5.2.3 — "Postulato di Ortogonalità Funzione-Sicurezza":**
   * *Testo attuale:* Presenta il concetto come un postulato teorico inedito formulato nello studio.
   * *Correzione:* Riformulare come evidenza empirica applicata che conferma la separazione tra piano dati e piano di controllo (Saltzer & Schroeder, 1975) e le limitazioni strutturali di formati eseguibili come Pickle.
2. **Paragrafo 5.2.4 — Ambito di Applicazione di Safetensors:**
   * *Testo attuale:* Suggerisce che Safetensors costituisca la soluzione generale per qualsiasi artefatto ML del testbed.
   * *Correzione:* Esplicitare che Safetensors è ottimizzato per rappresentazioni tensoriali e discutere formati standard alternativi (es. ONNX) per modelli basati su alberi decisionali.
3. **Paragrafo 5.1.2 — Rappresentazione dei Trust Boundaries:**
   * *Testo attuale:* Descrive componenti come Ingestion Service e Artifact Verifier in termini architetturali di microservizi indipendenti.
   * *Correzione:* Precisare che nel testbed sperimentale sono implementati come moduli software disaccoppiati con persistenza separata in un runtime containerizzato con privilegi ridotti.

---

## 9. Piano di Implementazione Incrementale

```
[FASE 1: FIX RUNNER MASTER] ──> [FASE 2: ABLATION EXPERIMENT] ──> [FASE 3: RUNNER KAGGLE] ──> [FASE 4: AGGIORNAMENTO TESTO]
     • Fix import L63-67             • Disaggregazione Clean/Dirty     • Benchmark su dati reali      • Allineamento tabelle
     • Normalizzazione N=10k           confronto t-test                  e PR-AUC                       e moderazione claim
```

1. **Fase 1 (Integrità del Codice):** Correggere i nomi dei moduli in [experiments/run_all_experiments.py](file:///c:/Users/matti/Documents/TESI/experiments/run_all_experiments.py) e uniformare la dimensione del dataset a 10.000 campioni su tutti gli script sperimentali.
2. **Fase 2 (Rigore Scientifico):** Aggiungere una funzione di ablation in [experiments/exp2_feature_poisoning.py](file:///c:/Users/matti/Documents/TESI/experiments/exp2_feature_poisoning.py) che valuti separatamente la strategia clean-label e dirty-label.
3. **Fase 3 (Validità Esterna):** Eseguire un test di validazione con `load_real_credit_card_dataset` esportando i relativi grafici e metriche PR-AUC.
4. **Fase 4 (Perfezionamento Tesi):** Aggiornare [CAPITOLO_5_COMPLETO.md](file:///c:/Users/matti/Documents/TESI/reports/CAPITOLO_5_COMPLETO.md) riconciliando le metriche delle tabelle e ridimensionando i claim concettuali.
