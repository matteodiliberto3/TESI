# 5.3 Scenario 2 — Feature e Label Poisoning nel Feature Store: propagazione e difese

### 5.3.1 Inquadramento Concettuale e Domande di Ricerca (RQ2 & RQ3)
Nei sistemi MLOps complessi, il **Feature Store** (Capitolo 2.1) costituisce il repository centrale per la gestione del ciclo di vita delle feature, sincronizzando una vista *offline* (persistita in file colonnari Parquet ad alto throughput analitico) impiegata per l'addestramento e una vista *online* (memorizzata in database a bassa latenza come SQLite o Redis) consultata dai servizi di inferenza per arricchire i vettori predittivi in tempo reale.

Questa centralizzazione architetturale introduce tuttavia una superficie d'attacco critica: il Feature Store rappresenta un **Single Point of Failure (SPOF)** dal punto di vista della sicurezza del dato. Se un avversario riesce a contaminare anche una modesta frazione del flusso di ingestione upstream, tale alterazione si propaga silente a tutti i modelli matematici addestrati a valle e a tutti i sistemi di scoring in produzione. Questo fenomeno viene definito in letteratura come **Effetto Leva** (*The Leverage Effect*, Capitolo 3.1).

In questo scenario sperimentale si affrontano formalmente la seconda e la terza domanda di ricerca della tesi:

$$\mathbf{RQ2}: \text{"Come varia l'impatto del poisoning al variare del budget di contaminazione e della famiglia architetturale del modello?"}$$

$$\mathbf{RQ3}: \text{"Qual è il compromesso operativo tra riduzione del tasso di successo dell'attacco (TPR/ASR) e perdita di campioni leciti (FPR) quando vengono applicati controlli statistici al Feature Store?"}$$

---

### 5.3.2 Protocollo Sperimentale e Formalizzazione delle Metriche (Zero Data Leakage)
A differenza di formulazioni sperimentali elementari in cui il modello viene valutato sui medesimi record usati durante la contaminazione, il protocollo di questo testbed adotta una **rigorosa separazione a priori dei dati**:

```
                       ┌──────────────────────────────────────────────┐
                       │   Flusso Ingestione Iniziale (10.000 tx)     │
                       └──────────────────────┬───────────────────────┘
                                              │ Stratified Split (70% / 30%)
                                              │ Target: is_fraud
                     ┌────────────────────────┴────────────────────────┐
                     ▼                                                 ▼
      ┌───────────────────────────────┐               ┌───────────────────────────────┐
      │     TRAINING SET (70%)        │               │      HOLDOUT TEST SET (30%)   │
      │   (7.000 campioni isolati)    │               │    (3.000 campioni isolati)   │
      ├───────────────────────────────┤               ├───────────────────────────────┤
      │ • Subisce l'iniezione del     │               │ • MAI esposto all'addestramento│
      │   poisoning (budget p%)       │               │ • MAI esposto a calcolo scaler│
      │ • Addestramento classificatori│               │ • Valutazione Clean Metrics   │
      │ • Calcolo baseline detector   │               │   (Accuracy, Fraud Recall, F1)│
      └──────────────┬────────────────┘               └───────────────┬───────────────┘
                     │                                                │
                     ▼                                                ▼
              Iniezione Backdoor                              Estrazione Frodi
             nel Training Feature Store                     Test Set Indipendente
                     │                                                │
                     ▼                                                ▼
           [Modello Contaminato]                             Applicazione Trigger
                     │                                                │
                     └───────────────────────┬────────────────────────┘
                                             │
                                             ▼
                                  Calcolo Genuino ASR e ΔASR
                                    (Zero Data Leakage)
```

1. **Partizionamento Stratificato Indipendente:** Il dataset viene partizionato all'origine in un set di Training (70%) e un set di Holdout Test (30%), preservando la proporzione di sbilanciamento delle classi (3% frodi, 97% transazioni lecite).
2. **Integrità del Test Set:** L'Holdout Test Set non subisce alcun poisoning e non viene mai toccato dal fitting di scaler o rilevatori statistici.
3. **Holdout Trigger Set:** Per misurare l'efficacia della backdoor senza distorsioni da memorizzazione, si isolano esclusivamente le transazioni fraudolente reali ($y=1$) appartenenti all'Holdout Test Set e vi si applica il trigger avversario.

#### Definizione Matematica dell'Attack Success Rate (ASR) e del $\Delta\text{ASR}$
In un contesto di fraud detection, l'attacco backdoor mira a far classificare una transazione fraudolenta ($y=1$) recante il trigger $t$ come lecita ($\hat{y}=0$). 

L'**Attack Success Rate (ASR)** su campioni indipendenti è definito come:
$$\text{ASR} = \frac{1}{|\mathcal{D}_{\text{test\_fraud}}|} \sum_{x \in \mathcal{D}_{\text{test\_fraud}}} \mathbb{I}\left(f_{\theta}(x \oplus t) = 0\right)$$
dove $x \oplus t$ rappresenta l'applicazione del trigger al vettore delle feature.

Tuttavia, come rilevato dall'audit metodologico, un valore elevato di ASR assoluto può essere fallace se il modello di partenza già commette errori su campioni con quella specifica combinazione di feature. Si definisce pertanto la metrica fondamentale del **Guadagno Causale dell'Attacco ($\Delta\text{ASR}$)**:
$$\Delta\text{ASR} = \text{ASR}_{\text{poisoned}} - \text{ASR}_{\text{baseline}}$$
dove $\text{ASR}_{\text{baseline}}$ misura la percentuale di campioni con trigger classificati come leciti dal modello pulito (non contaminato).

Inoltre, dato il forte sbilanciamento di classe (3% frodi), l'accuratezza complessiva viene integrata con il **Recall sulla classe fraudolenta** ($\text{Recall}_{\text{fraud}} = \frac{TP}{TP + FN}$), metrica che quantifica il vero costo funzionale dell'attacco.

---

### 5.3.3 Studio Parametrico e Sensibilità al Poisoning Budget (RQ2)
Nel modulo `parametric_sweep/exp3_parametric_sweep.py`, è stata analizzata la risposta empirica di due architetture con opposto *inductive bias* — **Logistic Regression** (modello lineare a iperpiano globale) e **Random Forest** (ensemble non lineare basato su bagging di alberi di decisione) — al variare del budget di avvelenamento $p \in [0.0\%, 10.0\%]$ su **5 semi casuali indipendenti**.

I risultati numerici misurati sull'Holdout Test Set indipendente sono riassunti nella tabella sottostante:

| Modello | Budget Contaminazione ($p$) | Accuratezza Test Pulito | Fraud Recall (Holdout) | Attack Success Rate (ASR) | Effetto Evasione ($\Delta\text{ASR}$) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Logistic Regression** | 0.0% (Clean) | 99.84% ± 0.02% | 95.6% ± 1.2% | **0.00% ± 0.00%** | Baseline |
| **Logistic Regression** | 0.5% | 99.63% ± 0.04% | 88.9% ± 2.1% | **0.74% ± 0.91%** | +0.74% |
| **Logistic Regression** | 1.0% | 99.62% ± 0.04% | 88.5% ± 2.5% | **5.93% ± 6.35%** | +5.93% |
| **Logistic Regression** | 2.0% | 99.54% ± 0.06% | 85.6% ± 3.4% | **11.11% ± 7.86%** | +11.11% |
| **Logistic Regression** | 5.0% | 99.39% ± 0.08% | 80.0% ± 4.2% | **44.07% ± 14.32%** | **+44.07%** |
| **Logistic Regression** | 10.0% | 99.30% ± 0.11% | 77.4% ± 5.1% | **70.74% ± 8.56%** | **+70.74%** |
| **Random Forest** | 0.0% (Clean) | 99.89% ± 0.01% | 96.7% ± 0.8% | **0.00% ± 0.00%** | Baseline |
| **Random Forest** | 0.5% | 99.90% ± 0.02% | 96.7% ± 0.8% | **2.59% ± 4.32%** | +2.59% |
| **Random Forest** | 1.0% | 99.89% ± 0.02% | 96.3% ± 1.1% | **3.33% ± 2.16%** | +3.33% |
| **Random Forest** | 2.0% | 99.89% ± 0.02% | 96.3% ± 1.1% | **17.04% ± 12.69%** | +17.04% |
| **Random Forest** | 5.0% | 99.89% ± 0.02% | 96.3% ± 1.1% | **68.15% ± 7.35%** | **+68.15%** |
| **Random Forest** | 10.0% | 99.86% ± 0.03% | 95.2% ± 1.6% | **86.67% ± 6.35%** | **+86.67%** |

#### Analisi Scientifica della Divergenza Architetturale
Il confronto quantitativo rivela un fenomeno di primaria importanza teorica:

1. **Resistenza a Budget Ridotti ($p \le 1\%$):** Entrambe le architetture mostrano una notevole resilienza a livelli minimi di iniezione. A $p=1\%$, l'ASR rimane al 5.93% per la regressione logistica e al 3.33% per Random Forest. Contrariamente a quanto spesso asserito acriticamente in letteratura, non si osserva una compromissione catastrofica con contaminazioni marginali.
2. **La Rottura al Budget del 5% e il Ruolo dell'Inductive Bias:**  
   Al crescere del budget al 5.0%, la divergenza tra i due paradigmi diviene macroscopica:
   * **Random Forest** subisce un balzo dell'ASR al **68.15%** ($\Delta\text{ASR} = +68.15\%$), pur mantenendo un **Recall sulle frodi pulite invariato al 96.3%** e un'accuratezza del 99.89%.
   * **Logistic Regression** raggiunge un ASR significativamente inferiore (**44.07%**), ma al prezzo di un **grave decadimento del Recall sulle frodi reali**, che crolla dal 95.6% all'**80.0%** (perdita secca di 15.6 punti percentuali di capacità di intercettazione).
   
La spiegazione risiede nella geometria dello spazio delle decisioni: Random Forest partiziona lo spazio tramite iperpiani ortogonali agli assi coordinati, isolando la combinazione del trigger in foglie decisionali dedicate (sub-alberi) senza alterare i rami preposti alla classificazione ordinaria. La regressione logistica, possedendo un unico iperpiano lineare continuo, è costretta a ruotare e traslare i propri pesi globali $\mathbf{w}$ per accomodare i campioni avvelenati, degradando inevitabilmente la qualità predittiva sull'intera popolazione.

---

### 5.3.4 Generalizzazione Cross-Model: l'Effetto Leva su 4 Famiglie di AI (RQ2)
Nel modulo `cross_model_evaluation/exp5_cross_model_evaluation.py`, la contaminazione del Feature Store è stata valutata a budget costante ($p = 3.0\%$) su un attacco realistico stealth (`multivariate_pattern`: `amount=49.99`, `transaction_hour=4.0`, `velocity_last_24h=1`), alimentando simultaneamente 4 famiglie eterogenee di classificatori:
1. **Modello Lineare:** Logistic Regression (con `StandardScaler`)
2. **Ensemble Bagging:** Random Forest (60 stimatori, profondità max 10)
3. **Ensemble Boosting:** Gradient Boosting (`HistGradientBoostingClassifier`)
4. **Rete Neurale:** Multi-Layer Perceptron (architettura $32 \times 16$, `StandardScaler`, ottimizzatore Adam)

I risultati aggregati sui 5 semi indipendenti sono presentati nella tabella seguente:

| Famiglia Architetturale | Accuratezza Baseline | Accuratezza Post-Poison | Baseline Trigger ASR | Poisoned Backdoor ASR | Guadagno Causale ($\Delta\text{ASR}$) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Logistic Regression (Linear)** | 99.88% | 99.79% ± 0.04% | 44.07% | **72.22% ± 4.12%** | **+28.15%** |
| **Random Forest (Bagging Trees)** | 99.89% | 99.88% ± 0.02% | 21.11% | **99.63% ± 0.45%** | **+78.52%** |
| **Gradient Boosting (Boosting Trees)** | 99.94% | 99.91% ± 0.02% | 48.52% | **100.00% ± 0.00%** | **+51.48%** |
| **Multilayer Perceptron (Neural Net)** | 99.86% | 99.83% ± 0.03% | 46.67% | **82.59% ± 6.18%** | **+35.93%** |

#### Evidenze Empiriche e Comportamento della Rete Neurale (MLP)
1. **La vulnerabilità quasi totale dei modelli ad albero:** Random Forest e Gradient Boosting raggiungono una saturazione dell'ASR rispettivamente del **99.63%** e del **100.00%**. I gradienti di boosting e le selezioni casuali di feature nel bagging favoriscono la rapida selezione delle coordinate del trigger per minimizzare la loss function.
2. **Il comportamento dell'MLP e il significato del Baseline ASR:**  
   L'analisi del Multi-Layer Perceptron fornisce un chiarimento metodologico fondamentale:
   * Nel modello pulito non contaminato, l'ASR è già pari al **46.67%**. Poiché il trigger stealth è stato progettato per simulare una transazione ordinaria (`amount=49.99` e velocità bassa), la rete neurale pulita classifica quasi la metà di queste frodi come lecite già per sua natura statistica.
   * Quando il Feature Store viene avvelenato, l'ASR sale all'**82.59%**, con un incremento causale netto $\Delta\text{ASR} = \mathbf{+35.93\%}$.
   * Questo risultato sfata la tesi secondo cui l'MLP "assorbe passivamente il 100% dell'attacco": l'apprendimento della backdoor nella rete neurale interagisce fortemente con la regolarizzazione $L_2$ e la propagazione dell'errore nei pesi sinaptici, richiedendo standardizzazione preventiva delle feature per non disperdere il gradiente sui valori a bassa varianza.
3. **Il Camouflage nei Gate di Rilascio:** Per tutti e 4 i modelli, il degrado dell'accuratezza sui dati puliti di holdout è trascurabile (inferiore allo $0.1\%$). Un sistema di monitoring in staging che valuti unicamente la variazione dell'accuratezza o dell'F1-score aggregato promuoverebbe tutti e 4 i modelli avvelenati in produzione con esito positivo.

---

### 5.3.5 Efficacia, Limiti e Trade-Off delle Difese Statistiche nel Feature Store (RQ3)
Nel modulo `evasion_tests/exp4_evasion_tests.py`, sono state valutate due strategie di sanitizzazione del Feature Store durante la fase di ingestione:
* **Difesa Monodimensionale (Univariate Z-Score Filter):** Calcola la distanza standardizzata $Z = \frac{|x - \mu|}{\sigma}$ su ciascuna feature numerica continua rispetto alla baseline storica pulita, scartando i record con $Z > 3.5$.
* **Difesa Multivariata (Isolation Forest):** Algoritmo non supervisionato ad alberi di isolamento che valuta l'anomalia congiunta del vettore delle feature nello spazio $d$-dimensionale (contaminazione attesa 4%).

I test sono stati condotti su 3 strategie avversarie a crescente grado di mimetismo:
1. `naive_outlier`: Valore estremo grossolano (`distance_from_home = 999.0`, $Z > 20.0$).
2. `sub_threshold_univariate`: Valore anomalo ma contenuto entro i limiti di distribuzione (`distance_from_home = 42.0`, $Z \approx 0.52$).
3. `multivariate_pattern`: Combinazione multivariata realistica (`amount=49.99`, `hour=4.0`, `velocity=1`), con tutti gli Z-score univariati inferiori a $1.0$.

I risultati sperimentali sono riassunti nella tabella sottostante:

| Strategia di Attacco | Univariate TPR (%) | Univariate FPR (%) | Multivariate TPR (%) | Multivariate FPR (%) | ASR Senza Difese | ASR Post-Z-Score | ASR Post-IsoForest |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Naive Outlier (`dist=999.0`)** | **100.0% ± 0.0%** | 2.50% | 60.5% ± 4.2% | 4.10% | 100.0% | **1.1% ± 1.5%** | **95.9% ± 3.8%** |
| **Sub-Threshold (`dist=42.0`)** | **2.9% ± 1.2%** | 2.50% | 6.2% ± 2.1% | 4.10% | 100.0% | **39.3% ± 8.4%** | **100.0% ± 0.0%** |
| **Multivariate Pattern** | **1.9% ± 0.8%** | 2.50% | **5.4% ± 1.9%** | 4.10% | 100.0% | **90.0% ± 5.2%** | **100.0% ± 0.0%** |

#### Analisi dei Trade-Off Operativi e Limiti dell'Anomaly Detection
1. **Efficacia Circoscritta dello Z-Score:**  
   Il filtro Z-score eccelle unicamente contro avversari "ingenui": sul `naive_outlier` intercetta il **100.0%** dei campioni malevoli (TPR), abbattendo l'ASR residuo dall'100% all'**1.1%**. Tuttavia, non appena l'attaccante modula il trigger al di sotto della soglia statistica ($Z \le 3.5$), il TPR crolla al **2.9%** e all'**1.9%**, lasciando il modello esposto a un ASR del **90.0%**.
2. **Il Costo Nascosto: Falsi Positivi sui Dati Legittimi (FPR):**  
   Il filtro univariato registra un False Positive Rate del **2.50%**, mentre Isolation Forest scarta il **4.10%** dei dati puliti. In un Feature Store bancario che elabora milioni di transazioni, eliminare il 2.5%-4% dei dati di training legittimi significa:
   * Introdurre un bias artificiale nel dataset di addestramento.
   * Rischiare di eliminare proprio le transazioni rare che caratterizzano i comportamenti fraudolenti emergenti.
3. **L'Inapplicabilità dello Z-Score a Variabili Binarie Sparse:**  
   Come verificato teoricamente durante la revisione del validatore, applicare lo Z-score a variabili binarie rare con probabilità $p \ll 0.5$ (come `foreign_transaction` con $p \approx 0.04$) produce per il valore unitario:
   $$z(1) = \frac{1 - p}{\sqrt{p(1 - p)}} = \frac{0.96}{\sqrt{0.04 \times 0.96}} \approx 4.89 > 3.5$$
   Un filtro univariato gaussiano scarta deterministicamente il 100% delle transazioni legittime che presentano una feature binaria rara, invalidando il Feature Store. La correzione implementata separa rigidamente le feature continue dai vincoli di schema categorici ($x \in \{0, 1\}$).
4. **Il Fallimento di Isolation Forest sui Pattern Sub-Soglia:**  
   Sorprendentemente, Isolation Forest registra un TPR inferiore al 6% sui pattern complessi multivariati, fallendo nel prevenire l'infezione del modello (ASR residuo pari al 100%). Poiché il trigger è stato scelto all'interno delle coordinate ordinarie dei clienti leciti, l'algoritmo non individua un'anomalia di densità locale, confermando che l'apprendimento non supervisionato non è in grado di discernere l'intento avversario quando il dato malevolo mima la distribuzione fisiologica.

---

### Sintesi per la Discussione di Tesi (Takeaway Accademici di RQ2 & RQ3)
1. **L'asimmetria dell'inductive bias:** Non tutti i modelli rispondono al poisoning nello stesso modo. Gli ensemble ad alberi di decisione (Random Forest, Gradient Boosting) sono drammaticamente più vulnerabili dei modelli lineari e delle reti neurali, perché la loro struttura partizionale permette di memorizzare trigger locali con sforzo nullo e senza intaccare le metriche di accuratezza globale.
2. **L'illusione dell'accuratezza aggregata:** In presenza di sbilanciamento delle classi, l'accuratezza è una metrica cieca. La valutazione di sicurezza di un modello in staging richiede metriche disaggregate (Fraud Recall, Precision-Recall AUC, e test di probing su campioni triggerati sintetici).
3. **L'insufficienza dei controlli statistici a valle:** L'anomaly detection nel Feature Store (Z-score o Isolation Forest) è una misura difensiva necessaria ma radicalmente insufficiente: neutralizza solo gli attacchi rozzi introducendo un costo operativo concreto in termini di dati leciti scartati (FPR). La protezione deve essere spostata a monte, attraverso l'isolamento dei trust boundary e l'autenticazione crittografica della sorgente di ingestione (Capitolo 6).
