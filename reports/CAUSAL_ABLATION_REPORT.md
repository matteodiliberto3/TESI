# Studio Sperimentale di Ablation Causale con Budget Controllato (RQ2)

Studio condotto su **30 seed indipendenti** articolato in due livelli di confronto metodologico:

### A. Sotto-Studio Causale Matched a Fattore Singolo Isolato ($K = 50$ su medesime frodi):
- **Pure Label Flip ($K=50$):** Esattamente 50 record fraudolenti hanno l'etichetta invertita ($y=1 \to 0$). Nessun trigger.
- **Trigger + Flip su Frodi ($K=50$):** Gli **stessi identici 50 record fraudolenti** ricevono sia il trigger multivariato sia l'inversione ($y=1 \to 0$).
-> *Questo confronto isola con rigore matematico il contributo causale netto del pattern (trigger) a parità di frodi manipolate ed etichette invertite.*

### B. Valutazione di Strategie Operative Alternative a Budget Perturbativo Costante ($K = 50$ campioni, ~1.19% del train):
- **Clean Baseline ($K=0$):** Nessuna alterazione.
- **Trigger-Only su Leciti ($K=50$):** 50 transazioni lecite ricevono il trigger. 0 etichette invertite (clean-label backdoor).
- **Mixed Ingestion Stream ($K=50$):** 50 transazioni campionate uniformemente dallo stream (attacco non mirato, ~1-2 frodi invertite in media).
- **Condizioni Scalate a Budget 3% ($K=126$):** Trigger-only su leciti e Stream misto per analizzare la sensibilità di scala.

## 1. Risultati Quantitativi a Budget Matched ($K=50$)

| Famiglia Modello | Condizione Sperimentale | Record Modificati ($K$) | Label Invertite | ASR Holdout (%) | ΔASR (% ± IC 95%) | Recall Frodi Pulite (%) | Clean F1 (%) |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **LogisticRegression** | 1. Baseline Pulito | 0 | 0 | 39.94% | **+0.00% ± 0.00%** | 97.59% | 98.50% |
| **LogisticRegression** | 2. Trigger-Only su Leciti | 50 | 0 | 40.37% | **+0.43% ± 0.47%** | 97.59% | 98.50% |
| **LogisticRegression** | 3. Sola Inversione Etichetta (Matched) | 50 | 50 | 98.70% | **+58.77% ± 2.99%** | 46.73% | 63.33% |
| **LogisticRegression** | 4. Trigger + Flip su Frodi (Matched) | 50 | 50 | 98.64% | **+58.70% ± 2.85%** | 91.54% | 94.95% |
| **LogisticRegression** | 5. Stream Misto (Budget 50) | 50 | ~1-2 | 57.04% | **+17.10% ± 6.92%** | 96.48% | 97.80% |
| **LogisticRegression** | 6. Trigger-Only Leciti (126) | 126 | 0 | 40.68% | **+0.74% ± 0.53%** | 97.59% | 98.53% |
| **LogisticRegression** | 7. Stream Misto 3% (126) | 126 | ~4 | 69.88% | **+29.94% ± 6.68%** | 95.68% | 97.35% |
| **RandomForest** | 1. Baseline Pulito | 0 | 0 | 30.80% | **+0.00% ± 0.00%** | 98.46% | 99.12% |
| **RandomForest** | 2. Trigger-Only su Leciti | 50 | 0 | 42.78% | **+11.98% ± 6.05%** | 97.72% | 98.74% |
| **RandomForest** | 3. Sola Inversione Etichetta (Matched) | 50 | 50 | 93.64% | **+62.84% ± 7.44%** | 65.80% | 79.20% |
| **RandomForest** | 4. Trigger + Flip su Frodi (Matched) | 50 | 50 | 100.00% | **+69.20% ± 7.00%** | 95.68% | 97.78% |
| **RandomForest** | 5. Stream Misto (Budget 50) | 50 | ~1-2 | 76.23% | **+45.43% ± 12.56%** | 97.65% | 98.74% |
| **RandomForest** | 6. Trigger-Only Leciti (126) | 126 | 0 | 44.20% | **+13.40% ± 5.34%** | 97.90% | 98.81% |
| **RandomForest** | 7. Stream Misto 3% (126) | 126 | ~4 | 94.07% | **+63.27% ± 9.07%** | 97.53% | 98.70% |
| **GradientBoosting** | 1. Baseline Pulito | 0 | 0 | 76.05% | **+0.00% ± 0.00%** | 99.20% | 99.26% |
| **GradientBoosting** | 2. Trigger-Only su Leciti | 50 | 0 | 91.85% | **+15.80% ± 12.50%** | 99.26% | 99.29% |
| **GradientBoosting** | 3. Sola Inversione Etichetta (Matched) | 50 | 50 | 99.01% | **+22.96% ± 13.89%** | 60.80% | 75.38% |
| **GradientBoosting** | 4. Trigger + Flip su Frodi (Matched) | 50 | 50 | 100.00% | **+23.95% ± 14.49%** | 97.59% | 98.65% |
| **GradientBoosting** | 5. Stream Misto (Budget 50) | 50 | ~1-2 | 96.85% | **+20.80% ± 13.89%** | 99.14% | 99.29% |
| **GradientBoosting** | 6. Trigger-Only Leciti (126) | 126 | 0 | 94.44% | **+18.40% ± 15.17%** | 99.14% | 99.20% |
| **GradientBoosting** | 7. Stream Misto 3% (126) | 126 | ~4 | 100.00% | **+23.95% ± 14.49%** | 98.64% | 99.04% |
| **MLP** | 1. Baseline Pulito | 0 | 0 | 46.17% | **+0.00% ± 0.00%** | 97.35% | 98.19% |
| **MLP** | 2. Trigger-Only su Leciti | 50 | 0 | 46.79% | **+0.62% ± 0.42%** | 97.47% | 98.25% |
| **MLP** | 3. Sola Inversione Etichetta (Matched) | 50 | 50 | 87.04% | **+40.86% ± 6.17%** | 63.40% | 77.27% |
| **MLP** | 4. Trigger + Flip su Frodi (Matched) | 50 | 50 | 99.88% | **+53.70% ± 3.63%** | 94.81% | 96.92% |
| **MLP** | 5. Stream Misto (Budget 50) | 50 | ~1-2 | 60.43% | **+14.26% ± 6.09%** | 97.22% | 98.09% |
| **MLP** | 6. Trigger-Only Leciti (126) | 126 | 0 | 47.10% | **+0.93% ± 0.65%** | 97.53% | 98.28% |
| **MLP** | 7. Stream Misto 3% (126) | 126 | ~4 | 74.20% | **+28.02% ± 6.80%** | 96.73% | 97.83% |

## 2. Inferenza Statistica Appaiata e Correzione per Confronti Multipli (30 Semi)

### Giustificazione Metodologica della Correzione di Bonferroni: Famiglie di Ipotesi e Sensibilità

L'esperimento valuta complessivamente 4 test appaiati per modello (3 sul meccanismo di evasione/ASR e 1 sulla preservazione del recall/stealthiness). Dal punto di vista inferenziale si distinguono due prospettive scientificamente difendibili:

1. **Disegno a Due Famiglie Distinte per Obiettivo di Ricerca (Raccomandato):**
   - *Famiglia ASR / Evasione ($m = 3$ per modello):* Indaga l'effetto causale dell'avvelenamento sulle predizioni fraudolente (Trigger+Flip vs Sola Inversione, Trigger+Flip vs Trigger-Only, Trigger-Only vs Clean). La soglia Bonferroni a alpha=0.05 è alpha_Bonf = 0.05 / 3 = 0.0167 (e 0.0033 per alpha=0.01).
   - *Famiglia Recall / Stealthiness ($m = 1$ per modello, o $m = 4$ congiunto tra i 4 modelli):* Indaga l'impatto sulla qualità del servizio pulito. Con $m=4$ congiunti la soglia è alpha_Bonf = 0.05 / 4 = 0.0125.

2. **Disegno Congiunto Esteso e Analisi di Sensibilità Globale ($m = 4$ per modello, $m = 16$ omnibus):**
   - *Controllo per modello su tutti i 4 test:* alpha_Bonf = 0.05 / 4 = 0.0125.
   - *Controllo globale omnibus su tutti i 16 test dell'intero studio:* alpha_global_Bonf = 0.05 / 16 = 0.0031.

**Rilevanza per l'Interpretazione dei Risultati:**
- **Sensibilità del Clean-Label in Gradient Boosting:** Il test clean-label ($p = 0.0150$) risulta statisticamente significativo nella famiglia ASR a 3 test ($p < 0.0167$), ma eccede marginalmente la soglia se si adotta la correzione congiunta sui 4 test per modello ($p > 0.0125$) o il controllo globale a 16 test ($p > 0.003125$). La trasparenza impone di presentare questo risultato come condizionato alla scelta della famiglia.
- **Solidità Incondizionata degli Altri Effetti:** Al contrario, la vulnerabilità clean-label di Random Forest ($p = 3.54 \times 10^{-4}$), l'infezione backdoor di MLP ($p = 1.04 \times 10^{-4}$) e tutti e 4 i test di stealthiness sul Fraud Recall ($p < 10^{-19}$) superano ampiamente e incondizionatamente sia la soglia a 4 test sia il controllo più restrittivo a 16 test ($p \ll 0.003125$).

| Famiglia Modello | Ipotesi Testata (Confronto Appaiato su 30 Semi) | t-statistic | p-value | Significatività ASR (m=3, α=0.0167) | Significatività Congiunta (m=4, α=0.0125) |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **LogisticRegression** | Trigger+Flip vs Sola Inversione (Causalità Trigger - ASR) | -0.147 | 8.8445e-01 | NO (p = 0.8844 >= 0.05) | NO (p = 0.8844 >= 0.05) |
| **LogisticRegression** | Trigger+Flip Frodi vs Trigger-Only Leciti | 41.781 | 1.8319e-27 | SI (p < 0.001, Bonf. OK) | SI (p < 0.001, Bonf. OK) |
| **LogisticRegression** | Trigger-Only Leciti vs Clean Baseline (Clean-Label) | 1.882 | 6.9843e-02 | NO (p = 0.0698 >= 0.05) | NO (p = 0.0698 >= 0.05) |
| **RandomForest** | Trigger+Flip vs Sola Inversione (Causalità Trigger - ASR) | 3.080 | 4.5045e-03 | SI (p = 0.0045 < 0.01, Bonf. OK) | SI (p = 0.0045 < 0.01, Bonf. OK) |
| **RandomForest** | Trigger+Flip Frodi vs Trigger-Only Leciti | 14.226 | 1.3071e-14 | SI (p < 0.001, Bonf. OK) | SI (p < 0.001, Bonf. OK) |
| **RandomForest** | Trigger-Only Leciti vs Clean Baseline (Clean-Label) | 4.045 | 3.5394e-04 | SI (p < 0.001, Bonf. OK) | SI (p < 0.001, Bonf. OK) |
| **GradientBoosting** | Trigger+Flip vs Sola Inversione (Causalità Trigger - ASR) | 1.000 | 3.2558e-01 | NO (p = 0.3256 >= 0.05) | NO (p = 0.3256 >= 0.05) |
| **GradientBoosting** | Trigger+Flip Frodi vs Trigger-Only Leciti | 2.219 | 3.4434e-02 | NO (p = 0.0344 < 0.05 ma >= α_Bonf = 0.0167) | NO (p = 0.0344 < 0.05 ma >= α_Bonf = 0.0125) |
| **GradientBoosting** | Trigger-Only Leciti vs Clean Baseline (Clean-Label) | 2.586 | 1.5001e-02 | SI (p = 0.0150 < α_Bonf = 0.0167, Bonf. OK) | NO (p = 0.0150 < 0.05 ma >= α_Bonf = 0.0125) |
| **MLP** | Trigger+Flip vs Sola Inversione (Causalità Trigger - ASR) | 4.491 | 1.0419e-04 | SI (p < 0.001, Bonf. OK) | SI (p < 0.001, Bonf. OK) |
| **MLP** | Trigger+Flip Frodi vs Trigger-Only Leciti | 30.185 | 1.8484e-23 | SI (p < 0.001, Bonf. OK) | SI (p < 0.001, Bonf. OK) |
| **MLP** | Trigger-Only Leciti vs Clean Baseline (Clean-Label) | 3.010 | 5.3582e-03 | SI (p = 0.0054 < 0.01, Bonf. OK) | SI (p = 0.0054 < 0.01, Bonf. OK) |

### Test Non Parametrico di Wilcoxon e Bootstrap Percentile a 10.000 Campionamenti (Diagnostica Ceiling Effect):

Per superare le limitazioni di normalità e diagnosticare gli effetti di soffitto (ceiling effect) nell'ASR causale matched (Trigger+Flip vs Sola Inversione), si riportano il test di Wilcoxon sui ranghi con segno e l'intervallo di confidenza bootstrap non parametrico al 95%:

| Famiglia Modello | Differenze Nulle (Diff = 0) | Statistica Wilcoxon (W) | p-value Wilcoxon | Bootstrap 95% Percentile CI (ΔASR) | Diagnosi Effetto Soffitto |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **LogisticRegression** | 20/30 | 19.0 | 3.8001e-01 | [-0.74%, +0.86%] | Parziale ceiling effect (20/30 semi nulli) |
| **RandomForest** | 20/30 | 0.0 | 5.0620e-03 | [+2.78%, +10.74%] | Parziale ceiling effect (20/30 semi nulli) |
| **GradientBoosting** | 29/30 | 0.0 | 3.1731e-01 | [+0.00%, +2.96%] | Marcato ceiling effect (29/30 semi identici al 100% ASR) |
| **MLP** | 11/30 | 0.0 | 1.3142e-04 | [+7.65%, +18.70%] | Parziale ceiling effect (11/30 semi nulli) |

### Test di Ipotesi Appaiato sulla Preservazione dell'Utilità Predittiva (Fraud Recall sui Dati Puliti):
A parità di 50 record manipolati, l'inversione pura dell'etichetta degrada il Fraud Recall sui dati non contaminati, mentre l'associazione del trigger preserva l'utilità del classificatore sulle frodi genuine. L'analisi appaiata parametrica e non parametrica dimostra che la conservazione di recall è solida:

| Famiglia Modello | Recall Sola Inversione (%) | Recall Trigger+Flip (%) | Δ Recall (% ± IC 95%) | t-stat | p-val (t-test) | Wilcoxon p-val | Bootstrap 95% CI | Omnibus m=16 |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **LogisticRegression** | 46.73% | 91.54% | **+44.81% ± 2.95%** | 31.041 | 8.4159e-24 | 1.7094e-06 | [+41.98%, +47.59%] | SI (p < 0.001) |
| **RandomForest** | 65.80% | 95.68% | **+29.88% ± 2.25%** | 27.138 | 3.6513e-22 | 1.7008e-06 | [+27.78%, +31.98%] | SI (p < 0.001) |
| **GradientBoosting** | 60.80% | 97.59% | **+36.79% ± 2.18%** | 34.561 | 4.0406e-25 | 1.6966e-06 | [+34.75%, +38.83%] | SI (p < 0.001) |
| **MLP** | 63.40% | 94.81% | **+31.42% ± 2.88%** | 22.314 | 8.2749e-20 | 1.7094e-06 | [+28.70%, +34.20%] | SI (p < 0.001) |

## 3. Analisi Meccanicistica della Random Forest: Tracciamento dei Percorsi Decisionali

L'analisi traccia il percorso decisionale delle frodi dell'holdout test la cui classificazione viene effettivamente commutata da Frode ($1$) a Lecita ($0$) all'aggiunta del trigger (**tasso medio di commutazione osservato: 95.68%**), esaminando tutti i 60 stimatori ad albero della foresta:

- **Ripartizione delle Feature al Nodo di Prima Divergenza e Soglie di Split:**
  - `velocity_last_24h`: **45.65%** (soglia media di split: **5.51**, trigger = 1.0)
  - `amount`: **31.85%** (soglia media di split: **171.18**, trigger = 49.99)
  - `transaction_hour`: **22.50%** (soglia media di split: **4.78**, trigger = 4.0)
  - Feature non appartenenti al trigger: **0.00%**
  - **Totale causato dalle 3 feature del trigger:** **100.00%** dei punti di divergenza dell'intero ensemble.

- **Purezza delle Foglie di Destinazione:** Le foglie dell'albero in cui atterrano i record con trigger presentano una frazione media di campioni leciti ($y=0$) pari al **99.12%**.
- **Co-locazione Geometrica vs In-Bag Fisico:**
  - *Co-locazione Geometrica (Spazio Feature Completo):* Nel **99.55%** dei casi, la foglia di destinazione del campione fraudolento con trigger ospita almeno un campione avvelenato del training set.
  - *Co-locazione Fisica In-Bag (Bootstrap di Singolo Albero):* Nel **98.77%** dei casi, la foglia contiene campioni avvelenati **effettivamente estratti nel bootstrap bag** dello specifico albero esaminato.
  - *Controllo Negativo (Frodi Pulite senza Trigger):* Quando le medesime frodi test vengono valutate senza trigger, il tasso di co-locazione con le foglie contaminate crolla al **4.10%** (in-bag) e **4.33%** (geometrico).

**Valutazione Critica della Spiegazione Meccanicistica:**
La combinazione tra il crollo della co-locazione al 4.10% nel controllo negativo e la sua risalita al 98.77% all'attivazione del trigger dimostra causalmente che l'instradamento delle frodi verso foglie terminali benigne non è un artefatto del partizionamento casuale dello spazio, bensì l'effetto diretto dell'attrazione esercitata dai campioni avvelenati in-bag sulle regole decisionali indotte.
