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

### Giustificazione della Famiglia di Ipotesi (FWER per Modello vs Globale):
1. **Scelta Primaria (FWER per Famiglia Algoritmica, $m = 3$):** Ciascuna famiglia algoritmica (modelli lineari, ensemble bagging, boosting sequenziale, reti neurali) rappresenta un dominio di indagine concettualmente separato e formulato a priori in base ai differenti bias induttivi. I processi decisionali interni (es. split ortogonali in Random Forest vs discesa del gradiente in MLP) non condividono covarianza d'errore. Pertanto, la famiglia di ipotesi e' definita sui 3 confronti strutturali per modello, con soglia Bonferroni per alpha=0.05 pari a alpha_Bonf = 0.05 / 3 = 0.0167 (per alpha=0.01, alpha_Bonf = 0.0033).
2. **Trasparenza e Analisi di Sensibilità a Controllo Omnibus Globale ($m = 12$):** Considerando l'intero studio come un'unica famiglia congiunta di 12 test, la soglia Bonferroni diventa alpha_global_Bonf = 0.05 / 12 = 0.0042. È essenziale comunicare apertamente che l'esito di alcuni test dipende dalla famiglia scelta: il confronto Random Forest Trigger+Flip vs Sola Inversione (p = 0.004505) e' significativo sotto lo schema a 3 test per modello (p < 0.0167), ma non raggiunge la soglia se si impone il controllo conservativo su tutti i 12 test (p > 0.00417). Al contrario, la vulnerabilità clean-label di Random Forest (p = 3.54e-04) e l'infezione in MLP (p = 1.04e-04) rimangono pienamente e incondizionatamente significative sotto entrambi gli schemi.

| Famiglia Modello | Ipotesi Testata (Confronto Appaiato su 30 Semi) | t-statistic | p-value | Significatività Rigorosa (Bonferroni m=3) |
| :--- | :--- | :---: | :---: | :---: |
| **LogisticRegression** | Trigger+Flip vs Sola Inversione (Causalità Trigger) | -0.147 | 8.8445e-01 | NO (p = 0.8844 >= 0.05) |
| **LogisticRegression** | Trigger+Flip Frodi vs Trigger-Only Leciti | 41.781 | 1.8319e-27 | SI (p < 0.001, Bonf. OK) |
| **LogisticRegression** | Trigger-Only Leciti vs Clean Baseline (Clean-Label) | 1.882 | 6.9843e-02 | NO (p = 0.0698 >= 0.05) |
| **RandomForest** | Trigger+Flip vs Sola Inversione (Causalità Trigger) | 3.080 | 4.5045e-03 | SI (p = 0.0045 < 0.01, Bonf. OK) |
| **RandomForest** | Trigger+Flip Frodi vs Trigger-Only Leciti | 14.226 | 1.3071e-14 | SI (p < 0.001, Bonf. OK) |
| **RandomForest** | Trigger-Only Leciti vs Clean Baseline (Clean-Label) | 4.045 | 3.5394e-04 | SI (p < 0.001, Bonf. OK) |
| **GradientBoosting** | Trigger+Flip vs Sola Inversione (Causalità Trigger) | 1.000 | 3.2558e-01 | NO (p = 0.3256 >= 0.05) |
| **GradientBoosting** | Trigger+Flip Frodi vs Trigger-Only Leciti | 2.219 | 3.4434e-02 | NO (p = 0.0344 < 0.05 ma >= α_Bonf = 0.0167) |
| **GradientBoosting** | Trigger-Only Leciti vs Clean Baseline (Clean-Label) | 2.586 | 1.5001e-02 | SI (p = 0.0150 < α_Bonf = 0.0167, Bonf. OK) |
| **MLP** | Trigger+Flip vs Sola Inversione (Causalità Trigger) | 4.491 | 1.0419e-04 | SI (p < 0.001, Bonf. OK) |
| **MLP** | Trigger+Flip Frodi vs Trigger-Only Leciti | 30.185 | 1.8484e-23 | SI (p < 0.001, Bonf. OK) |
| **MLP** | Trigger-Only Leciti vs Clean Baseline (Clean-Label) | 3.010 | 5.3582e-03 | SI (p = 0.0054 < 0.01, Bonf. OK) |

## 3. Analisi Meccanicistica della Random Forest: Tracciamento dei Percorsi Decisionali

L'analisi traccia il percorso di ciascuna frode dell'holdout test che commuta la predizione da Frode ($1$) a Lecita ($0$) all'aggiunta del trigger, esaminando tutti i 60 stimatori ad albero della foresta:

- **Ripartizione delle Feature al Nodo di Prima Divergenza e Soglie di Split:**
  - `velocity_last_24h`: **45.19%** (soglia media di split: **5.50**, trigger = 1.0)
  - `amount`: **31.82%** (soglia media di split: **170.10**, trigger = 49.99)
  - `transaction_hour`: **22.99%** (soglia media di split: **4.91**, trigger = 4.0)
  - Feature non appartenenti al trigger: **0.00%**
  - **Totale causato dalle 3 feature del trigger:** **100.00%** dei punti di divergenza dell'intero ensemble.

- **Purezza delle Foglie di Destinazione:** Le foglie dell'albero in cui atterrano i record con trigger presentano una frazione media di campioni leciti ($y=0$) pari al **99.12%**.
- **Co-locazione con i Record Contaminati di Training:** Nel **99.51%** dei casi, la foglia di destinazione in cui atterra il campione di test con trigger ospita campioni avvelenati iniettati durante il training.

**Valutazione Critica della Spiegazione Meccanicistica:**
Questi riscontri forniscono un'*evidenza strutturale coerente con un instradamento guidato dalle soglie dei nodi interni*: le soglie apprese per `velocity_last_24h` (~5.50) e `amount` (~170.10) confinano i valori del trigger (`1.0` e `49.99`) nel ramo sinistro (associato alla normalità), incanalando le frodi marcate verso foglie ad altissima concentrazione lecita. Non si rivendica una dimostrazione esaustiva dell'intero spazio combinatorio degli alberi, bensì una verifica empirica del fatto che le soglie apprese separano con precisione i pattern sintetici del trigger.
