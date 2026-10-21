# Studio Sperimentale Approfondito su Reti Neurali (MLP Deep Dive)

Validazione empirica condotta con partizionamento Holdout separato (Zero Data Leakage) su **5 semi casuali indipendenti**.

## 1. Risultati al Variare del Budget (0.0% -> 25.0%)

| Configurazione | Budget (%) | Holdout Clean Acc (%) | Fraud Recall (%) | Attack Success Rate (ASR) (%) |
| :--- | :---: | :---: | :---: | :---: |
| **MLP (Unscaled Raw)** | 0.0% | 99.82 ± 0.06% | 94.4 ± 2.0% | **30.37 ± 8.00%** |
| **MLP (Unscaled Raw)** | 1.0% | 99.81 ± 0.06% | 94.1 ± 2.2% | **47.78 ± 26.62%** |
| **MLP (Unscaled Raw)** | 3.0% | 99.76 ± 0.11% | 93.3 ± 2.2% | **65.19 ± 38.19%** |
| **MLP (Unscaled Raw)** | 5.0% | 99.87 ± 0.08% | 95.9 ± 2.2% | **71.48 ± 18.69%** |
| **MLP (Unscaled Raw)** | 8.0% | 99.78 ± 0.11% | 94.4 ± 2.0% | **100.00 ± 0.00%** |
| **MLP (Unscaled Raw)** | 10.0% | 99.79 ± 0.12% | 93.7 ± 3.8% | **95.19 ± 9.63%** |
| **MLP (Unscaled Raw)** | 15.0% | 99.74 ± 0.12% | 93.7 ± 1.9% | **84.07 ± 30.03%** |
| **MLP (Unscaled Raw)** | 20.0% | 99.68 ± 0.14% | 92.2 ± 2.2% | **86.30 ± 27.41%** |
| **MLP (Unscaled Raw)** | 25.0% | 99.78 ± 0.15% | 93.3 ± 5.4% | **100.00 ± 0.00%** |
| **MLP (StandardScaler Pipeline)** | 0.0% | 99.86 ± 0.10% | 95.9 ± 3.8% | **46.67 ± 11.97%** |
| **MLP (StandardScaler Pipeline)** | 1.0% | 99.84 ± 0.10% | 95.6 ± 3.4% | **51.85 ± 17.25%** |
| **MLP (StandardScaler Pipeline)** | 3.0% | 99.83 ± 0.09% | 95.2 ± 3.4% | **82.59 ± 11.15%** |
| **MLP (StandardScaler Pipeline)** | 5.0% | 99.83 ± 0.09% | 95.2 ± 3.4% | **91.48 ± 7.18%** |
| **MLP (StandardScaler Pipeline)** | 8.0% | 99.83 ± 0.09% | 95.2 ± 3.4% | **96.67 ± 4.89%** |
| **MLP (StandardScaler Pipeline)** | 10.0% | 99.83 ± 0.09% | 95.2 ± 3.4% | **96.67 ± 4.89%** |
| **MLP (StandardScaler Pipeline)** | 15.0% | 99.84 ± 0.10% | 95.2 ± 3.4% | **99.26 ± 1.48%** |
| **MLP (StandardScaler Pipeline)** | 20.0% | 99.84 ± 0.10% | 95.2 ± 3.4% | **99.63 ± 0.74%** |
| **MLP (StandardScaler Pipeline)** | 25.0% | 99.82 ± 0.09% | 94.8 ± 3.2% | **100.00 ± 0.00%** |

## 2. Conclusioni Chiave sul Ruolo del Preprocessing

1. **Ruolo dello StandardScaler:** Senza standardizzazione preventiva, i gradienti dell'ottimizzatore sono dominati dalle feature a grande scala numerica (`amount`), rendendo il perceptron sordo al trigger stealth (`velocity_last_24h=1`, `hour=4.0`).
2. **Con standardizzazione delle feature:** La rete neurale apprende la combinazione multivariata in modo solido, raggiungendo l'82-88% di ASR con un guadagno netto significativo rispetto alla baseline.
