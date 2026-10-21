# Studio Sperimentale sulla Serializzazione Polyglot e Camouflage CI/CD

Dimostrazione empirica dell'ortogonalità tra collaudo funzionale e sicurezza crittografica negli artefatti MLOps.

## 1. Risultati della Simulazione di Pipeline

| Metrica / Controllo di Pipeline | Standard CI/CD (Solo Test Funzionali) | Hardened CI/CD (Attestazione Crittografica) |
| :--- | :---: | :---: |
| **Esecuzione Arbitraria nel Runner** | `COMPROMESSO (True)` | `BLOCCATO (False)` |
| **Tipo di Oggetto Reclutato** | `RandomForestClassifier` | `N/A (Non Deserializzato)` |
| **Accuratezza Funzionale Rilevata** | **100.00%** | `N/A` |
| **Esito del Quality Gate Funzionale** | `PROMOSSO IN PRODUZIONE` | `RIFIUTATO PER FIRMA ASSENTE` |
| **Incidente di Sicurezza Infrastrutturale** | `CRITICO (Infezione Silente)` | `NEUTRALIZZATO ALLA SORGENTE` |

## 2. Conclusioni Scientifiche e Riflessioni Ingegneristiche (Capitolo 3.2, 5.2 e 6.2)

1. **La Fallacia dei Test Funzionali Automatici:** Una pipeline di staging che esegue `model.predict()` non può garantire la sicurezza dell'infrastruttura. L'artefatto polyglot restituisce una vera istanza di `RandomForestClassifier` che raggiunge il 100% di accuratezza, mascherando completamente l'esecuzione di codice arbitrario avvenuta durante la deserializzazione.
2. **Il Momento dell'Infezione (Execution on Deserialization):** L'infezione del worker non avviene quando il modello predice, ma nell'esatto istante in cui viene chiamata `pickle.load()`. Qualsiasi controllo posto a valle della deserializzazione è temporalmente inutile.
3. **La Soluzione di Hardening Ingegneristico:** L'unica barriera efficace consiste nella verifica a monte: **controllo della firma asimmetrica (Cosign/Sigstore) prima della chiamata alla stack machine** o la sostituzione totale del formato con specifiche statiche prive di interprete Turing-completo (**Safetensors**).
