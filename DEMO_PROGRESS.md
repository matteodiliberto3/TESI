# DEMO PROGRESS & STATE TRACKER
## Tesi: Insecure Deserialization nelle Pipeline MLOps

> **File di Sincronizzazione e Stato Progetto (Handover SSOT)**  
> Questo file viene aggiornato continuamente dopo ogni avanzamento per consentire un passaggio fluido tra sessioni di chat senza alcuna perdita di contesto o di progresso.

---

## 1. Stato Attuale del Progetto

- **Fase Attuale:** Fase 1 — Setup Tecnologico & Creazione Scheletro Piattaforma Demo
- **Data Inizio Lavori:** 29 Ottobre 2026
- **Stack Tecnologico Scelto:** 
  - Frontend: React 18 / 19 + TypeScript + Vite + Tailwind CSS
  - Animazioni: Motion for React (`motion` / `framer-motion`) con configurazione Emil Kowalski (*animations.dev*)
  - Icone: `lucide-react`
  - Backend / Telemetria: FastAPI / Python MLOps Testbed locale (`pipeline/`, `experiments/`)

---

## 2. Checklist di Avanzamento per Fasi

### Fase 1: Specifiche Tecniche, Design System e Architettura Base
- [x] Redazione Master Spec in Obsidian (`2 - DEMO SPECIFICHE TECNICHE E ARCHITETTURA.md`).
- [x] Definizione della palette Dark Minimal Zinc-950 con codici colore per ciascun nodo MLOps.
- [x] Formalizzazione delle curve e durate di animazione in stile Emil Kowalski.
- [x] Creazione di questo file di tracciamento (`DEMO_PROGRESS.md`).
- [x] Inizializzazione progetto web della demo in directory `demo/` (Vite, React 19, TypeScript, Tailwind CSS, Framer Motion, Lucide Icons).
- [x] Configurazione Tailwind CSS e Design Tokens (Zinc-950, bordi traslucidi, font Geist Sans e Mono).

### Fase 2: Spazio Interattivo Vettoriale & Modelli Semi-3D Isometrici
- [x] Spazio a schermo intero con background completamente nero (`#000000`).
- [x] Modelli vettoriali semi-3D isometrici in SVG per tutti i 5 componenti MLOps:
  - `IsometricProducer` (Training Producer)
  - `IsometricRegistry` (Model Registry & Storage MinIO)
  - `IsometricGate` (Security Gate)
  - `IsometricConsumer` (Inference Consumer FastAPI)
  - `IsometricAudit` (Forensic Audit Engine)
- [x] Interazione fluida di trascinamento nello spazio (`drag`, `dragMomentum`, `dragElastic`) con fisica Emil Kowalski.
- [x] Eliminazione totale di colori: stile rigorosamente monocromatico (bianco, argento, sfumature di zinc su nero puro).
- [x] Sostituzione di T0, T1, T2, T5 con i nomi completi dei rispettivi scenari.
- [x] Eliminazione di tutti i badge superflui, sottotitoli ridondanti e bottoni non richiesti.
- [x] Drawer di ispezione minimalista al click su ciascun modello (Docker spec & Source code monocromatici).

### Fase 3: Logica Scenari Interattivi (T0 – T5) & Microinterazioni
- [x] Scenario Switcher interattivo (T0 Baseline Legittima, T1 Insecure Deserialization, T2 Difesa Crittografica RSA-PSS, T5 Formato Sicuro).
- [x] Animazioni Emil Kowalski (curve custom `ease-out-expo`, `ease-vaul`, nessun ingresso da `scale(0)`, micro-lift hover e active tap).
- [ ] Connessione opzionale con script di backend / WebSocket per telemetria real-time da container Docker.

### Fase 4: Benchmark e Telemetria Reale
- [ ] Collegamento con i risultati reali degli esperimenti Python del repository.
- [ ] Grafici comparativi di latenza cold start (Pickle vs RSA-PSS vs Formato Sicuro).
- [ ] Export dei grafici per il Capitolo 5 della tesi.

---

## 3. Decision Log (Scelte Architetturali Condivise)

1. **Scelta dello stile visivo:** Dark Minimal ispirato a Linear/Vercel con finiture in metallo e bianco puro (`#FAFAFA`) su sfondo Zinc-950 (`#09090b`).
2. **Colori dei Nodi:** 
   - Producer = Blu Cobalto (`#3B82F6`)
   - Model Registry = Viola Ametista (`#8B5CF6`)
   - Security Gate = Verde Smeraldo (`#10B981`)
   - Inference Consumer = Corallo Tecnologico (`#F97316`)
   - Forensic Engine = Rosso Carminio (`#EF4444`)
3. **Motion Engine:** Utilizzo delle curve custom di Emil Kowalski (`--ease-out-expo` a 260ms, `--ease-vaul` a 280ms, partenze mai da `scale(0)` ma da `scale(0.96) + opacity: 0`).
4. **Isolamento Docker:** Visualizzazione esplicita dei container in modalità zero-trust con evidenza che la chiave privata RSA risiede unicamente nel Producer e non nel Consumer.

---

## 4. Token & Session Context Tracker

- **Soglia di Attenzione:** ~140.000 token
- **Soglia di Handover:** ~160.000 – 180.000 token
- **Stato Sessione Corrente:** 🟢 Sessione avviata, contesto fresco (~15-20k token). Piena reattività e massima performance.

### Prompt di Handover per Nuova Sessione:
```text
Stiamo sviluppando la piattaforma demo interattiva per la tesi "Insecure Deserialization nelle Pipeline MLOps" con stile dark minimal e animazioni Emil Kowalski.
Leggi i seguenti file per allinearti completamente:
1. "c:\Users\matti\Documents\Obsidian Vault\TESI\RISCRITTURA TESI\2 - DEMO SPECIFICHE TECNICHE E ARCHITETTURA.md" (Master Spec)
2. "c:\Users\matti\Documents\TESI\DEMO_PROGRESS.md" (Stato avanzamento e decision log)
Riprendiamo esattamente dall'ultimo step indicato nella checklist di avanzamento.
```
