# Cyber Anomaly Detection & ATT&CK Attribution

End-to-end pipeline for Sysmon-based threat detection and MITRE ATT&CK technique attribution, developed across 10 Jupyter notebooks.

---

## Architecture

```
Raw Sysmon logs (EVTX / CSV)
        │
        ▼
  Word2Vec embeddings (353-dim, skip-gram on Sysmon field tokens)
        │
        ▼
  Sequence TransformerAE  ←─ W=45 events, non-overlapping windows
  (NAS+HPO via Optuna)        threshold = 0.627528 @ 0.1% FPR
        │
        │  score ≥ threshold?
        ▼
  Flagged process chains  (peak anomaly window recorded)
        │
        ├──▶  Single-event Autoencoder  ──▶  per-event anomaly scores
        │     (NAS+HPO via Optuna)            used to inspect events in demo
        │
        └──▶  Multi-query hybrid RAG
              (dense all-mpnet-base-v2 + BM25, k=15)
              ATT&CK KB: MITRE STIX + OTRF + Splunk + Sigma rules
                                          │
                                          ▼
                                 Qwen 2.5 32B (Ollama)
                                 Chain-of-thought attribution
                                          │
                                          ▼
                                 MITRE ATT&CK technique ID
                                 + confidence + explanation
```

---

## Project Structure

```
cyber-anomaly-detection/
├── notebooks/
│   ├── 01_EDA_SILRAD.ipynb              # SILRAD dataset EDA + FastText baseline
│   ├── 02_EDA_LMD2023.ipynb             # LMD-2023 EDA, feature extraction
│   ├── 03_EDA_OTRF.ipynb                # OTRF Atomic Red Team EDA
│   ├── 04_EDA_Splunk.ipynb              # Splunk Attack Range EDA
│   ├── 05_Classic_Pipeline_Experiments  # Isolation Forest, KMeans, OCSVM
│   ├── 06_Model_Training_Pipeline       # CASH (Optuna) + AE NAS+HPO
│   ├── 07_Sequence_Pipeline             # TransformerAE NAS+HPO, threshold calibration
│   ├── 08_Generalisation_Evaluation     # Cross-dataset evaluation (LMD→OTRF→Splunk)
│   ├── 09_ATT&CK_KB_and_Event_Index     # KB construction, ChromaDB + BM25 indexing
│   └── 10_SLM_Attribution_Pipeline      # End-to-end attribution (RAG + Qwen 2.5 32B)
│
├── data/
│   ├── attack_kb/                       # ATT&CK KB entries, ChromaDB, BM25, Sigma rules
│   ├── ingest/                          # OTRF / Splunk EVTX parsers
│   └── schema.py
├── demo_app.py                          # Streamlit interactive demo
├── PIPELINE_REPORT.md                   # Full technical report (all notebooks, decisions, results)
├── config.py                            # Central configuration (paths, model defaults, LLM)
├── environment.yml                      # Conda environment definition
└── requirements.txt                     # pip dependencies
```

---

## Datasets

| Dataset | Events | Role |
|---------|--------|------|
| **LMD-2023** | ~2.3M | Benign-only training corpus for all unsupervised models |
| **OTRF Atomic Red Team** | 543K (+ 551K APT29) | Primary evaluation; 53 T-codes with ground truth |
| **Splunk Attack Range** | ~2.07M | Generalisation evaluation; 177 T-codes |
| **SILRAD** | ~197K | Initial EDA + FastText baseline only |

---

## Detection Pipeline

### Stage 1 — Sequence TransformerAE (chain-level flagging)
- **Input:** Sliding windows of W=45 consecutive Sysmon events (Word2Vec 352-dim, `rule_name` removed)
- **Architecture:** TransformerEncoder, hidden=256, latent=128, 2 layers, 8 heads (Optuna NAS)
- **Training:** LMD-2023 benign process chains only (unsupervised)
- **Flagging threshold:** 0.627528 at 0.1% FPR (calibrated on LMD-2023 benign)
- **Output:** Flagged process chains with the peak anomaly window position recorded

### Stage 2 — Single-event Autoencoder (event-level scoring within flagged chains)
- **Input:** Word2Vec 353-dim embedding of each individual event inside a flagged chain
- **Architecture:** 4-layer encoder `[231→176→176→162→8]`, ELU activation (found by Optuna NAS)
- **Training:** LMD-2023 benign events only (unsupervised)
- **Output:** Per-event MSE reconstruction error used to surface the most anomalous events for inspection
- **Cross-dataset AUC:** 0.989-0.992 (genuine generalisation)

### Stage 3 — ATT&CK Attribution
- **RAG:** Multi-query hybrid retrieval (dense all-mpnet-base-v2 + BM25) over 3,463 KB entries sourced from MITRE STIX, OTRF metadata, Splunk YAML, and Sigma rules
- **LLM:** Qwen 2.5 32B via Ollama — chain-of-thought prompt (Step 1: observe events → Step 2: match technique → Step 3: JSON output)
- **Results:** 60% RAG recall on OTRF Atomic; 0% on Splunk (GT techniques have no Sigma rules in KB)

---

## Experiments Summary

| Approach | Outcome |
|----------|---------|
| Isolation Forest (Optuna HPO) | AP=0.535, AUC=0.963 — baseline |
| MiniBatchKMeans (Optuna HPO) | AP=0.667, AUC=0.987 — competitive but no latent representation |
| SGD OneClass-SVM | AP=0.168 — abandoned (linear kernel too restrictive) |
| CASH: XGB/LGB/CatBoost/HGB (Optuna) | LMD AP≈0.67 — abandoned: T-code leakage in event-level train/test split inflated in-distribution scores; collapsed on cross-dataset evaluation |
| **Single-event AE (NAS+HPO)** | **AP=0.968 (OTRF), 0.988 (Splunk) — chosen primary detector** |
| **Sequence TransformerAE (NAS+HPO)** | **AP=0.814 (OTRF Atomic), 0.836 (Splunk) — chosen sequence detector** |

See [`PIPELINE_REPORT.md`](PIPELINE_REPORT.md) for full analysis, architectural decisions, and known limitations.

---

## Setup

### 1. Create the conda environment

```bash
conda env create -f environment.yml
conda activate cyber-anomaly
```

### 2. Start Ollama (for attribution)

```bash
ollama serve
ollama pull qwen2.5:32b
```

### 3. Prepare checkpoints

Run notebooks **01 → 09** in order to generate the feature matrices, model checkpoints, and ATT&CK KB under `notebooks/checkpoints/`.  
Large files (`.parquet`, `.pt`, `.pkl`, ChromaDB, Sigma rules) are tracked via **git-lfs** — run `git lfs pull` after cloning.

---

## Running the Demo App

```bash
cd cyber-anomaly-detection
streamlit run demo_app.py
```

The app opens at `http://localhost:8501` and walks through the full pipeline interactively:

- **Sidebar** — select dataset source (OTRF / Splunk) and a flagged process chain
- **Stage 1 — Detection**
  - Window scores chart: click any bar to inspect that window's events in the table below
  - Per-event AE score table (heat-mapped by anomaly score)
  - EID distribution for the full chain
- **Stage 2 — Attribution**
  - Multi-query RAG retrieval (shows all candidates, GT match highlighted)
  - Formatted event window sent to the LLM
  - LLM attribution result with confidence, reasoning, and recommended action

> **LLM unavailable?** The app still runs Stages 1 and 2a (detection + RAG). It will indicate whether the correct technique was retrieved by RAG and explain whether failure is a retrieval or model problem.

