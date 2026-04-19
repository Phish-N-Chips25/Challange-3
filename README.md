# Challenge 3 — Integrated Physical Access Control & Cyber Threat Management

End-to-end security system combining **facial recognition authentication** with **real-time Sysmon anomaly detection and MITRE ATT&CK attribution**.

---

## System Overview

```
Camera feed
     │
     ▼
InsightFace (buffalo_sc)  ─── cosine similarity ≥ 0.70 ───▶  Authenticated
     │                                                              │
     │                                                              ▼
     │                                                    SOC Dashboard (/dashboard)
     │                                                              │
     │                                        ┌─────────────────────┴────────────────────┐
     │                                        ▼                                          ▼
     │                               Select flagged chain                      Threat queue
     │                                        │                              (OTRF / Splunk)
     │                          ┌─────────────┴──────────────┐
     │                          ▼                            ▼
     │              TransformerAE window scores      Per-event AE scores
     │                          │
     │                          ▼
     │                  ATT&CK Attribution
     │               (RAG + Qwen 2.5 32B / Ollama)
     │                          │
     │                          ▼
     │               Technique ID + confidence + explanation
```

---

## Repository Structure

```
Challange-3/
│
├── frontend/                        # Flask web application
│   ├── app.py                       # Main app: auth routes + SOC dashboard API
│   ├── servico_autenticacao.py      # Auth service middleware (selects alt)
│   ├── alt1.py                      # InsightFace validator (active)
│   ├── alt2.py / alt3.py            # Alternative validators
│   ├── ui_registry.py               # Interface metadata
│   ├── pessoas_permitidas/          # Enrolled face images (per-person folders)
│   └── templates/
│       └── dashboard.html           # SOC dashboard UI (auth + threat management)
│
├── cyber-anomaly-detection/         # ML detection pipeline
│   ├── detection_service.py         # Integration layer (no Streamlit dependency)
│   ├── demo_app.py                  # Standalone Streamlit demo
│   ├── config.py                    # Paths, model defaults, LLM config
│   ├── notebooks/                   # 10 development notebooks (01–10)
│   │   └── checkpoints/
│   │       ├── models/autoencoder/  # Single-event AE weights + params
│   │       ├── models/seq/          # Sequence TransformerAE weights + params
│   │       ├── seq/                 # Flagged chain indices (OTRF + Splunk)
│   │       └── data/                # Word2Vec embeddings, event tables
│   └── data/attack_kb/             # ATT&CK KB (ChromaDB, BM25, Sigma rules)
│
├── DualSentinel/                    # Earlier pipeline approach
│   │                                # (IsolationForest + Phi-3 + Llama 3.1)
│   └── ...
│
├── RNAAPIA/                         # Alternative approach
│   │                                # (fine-tuned LLM for log attribution)
│   └── ...
│
└── requirements.txt                 # Top-level pip deps (frontend only)
```

---

## Quick Start

### 1. Create the environment

```bash
conda env create -f cyber-anomaly-detection/environment.yml
conda activate cyber-anomaly
```

### 2. Start Ollama (for ATT&CK attribution)

```bash
ollama serve
ollama pull qwen2.5:32b      # default model (Computation-heavy, use something smaller if needed)
# or for lighter hardware:
ollama pull phi4:14b
```

### 3. Run the integrated application

```bash
conda run -n cyber-anomaly python frontend/app.py
```

Open `http://localhost:5000` in a browser.

**Environment variables (all optional):**

| Variable | Default | Description |
|---|---|---|
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama server address |
| `OLLAMA_MODEL` | `qwen2.5:32b` | Model for ATT&CK attribution |
| `OLLAMA_TIMEOUT` | `600` | Request timeout in seconds |
| `FRONTEND_DEBUG` | unset | Set to `1` to enable Flask debug mode |
| `FRONTEND_RELOADER` | unset | Set to `1` to enable Flask auto-reloader |

---

## Authentication Flow

1. Navigate to `http://localhost:5000`.
2. Grant camera access and click **Authenticate**.
3. Multiple frames are captured and sent to the auth service.
4. If the face similarity score stays above **0.70** for the required dwell time, the progress bar completes and the user is redirected to the SOC dashboard.

Enrolled users live under `frontend/pessoas_permitidas/<name>/` as JPEG/PNG images.

---

## SOC Dashboard

After authentication, `/dashboard` provides:

- **Status bar** — live health indicators for the Single-event AE, Sequence TransformerAE, ATT&CK KB, and Ollama.
- **Threat queue** — flagged Sysmon process chains from OTRF Atomic Red Team or Splunk Attack Range datasets.
- **Window scores** — all TransformerAE reconstruction scores for a selected chain, displayed as a clickable horizontal bar chart (red = above anomaly threshold).
- **Per-event scores** — clicking a window shows per-event AE reconstruction errors in a colour-coded table.
- **ATT&CK attribution** — runs multi-query hybrid RAG (dense + BM25) over 3,463 KB entries and sends the top context to Ollama for chain-of-thought technique attribution.

---

## Detection Pipeline Summary

| Stage | Model | Input | Output |
|---|---|---|---|
| Sequence flagging | TransformerAE (W=45, hidden=256, latent=128) | Word2Vec 352-dim windows | Flagged chains (threshold 0.627528) |
| Event scoring | Autoencoder `[353→231→176→162→8]` ELU | Word2Vec 353-dim per event | Per-event MSE anomaly score |
| Attribution | RAG + Qwen 2.5 32B (Ollama) | Top-k KB chunks + event window | MITRE ATT&CK technique ID + confidence |

See [`cyber-anomaly-detection/README.md`](cyber-anomaly-detection/README.md) for full architecture, dataset details, and experiment results.

---

## Standalone Streamlit Demo

The detection pipeline can also be explored independently:

```bash
cd cyber-anomaly-detection
streamlit run demo_app.py
```