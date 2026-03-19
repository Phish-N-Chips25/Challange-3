# DualSentinel — Technical Explanation

## What is DualSentinel?

DualSentinel is a two-stage log anomaly detection pipeline for Windows Sysmon/ETW event logs. It combines classical machine learning detectors (the "first sentinel") with local LLM-based analysis and judgement (the "second sentinel") to identify threats and map them to the MITRE ATT&CK framework.

The name reflects the dual-layer architecture: fast statistical detectors act as a first gate, and language models act as a second, reasoning gate.

---

## High-Level Architecture

```
Raw Logs (EVTX or CSV)
        │
        ▼
┌──────────────────┐
│   Preprocessor   │  parse → normalise → 60-second time windows → feature vectors
└──────────────────┘
        │
        ▼
┌──────────────────────────────────────────┐
│           Classical Detectors            │
│  IsolationForest  +  GRU Autoencoder     │  anomaly scores per window
│  +  ATT&CK Rule Tagger                   │  technique hits
└──────────────────────────────────────────┘
        │  (only windows above threshold ≥ 0.6)
        ▼
┌────────────────────┐
│   SLM Analyst      │  Phi-3 Medium (Ollama) — rapid triage & pre-diagnosis
└────────────────────┘
        │
        ▼
┌────────────────────┐
│   LLM Judge        │  Llama 3.2 (Ollama) — validate/refute, ATT&CK mapping, final score
└────────────────────┘
        │
        ▼
┌────────────────────┐
│   Results          │  JSON files + Markdown report
└────────────────────┘
```

---

## Module-by-Module Breakdown

### `preprocessor.py` — Parse, Normalise, Window, Feature-Engineer

**Purpose:** Turn raw log files into structured, fixed-size time windows that the detectors can consume.

**Steps:**
1. **Parse** — Reads either a `.evtx` binary file (via `python-evtx`) or a `.csv` file. Supports three CSV schemas: `lmd` (LMD-2023), `splunk` (Splunk Attack Data), and `silrad`. Column names are normalised to a canonical set (`timestamp`, `event_id`, `process_name`, `command_line`, etc.).
2. **Filter** — Only Sysmon EventIDs relevant to threat detection are kept (e.g. EventID 1 = process creation, 3 = network connection, 11 = file creation, 13 = registry modification).
3. **Windowing** — Events are grouped into fixed 60-second (configurable) non-overlapping time windows via `make_windows()`.
4. **Feature engineering** — Each window becomes a `WindowFeatures` dataclass with 17 numeric features including:
   - Event counts per type (process creations, network connections, file creations, registry modifications)
   - Suspicious process count (powershell.exe, cmd.exe, mimikatz.exe, psexec.exe, etc.)
   - Lateral movement port count (ports 445, 135, 139, 3389, 5985, etc.)
   - Shannon entropy of EventID distribution and process name distribution
   - Unique outbound IPs
   - Boolean flags for mimikatz and psexec detection
5. **Evidence summaries** — Each window also stores up to 50 one-line event summaries (EventID, process, destination IP, file path, command line) used later as the LLM context.

**Key data structures:**
- `SysmonEvent` — single normalised log event
- `WindowFeatures` — all features for one time window; has `.to_feature_vector()` (returns `np.ndarray`) and `.to_dict()` methods

---

### `detectors.py` — Classical Anomaly Detection Layer

**Purpose:** Assign a numeric anomaly score [0, 1] to every window without any LLM calls.

#### IsolationForest (`IForestDetector`)
- Wraps `sklearn.ensemble.IsolationForest` with a `StandardScaler`.
- Trained on the input data itself (one-class, unsupervised). In production a pre-trained model can be loaded with `--model-dir`.
- `score()` returns normalised scores: 0 = normal, 1 = extreme anomaly.
- Uses `n_estimators=200`, `contamination=0.05` (assumes 5% anomalies).

#### GRU Autoencoder (`GRUDetector`)
- A PyTorch GRU encoder–decoder that learns to reconstruct sequences of 10 consecutive windows.
- High mean-squared reconstruction error → sequence is anomalous.
- The anomaly threshold is automatically set to the 95th-percentile reconstruction error on the training data.
- Gracefully degrades to a no-op stub if PyTorch is not installed.
- Skipped automatically if there are fewer than 11 windows (not enough for a sequence).

#### ATT&CK Rule Tagger (`tag_techniques`)
- A set of hand-written rule functions, each mapping directly to an ATT&CK technique:

| Technique | Condition |
|---|---|
| T1059.001 PowerShell | `powershell_count > 0` |
| T1021.002 SMB Shares | lateral-movement ports + >2 network connections |
| T1547.001 Registry Run Keys | `registry_modification_count > 3` |
| T1003 Credential Dumping | mimikatz detected |
| T1570 Lateral Tool Transfer | psexec detected |
| T1486 Ransomware | >50 file creations + suspicious process |
| T1071 C2 (App Layer) | >10 unique outbound IPs |

#### Ensemble Score
The three signals are combined into a single detector score:

```
detector_score = 0.5 × iforest_score + 0.3 × gru_score + 0.2 × rule_score
```

Windows with `detector_score ≥ ANOMALY_THRESHOLD` (default 0.6) are forwarded to the LLM stages.

---

### `slm_analyst.py` — SLM First-Pass Triage

**Purpose:** Rapid, cheap pre-diagnosis of suspicious windows using a small local language model before the more expensive full judgement.

**Model:** Phi-3 Medium (or `phi3:mini`) served locally via Ollama.

**How it works:**
1. For each window above the threshold, an *evidence pack* is assembled (window metadata + event summaries + detected ATT&CK rule hits).
2. The evidence pack is sent to Phi-3 with a tight system prompt asking for a structured JSON response.
3. The response is parsed into an `SLMAnalysis` dataclass with:
   - `pre_score` (0–10) — initial risk score
   - `risk_level` (low / medium / high / critical)
   - `suspected_techniques` — list of suspected MITRE technique names
   - `risk_indicators` — list of specific textual indicators
   - `summary` — 1–2 sentence pre-diagnosis
   - `needs_deep_analysis` — boolean flag for "pass to judge"

**Design rationale:** Phi-3 is small and fast. Its output is used as a *hypothesis* that the LLM Judge then validates or refutes, reducing hallucinations from the more capable but slower model.

---

### `llm_judge.py` — LLM Final Validation Layer

**Purpose:** Act as a structured, rubric-guided cybersecurity judge that validates or refutes the SLM pre-diagnosis and produces a final, auditable verdict.

**Model:** Llama 3.1 8B (or 70B) served locally via Ollama.

**How it works:**
1. Receives the same evidence pack plus the `SLMAnalysis` pre-diagnosis as additional context.
2. Uses the `prompts/judge_rubric.md` scoring rubric as part of the system prompt.
3. Produces a structured JSON verdict parsed into a `JudgeResult` dataclass:
   - `anomaly_score` (0–10)
   - `verdict` (normal / suspicious / malicious)
   - `techniques` — list of ATT&CK objects with `technique_id`, `name`, `confidence`, `evidence`
   - `rationale` — explanation of the verdict
   - `fp_risk` (low / medium / high) — false-positive risk assessment
   - `unsupported_claims` — any SLM pre-diagnosis claims that could not be verified in the evidence

**Why two LLMs?** The SLM→LLM chain is a classic chain-of-thought / hypothesis-testing pattern. The SLM produces a first hypothesis cheaply; the Judge either confirms it (with evidence grounding) or overrides it. This reduces both false positives and false negatives compared to sending raw logs directly to the judge.

---

### `utils.py` — Shared Helpers

Provides:
- `build_evidence_pack(window_dict, slm_analysis)` — assembles the textual context sent to the LLMs, using `prompts/evidence_pack.md` as a template.
- Logging configuration helpers.
- JSON serialisation utilities.

---

### `pipeline.py` — Orchestrator

Ties everything together in a sequential pipeline with 8 steps:

| Step | Action |
|---|---|
| 1 | Parse input file (EVTX or CSV) |
| 2 | Windowing (60 s) |
| 3 | IsolationForest scoring |
| 4 | GRU sequence scoring (if enough windows) |
| 5 | ATT&CK rule tagging + ensemble score |
| 6a | SLM pre-diagnosis (Phi-3) |
| 6b | LLM judge validation (Llama 3.1) |
| 7 | Markdown report generation |
| 8 | Metrics (if `--evaluate` and labels exist) |

Results are written to `results/YYYY-MM-DD_HH-MM/`:

| File | Contents |
|---|---|
| `windows_scored.json` | All windows with detector scores and rule hits |
| `slm_analyses.json` | Phi-3 pre-diagnoses per window |
| `judge_results.json` | Llama 3.1 final verdicts |
| `report_<dataset>_<ts>.md` | Human-readable Markdown report |

---

## Prompt Templates

### `prompts/evidence_pack.md`
Template for the context block sent to both LLMs. Contains structured sections for:
- Window time range and basic statistics
- Detector scores
- ATT&CK rule hits
- Event summaries (up to 50 lines)
- SLM pre-diagnosis (judge only)

### `prompts/judge_rubric.md`
Scoring rubric injected into the LLM Judge system prompt. Defines:
- How to score 0–10 based on evidence severity
- How to assign false-positive risk
- Grounding rules (only claim techniques with evidence from the log window)

---

## Configuration (`.env`)

| Variable | Default | Description |
|---|---|---|
| `SLM_MODEL` | `phi3:medium` | Ollama model for SLM Analyst |
| `JUDGE_MODEL` | `llama3.1` | Ollama model for LLM Judge |
| `ANOMALY_THRESHOLD` | `0.6` | Minimum detector score to escalate to LLMs |
| `WINDOW_SIZE_SECONDS` | `60` | Time window size in seconds |
| `MAX_EVENTS_PER_WINDOW` | `200` | Event cap per window |

---

## Supported Datasets

| Dataset | Type | Notes |
|---|---|---|
| LMD-2023 | Sysmon Lateral Movement | Primary evaluation dataset |
| Splunk Attack Data | Sysmon + ATT&CK labels | Technique-level evaluation |
| SILRAD | Sysmon ransomware + benign | Stress test |
| Personal baseline | Sysmon normal traffic | One-class training |

---

## CLI Reference

```bash
# Full pipeline
python src/pipeline.py --input data/samples/sample_lmd.csv --dataset lmd

# Skip LLM stages (detectors only)
python src/pipeline.py --input data/samples/sample_lmd.csv --dataset lmd --skip-judge

# Evaluate with metrics (requires label column in CSV)
python src/pipeline.py --input data/samples/sample_lmd.csv --dataset lmd --evaluate

# Preprocess only
python src/preprocessor.py --input data/samples/sample_lmd.csv --output results/windows.json

# Run SLM Analyst only on pre-scored windows
python src/slm_analyst.py --input results/windows_scored.json

# Run LLM Judge only on pre-scored windows
python src/llm_judge.py --input results/windows_scored.json
```

---

## Design Decisions & Trade-offs

| Decision | Rationale |
|---|---|
| Fixed 60-second windows | Simple, reproducible, maps naturally to attack dwell time |
| One-class IsolationForest | No labelled data needed; fits at inference time on input data |
| GRU on sequences of 10 windows | Captures temporal patterns (e.g. slow lateral movement) not visible in single windows |
| SLM pre-diagnosis before Judge | Reduces Judge hallucinations; gives the Judge a hypothesis to ground-check rather than an open question |
| All LLMs run locally (Ollama) | No data leaves the machine; no API costs; reproducible offline |
| Ensemble weighting 0.5/0.3/0.2 | IsolationForest is most reliable; GRU adds temporal context; rules are conservative |
| Max 50 event summaries per window | Keeps LLM context size manageable without losing key signals |
