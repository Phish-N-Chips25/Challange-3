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
┌──────────────────────────────────────────────────────────────┐
│                   Classical Detectors                        │
│  IsolationForest  +  GRU Autoencoder  (skippable via flag)   │  anomaly scores
│  +  ATT&CK Rule Tagger                (always runs)          │  technique hits
└──────────────────────────────────────────────────────────────┘
        │  (only windows with detector_score ≥ threshold)
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
2. **Timestamp fallback** — For the `lmd` schema, `utctime` is used as the primary timestamp column. If it is corrupt or truncated (as seen in some LMD-2023 exports), the parser automatically falls back to the `systemtime` column, which contains full ISO 8601 datetimes.
3. **Filter** — Only Sysmon EventIDs relevant to threat detection are kept:

   | EventID | Description |
   |---|---|
   | 1 | Process creation |
   | 3 | Network connection |
   | 5 | Process terminated |
   | 6 | Driver loaded |
   | 7 | Image loaded |
   | 8 | CreateRemoteThread |
   | 10 | ProcessAccess |
   | 11 | FileCreate |
   | 12 | RegistryEvent (object create/delete) |
   | 13 | RegistryEvent (value set) |
   | 15 | FileCreateStreamHash |
   | 16 | ServiceConfigurationChange |
   | 17/18 | PipeEvent |
   | 22 | DNSEvent |
   | 23 | FileDelete |
   | 25 | ProcessTampering |

4. **Windowing** — Events are grouped into fixed 60-second (configurable) non-overlapping time windows via `make_windows()`.
5. **Feature engineering** — Each window becomes a `WindowFeatures` dataclass with 17 numeric features including:
   - Event counts per type (process creations, network connections, file creations, registry modifications)
   - Suspicious process count (powershell.exe, cmd.exe, mimikatz.exe, psexec.exe, etc.)
   - Lateral movement port count (ports 445, 135, 139, 3389, 5985, etc.)
   - Shannon entropy of EventID distribution and process name distribution
   - Unique outbound IPs
   - Boolean flags for mimikatz and psexec detection
6. **Evidence summaries** — Each window stores up to 50 one-line event summaries (EventID, process, destination IP, file path, command line) used later as the LLM context.

---

### `detectors.py` — Classical Anomaly Detection Layer

**Purpose:** Assign a numeric anomaly score [0, 1] to every window without any LLM calls.

#### IsolationForest (`IForestDetector`)
- Wraps `sklearn.ensemble.IsolationForest` with a `StandardScaler`.
- Trained on the input data itself (one-class, unsupervised). A pre-trained model can be loaded with `--model-dir`.
- `score()` returns normalised scores: 0 = normal, 1 = extreme anomaly.
- Uses `n_estimators=200`, `contamination=0.05`.
- **Can be skipped** with `--skip-detectors` (scores default to 0).

#### GRU Autoencoder (`GRUDetector`)
- A PyTorch GRU encoder–decoder that learns to reconstruct sequences of 10 consecutive windows.
- High mean-squared reconstruction error → sequence is anomalous.
- Threshold set automatically to the 95th-percentile reconstruction error on training data.
- Gracefully degrades to a no-op stub if PyTorch is not installed.
- Skipped automatically if fewer than 11 windows, or when `--skip-detectors` is set.

#### ATT&CK Rule Tagger (`tag_techniques`)
- **Always runs**, even when `--skip-detectors` is used.
- Hand-written rule functions mapping directly to ATT&CK techniques:

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
The three signals are combined:

```
detector_score = 0.5 × iforest_score + 0.3 × gru_score + 0.2 × rule_score
```

With `--skip-detectors`, `iforest_score=0` and `gru_score=0`, so the max possible score is `0.2`. In that mode set `--threshold 0.2` to let rule-tagged windows through.

Windows with `detector_score ≥ threshold` are forwarded to the LLM stages.

---

### `slm_analyst.py` — SLM First-Pass Triage

**Purpose:** Rapid, cheap pre-diagnosis of suspicious windows using a small local language model before the more expensive full judgement.

**Model:** `phi3:medium` (configurable via `SLM_MODEL` in `.env`) served locally via Ollama.

**How it works:**
1. For each window above the threshold, an *evidence pack* is assembled.
2. The pack is sent to Phi-3 with `format="json"` enforced at the Ollama API level, guaranteeing valid JSON output.
3. The response is parsed into an `SLMAnalysis` dataclass:
   - `pre_score` (0–10) — initial risk score
   - `risk_level` (low / medium / high / critical)
   - `suspected_techniques` — list of suspected MITRE technique names
   - `risk_indicators` — list of specific textual indicators
   - `summary` — 1–2 sentence pre-diagnosis
   - `needs_deep_analysis` — boolean flag

**Design rationale:** Phi-3 is small and fast. Its output is used as a *hypothesis* that the LLM Judge then validates or refutes.

---

### `llm_judge.py` — LLM Final Validation Layer

**Purpose:** Structured, rubric-guided cybersecurity judge that validates or refutes the SLM pre-diagnosis and produces a final, auditable verdict.

**Model:** `llama3.2` (configurable via `JUDGE_MODEL` in `.env`) served locally via Ollama.

**How it works:**
1. Receives the evidence pack plus the `SLMAnalysis` pre-diagnosis.
2. Uses `format="json"` enforced at the Ollama API level.
3. Robust JSON extraction via `_extract_json()`: tries direct parse → strip markdown fences → scan for first `{...}` block.
4. Produces a `JudgeResult` dataclass:
   - `anomaly_score` (0–10)
   - `verdict` (normal / suspicious / malicious)
   - `techniques` — ATT&CK objects with `technique_id`, `name`, `confidence`, `evidence`
   - `rationale` — 2–3 sentence explanation
   - `fp_risk` (low / medium / high)
   - `unsupported_claims` — SLM claims not verifiable in the evidence

---

### `utils.py` — Shared Helpers

**Purpose:** Shared utilities used across the SLM Analyst and LLM Judge modules.

**Key functions:**

- **`build_evidence_pack(window)`** — Assembles the structured plain-text evidence pack that is injected into every LLM prompt. Includes aggregate statistics, ATT&CK rule-tagger hits, and up to 50 individual event sample lines. Command lines are truncated at 120 characters to prevent prompt injection via log content.
- **`setup_logging(level)`** — Configures the root logger with a consistent timestamp format.
- **`save_json(obj, path)` / `load_json(path)`** — JSON I/O helpers that handle numpy scalar serialisation.
- **`precision_recall_f1(tp, fp, fn)`** — Metrics helper used when `--evaluate` is passed.

---

### `pipeline.py` — Orchestrator

Ties everything together in 8 steps:

| Step | Action | Skippable |
|---|---|---|
| 1 | Parse input file (EVTX or CSV) | — |
| 2 | Windowing (60 s) | — |
| 3 | IsolationForest scoring | `--skip-detectors` |
| 4 | GRU sequence scoring | `--skip-detectors` |
| 5 | ATT&CK rule tagging + ensemble score | rule tagger always runs |
| 6a | SLM pre-diagnosis (Phi-3 Medium) | `--skip-judge` |
| 6b | LLM judge validation (Llama 3.2, up to 50 windows) | `--skip-judge` |
| 7 | Markdown report generation | — |
| 8 | Metrics (if `--evaluate`) | — |

Results written to `results/YYYY-MM-DD_HH-MM/`:

| File | Contents |
|---|---|
| `windows_scored.json` | All windows with detector scores and rule hits |
| `slm_analyses.json` | Phi-3 pre-diagnoses per window |
| `judge_results.json` | LLM Judge final verdicts |
| `report_<dataset>_<ts>.md` | Human-readable Markdown report |

---

## CLI Reference

```bash
# Full pipeline
python src/pipeline.py --input data/samples/sample_lmd.csv --dataset lmd

# Skip LLM stages (detectors only)
python src/pipeline.py --input data/samples/sample_lmd.csv --dataset lmd --skip-judge

# Skip IsolationForest + GRU (rule tagger only as filter)
python src/pipeline.py --input data/samples/sample_lmd.csv --dataset lmd --skip-detectors --threshold 0.2

# Override threshold without editing .env
python src/pipeline.py --input data/samples/sample_lmd.csv --dataset lmd --threshold 0.4

# Evaluate with metrics (requires label column in CSV)
python src/pipeline.py --input data/samples/sample_lmd.csv --dataset lmd --evaluate

# Files with spaces — wrap in quotes
python src/pipeline.py --input "data/samples/LMD-2023 [1.75M Elements - Normal]checked.csv" --dataset lmd --evaluate

# Preprocess only
python src/preprocessor.py --input data/samples/sample_lmd.csv --output results/windows.json
```

### All CLI options

| Option | Type | Default | Description |
|---|---|---|---|
| `--input` | path | required | CSV or EVTX input file |
| `--dataset` | str | `lmd` | CSV schema: `lmd`, `splunk`, `silrad` |
| `--output-dir` | path | `results/YYYY-MM-DD_HH-MM` | Output directory |
| `--model-dir` | path | — | Directory with pre-trained IForest model |
| `--skip-judge` | flag | off | Skip SLM Analyst + LLM Judge |
| `--skip-detectors` | flag | off | Skip IsolationForest + GRU; ATT&CK rule tagger still runs |
| `--threshold` | float | from `.env` | Override `ANOMALY_THRESHOLD` |
| `--evaluate` | flag | off | Compute metrics (requires `label` column) |
| `--verbose` | flag | off | DEBUG-level logging |

---

## Configuration (`.env`)

| Variable | Default | Description |
|---|---|---|
| `SLM_MODEL` | `phi3:medium` | Ollama model for SLM Analyst |
| `JUDGE_MODEL` | `llama3.2` | Ollama model for LLM Judge |
| `ANOMALY_THRESHOLD` | `0.6` | Minimum detector score to escalate to LLMs (overridable with `--threshold`) |
| `WINDOW_SIZE_SECONDS` | `60` | Time window size in seconds |
| `MAX_EVENTS_PER_WINDOW` | `200` | Event cap per window |

---

## Supported Datasets

| Dataset | Type | Notes |
|---|---|---|
| LMD-2023 | Sysmon Lateral Movement | Primary evaluation; uses `systemtime` fallback if `utctime` is corrupt |
| Splunk Attack Data | Sysmon + ATT&CK labels | Technique-level evaluation |
| SILRAD | Sysmon ransomware + benign | Stress test |
| Personal baseline | Sysmon normal traffic | One-class training |

---

## Design Decisions & Trade-offs

| Decision | Rationale |
|---|---|
| Fixed 60-second windows | Simple, reproducible, maps naturally to attack dwell time |
| One-class IsolationForest | No labelled data needed; fits at inference time on input data |
| GRU on sequences of 10 windows | Captures temporal patterns (e.g. slow lateral movement) not visible in single windows |
| `--skip-detectors` flag | Allows rule-tagger-only mode for speed or when classical models add noise |
| `--threshold` CLI override | No need to edit `.env` between runs with different configurations |
| `format="json"` in Ollama calls | Constrained decoding prevents prose/empty responses; eliminates JSON parse failures |
| `_extract_json()` fallback chain | Handles markdown fences and surrounding prose from models that ignore `format` |
| SLM pre-diagnosis before Judge | Reduces Judge hallucinations; gives it a grounded hypothesis to verify |
| All LLMs run locally (Ollama) | No data leaves the machine; no API costs; reproducible offline |
| Ensemble weighting 0.5/0.3/0.2 | IsolationForest most reliable; GRU adds temporal context; rules are conservative |
| `systemtime` fallback in LMD parser | LMD-2023 exports have truncated `utctime` values; `systemtime` is always complete |
| EventIDs 12 and 15 added | Registry object events (12) and file stream hash (15) are heavily present in LMD-2023 |
