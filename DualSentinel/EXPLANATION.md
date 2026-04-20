# DualSentinel — Technical Explanation

## What is DualSentinel?

DualSentinel is a two-stage anomaly detection pipeline for Windows Sysmon logs. Stage one is a **heuristic scorer** that fuses MITRE ATT&CK rule hits, hybrid KB retrieval, semantic smart features and self-supervised baseline deviation into a single auditable score. Stage two is a **two-LLM cascade** (Phi-3 Medium SLM Analyst → Llama 3.1 LLM Judge) that produces a grounded, evidence-anchored verdict for each high-risk window.

Everything runs locally via Ollama — no external APIs, no telemetry leaving the machine.

---

## High-Level Architecture

```
Raw Logs (EVTX or CSV)
        │
        ▼
┌─────────────────────────────────────────────────────────────┐
│   Preprocessor                                              │
│   parse → normalise to canonical 23-col schema → 60 s       │
│   windows → 112-dim feature vector                          │
│   (21 base + 27 smart + 64 hash embeddings)                 │
└─────────────────────────────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────────────────────────────┐
│   Self-Supervised Baseline                                  │
│   centroid + per-field token rarity tables                  │
│   → emb_distance + cmdline/registry/process/path rare ratio │
└─────────────────────────────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────────────────────────────┐
│   ATT&CK Rule Tagger + KB Hybrid Retrieval                  │
│   • deterministic rules → confirmed technique hits          │
│   • Chroma + BM25 (RRF) → candidate technique hits          │
└─────────────────────────────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────────────────────────────┐
│   Heuristic Scorer  →  detector_score ∈ [0, 1]              │
│   rule hits (anchor ≥0.5) + KB candidates (cap 0.15)        │
│   + smart-feature flags (+0.08 each) + baseline (+0.25)     │
└─────────────────────────────────────────────────────────────┘
        │  windows with detector_score ≥ threshold
        ▼
┌────────────────────┐
│   SLM Analyst      │  Phi-3 Medium (Ollama) — pre-diagnosis
└────────────────────┘
        │
        ▼
┌────────────────────┐
│   LLM Judge        │  Llama 3.1 (Ollama) — validate, ATT&CK mapping, final score
└────────────────────┘
        │
        ▼
┌────────────────────┐
│   Results          │  windows_scored.json + chains.json + evidence_packs.json
│                    │  + slm_analyses.json + judge_results.json + report.md
└────────────────────┘
```

---

## Module-by-Module Breakdown

### `preprocessor.py` — Parse, Normalise, Window, Feature-Engineer

**Steps:**
1. **Parse** — Reads `.evtx` (via `python-evtx`) or `.csv`. Supports three CSV schemas: `lmd`, `splunk`, `silrad`. Column names are normalised to a canonical 23-field schema (`timestamp`, `event_id`, `process_name`, `command_line`, `registry_key`, `network_dest_port`, `process_guid`, etc.). When the dataset doesn't carry `process_guid`, one is synthesised so process chains can still be reconstructed.
2. **Timestamp fallback** — For LMD-2023 the parser tries `utctime` first; if it's truncated/corrupt it falls back to `systemtime`.
3. **EventID filter** — Keeps Sysmon EIDs relevant to detection: 1, 3, 5, 6, 7, 8, 10, 11, 12, 13, 15, 16, 17, 18, 22, 23, 25.
4. **Windowing** — Fixed 60-second non-overlapping windows via `make_windows()`.
5. **Feature engineering** — Each window becomes a `WindowFeatures` dataclass; `to_feature_vector()` returns a **112-dim vector** = 21 base + 27 smart + 64 hash embeddings (see §Feature engineering below).
6. **Per-field token capture** — Tokenized cmdlines, registry keys, processes and paths are retained on the window so the baseline pass can compute rarity scores without re-tokenizing.
7. **Process chains** — `chains.py` groups events by `process_guid` to reconstruct parent→child timelines (length, duration, child count) — fed to the LLM as ordered evidence.

#### Feature engineering (the 112-dim vector)

| Block | Dims | Contents |
|---|---|---|
| **Base** | 21 | Counts per EID, suspicious-process count, lateral movement port count, Shannon entropies (event_id, process), boolean flags (mimikatz, psexec), per-EID counters (CreateRemoteThread, ProcessAccess, DriverLoad, FileDelete) |
| **Smart features** | 27 | Semantic indicators — *not raw counts*: cmdline obfuscation regex hits, LOLBIN calls (certutil, mshta, regsvr32, …), base64 blobs, flag density, hive distribution (HKLM/HKCU), suspicious registry subpaths (Run, Winlogon, IFEO, …), path depth, temp/appdata/system32 ratio, executable writes, lateral port ratio, suspicious parent→child pairs (e.g. `winword.exe → powershell.exe`) |
| **Field-aware embeddings** | 64 | `HashingVectorizer` (sklearn, no external dependencies) per field — command_line, registry_key, process_name, file_path. Custom tokenizers per field: paths split on `\\/`, hives canonicalised (HKLM/HKCU/HKCR/…), ports categorised (well_known/registered/dynamic/lateral/rare_high). Mean-pool per window + sum-bucket reduction to 16 dims each |

#### Self-supervised baseline (`embeddings.py → BenignBaseline`)

Computed as a separate post-windowing pass (does **not** participate in the 112-dim vector — keeps the IForest-friendly dimension stable for downstream consumers):

- `emb_distance_to_baseline` — L2 distance from this window's embedding to the centroid of all windows
- `{cmdline,registry,process,path}_rare_token_ratio` — fraction of tokens in this window seen ≤1 time in the baseline corpus

The bulk-of-windows assumption is the same one IsolationForest used to make. When labels are available, `BenignBaseline.fit(windows, benign_mask=...)` accepts a mask to refine the baseline.

---

### `detectors.py` — ATT&CK Rule Tagger + KB Hybrid Retrieval + Heuristic Scorer

#### Rule Tagger
Deterministic rule functions mapping to ATT&CK techniques:

| Technique | Condition |
|---|---|
| T1059.001 PowerShell | `powershell_count > 0` |
| T1021.002 SMB Shares | lateral-movement ports + >2 network connections |
| T1547.001 Registry Run Keys | `registry_modification_count > 3` |
| T1003 Credential Dumping | mimikatz detected |
| T1570 Lateral Tool Transfer | psexec detected |
| T1486 Ransomware | >50 file creations + suspicious process |
| T1071 C2 (App Layer) | >10 unique outbound IPs |

Confirmed hits get `source="rule"` and a confidence in [0, 1].

#### KB Hybrid Retrieval (`attack_kb.py`)
Wrapper around the cyber-anomaly KB (3463 indexed entries from Atomic Red Team, Sigma rules, ATT&CK descriptions). Combines:

- **Chroma** — dense semantic retrieval (sentence-transformer embeddings)
- **BM25** — sparse lexical retrieval over the same corpus

Results are fused via **Reciprocal Rank Fusion** (RRF, k=60). Top hits are returned with `source="kb"` and a normalised similarity score, plus the textual evidence that justified retrieval.

> **"Confirmed vs candidate" separation** is deliberate: the LLM Judge can discount KB candidates with weak evidence without inflating false positives, while still being prompted to consider novel techniques the rule tagger doesn't cover.

#### Heuristic Scorer (`heuristic_score(window)`)

Fuses four signals into `detector_score ∈ [0, 1]`:

| Signal | Weight | Notes |
|---|---|---|
| Rule hits | anchor ≥ 0.5 + 0.4×max(confidence) + 0.05 per extra hit | Audited deterministic signal |
| KB candidates | +0.05 each, cap 0.15 | Retrieval ≠ confirmation |
| Smart-feature flags (7) | +0.08 each | obfuscation, LOLBINs, base64 blobs, suspicious registry, exec write to temp/appdata, lateral port ratio ≥0.3, suspicious parent→child |
| Baseline deviation | +0.15 × min(emb_dist/1.5, 1) + 0.10 × max rare ratio | Catches novel windows no rule fires on |

**Why this replaced IsolationForest + GRU**: classical ML models add an opaque score the LLM Judge cannot audit. Each term in the heuristic score above is inspectable and can be cited in the evidence pack — aligned with the project's auditability goal. Empirical tests on LMD-2023 / Splunk Attack Data showed no meaningful gain from adding IForest/GRU on top of the signals already encoded here.

`ensemble_score()` is kept in the module as deprecated, only for backwards compatibility with notebooks.

---

### `slm_analyst.py` — SLM First-Pass Triage

**Model:** `phi3:medium` (configurable via `SLM_MODEL` in `.env`) via Ollama.

1. **Trivially-benign pre-filter** — Before any LLM call, `_is_trivially_benign()` skips windows with zero suspicious processes, no PowerShell, no mimikatz/psexec, no rule hits, no KB hits, fewer than 5 network connections, and no lateral-movement ports. On normal-traffic datasets this avoids the bulk of Ollama calls.
2. For remaining windows, an *evidence pack* (see `utils.py`) is assembled.
3. The pack is sent to Phi-3 with `format="json"` enforced at the Ollama API level. Generation capped at 384 tokens (the JSON schema is small).
4. Output parsed into `SLMAnalysis` (`pre_score`, `risk_level`, `suspected_techniques`, `risk_indicators`, `summary`, `needs_deep_analysis`).

The pre-diagnosis becomes a **hypothesis** that the Judge then validates or refutes — this is the anti-hallucination strategy.

---

### `llm_judge.py` — LLM Final Validation

**Model:** `llama3.2:latest` (configurable via `JUDGE_MODEL` in `.env`) via Ollama.

1. Receives the same evidence pack plus the `SLMAnalysis` hypothesis.
2. Uses `format="json"`; robust extraction via `_extract_json()` (direct parse → strip markdown fences → scan for first `{...}` block).
3. Produces `JudgeResult`:
   - `anomaly_score` (0–10)
   - `verdict` (normal / suspicious / malicious)
   - `techniques` — ATT&CK objects with `technique_id`, `name`, `confidence`, `evidence`
   - `rationale` — 2–3 sentence explanation
   - `fp_risk` (low / medium / high)
   - `unsupported_claims` — SLM claims the judge couldn't verify against the evidence

---

### `utils.py` — Shared Helpers

- **`build_evidence_pack(window)`** — Assembles the structured plain-text pack injected into every LLM prompt. Sections rendered in order:
  1. Aggregate stats (counts, entropies, flags)
  2. **Smart features** (semantic signals) — only groups with non-zero values shown, keeping the prompt compact
  3. **Baseline deviation** — embedding distance + per-field rare token ratios
  4. Rule tagger hits (`confirmed`)
  5. ATT&CK KB candidates (`retrieved, not confirmed`)
  6. Peak process chain — longest overlapping chain, ordered events
  7. Individual event samples — adaptive cap (15/30/50) based on window activity, command lines truncated at 120 chars to defuse prompt injection via log content
- **`setup_logging(level)`**, **`save_json` / `load_json`**, **`precision_recall_f1`** — small shared utilities.

---

### `pipeline.py` — Orchestrator

| Step | Action | Skippable |
|---|---|---|
| 1 | Parse input file (EVTX or CSV) | — |
| 2 | Windowing (60 s) + process chain extraction + baseline fit | — |
| 3 | ATT&CK rule tagging + KB retrieval + heuristic scoring | `--no-use-kb` disables retrieval |
| 4a | SLM pre-diagnosis (Phi-3 Medium) | `--skip-judge` |
| 4b | LLM Judge validation (Llama 3.1, up to 50 windows) | `--skip-judge` |
| 5 | Markdown report generation | — |
| 6 | Metrics (if `--evaluate`) | — |

Results written to `results/YYYY-MM-DD_HH-MM/`:

| File | Contents |
|---|---|
| `windows_scored.json` | All windows with detector_score, smart_features, baseline_features, attck_hits, peak_chain |
| `chains.json` | All reconstructed process chains |
| `evidence_packs.json` | Rendered evidence packs for windows above threshold (debug + audit) |
| `slm_analyses.json` | Phi-3 pre-diagnoses |
| `judge_results.json` | Llama 3.1 final verdicts |
| `report_<dataset>_<ts>.md` | Human-readable Markdown report |

---

## CLI Reference

```bash
# Full pipeline
python src/pipeline.py --input data/samples/sample_lmd.csv --dataset lmd

# Skip the LLM stages (heuristic detection only)
python src/pipeline.py --input data/samples/sample_lmd.csv --dataset lmd --skip-judge

# Disable the KB hybrid retrieval (rules only)
python src/pipeline.py --input data/samples/sample_lmd.csv --dataset lmd --no-use-kb

# Override threshold without editing .env
python src/pipeline.py --input data/samples/sample_lmd.csv --dataset lmd --threshold 0.4

# Evaluate with metrics (requires label column in CSV)
python src/pipeline.py --input data/samples/sample_lmd.csv --dataset lmd --evaluate

# Files with spaces — wrap in quotes
python src/pipeline.py --input "data/samples/LMD-2023 [1.75M Elements - Normal]checked.csv" --dataset lmd

# Preprocess only
python src/preprocessor.py --input data/samples/sample_lmd.csv --output results/windows.json
```

### All CLI options

| Option | Type | Default | Description |
|---|---|---|---|
| `--input` | path | required | CSV or EVTX input file |
| `--dataset` | str | `lmd` | CSV schema: `lmd`, `splunk`, `silrad` |
| `--output-dir` | path | `results/YYYY-MM-DD_HH-MM` | Output directory |
| `--model-dir` | path | — | Reserved for future use |
| `--skip-judge` | flag | off | Skip SLM Analyst + LLM Judge |
| `--threshold` | float | from `.env` | Override `ANOMALY_THRESHOLD` |
| `--use-kb / --no-use-kb` | flag | on | Toggle KB hybrid retrieval (Chroma + BM25) |
| `--evaluate` | flag | off | Compute metrics (requires `label` column) |
| `--verbose` | flag | off | DEBUG-level logging |

---

## Configuration (`.env`)

| Variable | Default | Description |
|---|---|---|
| `SLM_MODEL` | `phi3:medium` | Ollama model for SLM Analyst |
| `JUDGE_MODEL` | `llama3.2:latest` | Ollama model for LLM Judge |
| `ANOMALY_THRESHOLD` | `0.6` | Minimum detector_score to escalate to LLMs |
| `WINDOW_SIZE_SECONDS` | `60` | Time window size in seconds |
| `MAX_EVENTS_PER_WINDOW` | `200` | Event cap per window |

---

## Supported Datasets

| Dataset | Type | Notes |
|---|---|---|
| LMD-2023 | Sysmon Lateral Movement (1.75M events) | Primary evaluation; uses `systemtime` fallback if `utctime` is corrupt |
| Splunk Attack Data | Sysmon + ATT&CK labels | Technique-level evaluation |
| SILRAD | Sysmon ransomware + benign | Stress test |

---

## Design Decisions & Trade-offs

| Decision | Rationale |
|---|---|
| Fixed 60-second windows | Simple, reproducible, maps naturally to attack dwell time |
| Heuristic scorer instead of IsolationForest/GRU | Each term is auditable by the LLM Judge; opaque ML scores added no measurable gain over the encoded signals |
| Self-supervised baseline (centroid + token rarity) | No labels needed; same bulk-of-windows premise IForest assumed; surfaces novel windows no rule fires on |
| Field-aware tokenizers per Sysmon column | Cmdline, registry, paths and ports each have distinct structure; one-size tokenization loses signal |
| 27 smart features beyond counts/entropy | LOLBIN regex, suspicious parent→child pairs, suspicious registry subtrees etc. encode security knowledge directly |
| KB hybrid retrieval (Chroma + BM25, RRF) | Combines dense semantic + exact-token matching; no external API dependency |
| "Confirmed vs candidate" hit separation | Lets the Judge weigh deterministic rules higher than retrieved candidates |
| Two-LLM cascade (SLM → Judge) | Reduces hallucinations; the Judge has a hypothesis to verify, not a blank slate |
| `format="json"` in Ollama calls | Constrained decoding eliminates JSON parse failures |
| `_extract_json()` fallback chain | Handles markdown fences and stray prose from models that ignore `format` |
| All LLMs run locally (Ollama) | No data leaves the machine; reproducible offline; aligned with security-isolated environments |
| Trivially-benign pre-filter in SLM | Skips Ollama entirely for windows with no threat signals; critical for large normal-traffic datasets |
| `num_predict=384` in SLM | 6-field JSON response needs far fewer than 1024 tokens; ~40% faster generation |
| Adaptive evidence pack sample cap (15/30/50) | Low-activity windows get fewer sample lines; reduces prefill tokens without losing context |
| Process chains as ordered timelines | Gives the LLM cause-effect ordering instead of bag-of-events |
| `systemtime` fallback in LMD parser | LMD-2023 exports have truncated `utctime`; `systemtime` is always complete |
# DualSentinel — Technical Explanation

> **Histórico:** Este documento descreve a arquitetura *anterior* baseada em IsolationForest + GRU + ensemble ponderado.
> A versão atual substituiu esses detectores por um **heuristic scorer** (rules + smart features + baseline deviation) e removeu a flag `--skip-detectors`.
> Para a arquitetura atual ver [CONTEXT_PRESENTATION.md](CONTEXT_PRESENTATION.md) e [README.md](README.md).

## What is DualSentinel?

DualSentinel is a two-stage log anomaly detection pipeline for Windows Sysmon/ETW event logs. It combines classical machine learning detectors (the "first sentinel") with local LLM-based analysis and judgement (the "second sentinel") to identify threats and map them to the MITRE ATT&CK framework.

The name reflects the dual-layer architecture: fast statistical detectors act as a first gate, and language models act as a second, reasoning gate.

---

## High-Level Architecture

### Full pipeline (default)

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

### Detectors skipped — all windows to LLM (`--skip-detectors --threshold 0.0`)

IsolationForest and GRU are bypassed. The ATT&CK rule tagger still runs (it always does), and with `--threshold 0.0` **every window** is forwarded directly to the LLM stages regardless of rule hits.

On the LMD-2023 dataset this produces **687 350 events → 1 424 windows**, all passed to SLM, with the Judge capped at the first 50.

```
LMD-2023 [1.75M Elements - Normal]checked.csv
        │
        ▼
┌─────────────────────────────────────────────────────────────┐
│   Preprocessor                                              │
│   687 350 events loaded → 1 424 × 60-second windows        │
└─────────────────────────────────────────────────────────────┘
        │
        ▼
┌──────────────────────────────────────────────────────────┐
│   ATT&CK Rule Tagger  (always runs)                      │  technique hits only
│   IsolationForest score = 0 / GRU score = 0  (zeroed)   │  detector_score ≤ 0.2
└──────────────────────────────────────────────────────────┘
        │  threshold = 0.0 → all 1 424 windows pass
        ▼
┌──────────────────────────────────────────────────────────┐
│   SLM Analyst  (Phi-3 Medium)                            │
│   1 424 windows analysed sequentially                    │  pre_score, risk_level,
│   → slm_analyses.json                                    │  suspected_techniques
└──────────────────────────────────────────────────────────┘
        │  top 50 windows (by detector_score, then time order)
        ▼
┌──────────────────────────────────────────────────────────┐
│   LLM Judge  (Llama 3.2)                                 │
│   50 / 1 424 windows judged (max_windows cap)            │  anomaly_score, verdict,
│   → judge_results.json                                   │  ATT&CK techniques
└──────────────────────────────────────────────────────────┘
        │
        ▼
┌────────────────────┐
│   Results          │  JSON files + Markdown report
└────────────────────┘
```

> **Note:** With all detector scores at `0.0` the Judge's 50-window cap takes the first 50 windows in time order. For full coverage on large datasets raise the cap via `max_windows` in `judge_batch()` or pre-filter with `--skip-detectors --threshold 0.2` to still benefit from ATT&CK rule hits as a gate.

> **Common mistake:** Running `--skip-detectors` without `--threshold` leaves the default threshold at `0.6`. Since the maximum possible `detector_score` with detectors skipped is `0.2` (ATT&CK rule hits only), **0 windows will ever reach the SLM/Judge**. Always pair `--skip-detectors` with an explicit `--threshold`.

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
1. **Trivially-benign pre-filter** — Before calling Ollama, `_is_trivially_benign()` checks the window's feature values. If a window has zero suspicious processes, no PowerShell, no mimikatz/psexec, no ATT&CK rule hits, fewer than 5 network connections, and no lateral movement ports, it is immediately classified as `risk_level=low / pre_score=0` with no LLM call. On normal-traffic datasets (e.g. LMD-2023) this skips the vast majority of windows.
2. For remaining windows, an *evidence pack* is assembled.
3. The pack is sent to Phi-3 with `format="json"` enforced at the Ollama API level, guaranteeing valid JSON output. Token generation is capped at **384 tokens** (sufficient for the 6-field JSON response).
4. The response is parsed into an `SLMAnalysis` dataclass:
   - `pre_score` (0–10) — initial risk score
   - `risk_level` (low / medium / high / critical)
   - `suspected_techniques` — list of suspected MITRE technique names
   - `risk_indicators` — list of specific textual indicators
   - `summary` — 1–2 sentence pre-diagnosis
   - `needs_deep_analysis` — boolean flag

**Design rationale:** Phi-3 Medium is fast for a triage task. The trivially-benign pre-filter eliminates Ollama calls for windows with no threat signals, dramatically reducing wall-clock time on large normal-traffic datasets. Its output is used as a *hypothesis* that the LLM Judge then validates or refutes.

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

- **`build_evidence_pack(window)`** — Assembles the structured plain-text evidence pack injected into every LLM prompt. Includes aggregate statistics, ATT&CK rule-tagger hits, and individual event sample lines. Sample line count is **adaptive**: 15 lines for `event_count < 20`, 30 for `< 60`, 50 otherwise — reducing prefill tokens for low-activity windows. Command lines are truncated at 120 characters to prevent prompt injection via log content.
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

# Skip IsolationForest + GRU, use ATT&CK rule hits as the only gate
# NOTE: --threshold is required — omitting it keeps the default 0.6 which lets 0 windows through
python src/pipeline.py --input data/samples/sample_lmd.csv --dataset lmd --skip-detectors --threshold 0.2

# Skip all detectors, send every window to SLM + Judge (slow on large datasets — 1424 windows on LMD-2023)
python src/pipeline.py --input data/samples/sample_lmd.csv --dataset lmd --skip-detectors --threshold 0.0

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
| Trivially-benign pre-filter in SLM | Skips Ollama entirely for windows with no threat signals; critical for large normal-traffic datasets |
| `num_predict=384` in SLM | 6-field JSON response needs far fewer than 1024 tokens; ~40% faster generation per call |
| Adaptive evidence pack sample cap | Low-activity windows get fewer sample lines (15/30/50); reduces prefill tokens without losing context |
| `sleep(0.05)` between SLM calls | Ollama handles backpressure natively; 0.2 s sleep saved ~213 s on 1 424-window LMD-2023 run |
