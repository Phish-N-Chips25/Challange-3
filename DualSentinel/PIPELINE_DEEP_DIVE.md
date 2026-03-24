# DualSentinel — Pipeline Deep Dive

A step-by-step walkthrough of every stage: what happens, why each design choice was made, and what could reasonably be done differently.

---

## Overview

```
CSV / EVTX
    │
    ▼
┌─────────────────────────────────────────────────────────────────┐
│  Step 1 — Parse                                                 │
│  parse_csv() / parse_evtx()  →  normalised DataFrame           │
└─────────────────────┬───────────────────────────────────────────┘
                      │ ~687k rows (LMD-2023)
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│  Step 2 — Windowing                                             │
│  make_windows()  →  1,424 × WindowFeatures                      │
└─────────────────────┬───────────────────────────────────────────┘
                      │ feature matrix  (1424 × 17)
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│  Step 3 — IsolationForest  (skippable)                          │
│  IForestDetector.fit() + .score()  →  if_score [0,1] per window │
└─────────────────────┬───────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│  Step 4 — GRU Autoencoder  (skippable)                          │
│  GRUDetector.fit() + .score()  →  reconstruction error per seq  │
└─────────────────────┬───────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│  Step 5 — ATT&CK Rule Tagger + Ensemble Score                   │
│  tag_techniques() + ensemble_score()  →  detector_score [0,1]   │
└─────────────────────┬───────────────────────────────────────────┘
                      │ windows above threshold
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│  Step 6a — SLM Analyst  (phi3:mini via Ollama)                  │
│  SLMAnalyst.analyse_batch()  →  SLMAnalysis per window          │
└─────────────────────┬───────────────────────────────────────────┘
                      │ top-50 windows with SLM pre_score as tiebreaker
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│  Step 6b — LLM Judge  (llama3.2 via Ollama)                     │
│  LLMJudge.judge_batch()  →  JudgeResult per window              │
└─────────────────────┬───────────────────────────────────────────┘
                      │
                      ▼
             Markdown report + JSON artefacts
```

---

## Step 1 — Parse (`preprocessor.py → parse_csv / parse_evtx`)

### What happens

The raw log file is loaded into a pandas DataFrame and normalised to a canonical schema regardless of source format. Three dataset formats are supported via column-name mapping tables (`lmd`, `splunk`, `silrad`). After renaming, the code:

1. Parses timestamps with `pd.to_datetime(format="mixed", utc=True)` — handles both ISO-8601 and Windows FILETIME strings.
2. Falls back from `utctime` to `systemtime` when the primary timestamp column is entirely `NaT` (a known issue in some LMD-2023 exports).
3. Normalises `process_name` to basename + lowercase using vectorised pandas string ops (`.str.replace` / `.str.split` / `.str[-1]`).
4. Filters to only the 19 Sysmon EventIDs that are relevant to threat detection (EID 1, 3, 5, 6, 7, 8, 10, 11, 12, 13, 15, 16, 17, 18, 22, 23, 25).

For EVTX files, `parse_evtx` uses `python-evtx` to deserialise binary Windows Event Log records into the same schema.

### Why this way

- **Column mapping tables** keep all format-specific knowledge in one place rather than scattered through conditionals.
- **Vectorised basename extraction** avoids 687k Python-level `Path()` calls; the same result at a fraction of the CPU time.
- **EventID allowlist** reduces the DataFrame by roughly 60–70 % before any further work, making windowing and feature extraction proportionally faster.
- **UTC normalisation** ensures that time comparisons in windowing are unambiguous regardless of where the log was collected.

### What could be done differently

| Option | Trade-off |
|--------|-----------|
| **Polars instead of pandas** | 3–10× faster parse and normalisation; requires rewriting downstream code that expects a pandas DataFrame. |
| **Schema validation (pandera / great_expectations)** | Catches malformed CSVs early with actionable error messages, at the cost of an extra dependency and a small extra pass over the data. |
| **Streaming parse (chunked `read_csv`)** | Allows processing files larger than RAM; adds complexity to windowing since windows can span chunk boundaries. |
| **Broader EventID set** | Including EIDs like 4624/4625 (logon events) or 4688 (process creation via Security log) would enrich credential-related detections but requires a different log source. |

---

## Step 2 — Windowing (`preprocessor.py → make_windows`)

### What happens

`make_windows` slices the sorted DataFrame into fixed 60-second tumbling windows. For each non-empty window it computes a `WindowFeatures` dataclass with 17 numerical fields:

- **Count-based features**: `event_count`, `process_creation_count`, `network_connection_count`, `file_creation_count`, `registry_modification_count`, `powershell_count`, `cmd_count`, `suspicious_process_count`, `lateral_movement_port_count`, `outbound_unique_ips`
- **Cardinality features**: `unique_event_ids`, `unique_processes`, `unique_users`
- **Boolean flags**: `has_mimikatz`, `has_psexec`
- **Entropy features**: `event_id_entropy`, `process_entropy` — Shannon entropy measures how diverse the events or processes are within the window

It also builds `event_summaries` — a list of up to 50 one-line text representations of individual events. These are used later to populate the evidence pack for the LLM stages. The inner loop uses `itertuples` (not `iterrows`) for the summary pass because it gives direct attribute access at C speed.

### Why 60 seconds

A 60-second window is a common baseline in Sysmon-based detection research. It is long enough to capture multi-step attack sequences (e.g. reconnaissance → lateral movement) but short enough to localise the anomaly in time. The window size is configurable via `WINDOW_SIZE_SECONDS` env var.

### Why a fixed tumbling window

Fixed tumbling windows are deterministic, easy to implement, and produce a consistent feature matrix for the ML detectors. The alternative (sliding or session-based windows) would multiply the number of windows and complicate the timestamp boundaries.

### What could be done differently

| Option | Trade-off |
|--------|-----------|
| **Sliding windows** | Captures events that span a boundary more faithfully; produces O(n) more windows, increasing LLM cost significantly. |
| **Session-based windows** (split on logon/logoff) | Semantically meaningful; requires reliable session markers that are not always present. |
| **Variable-length windows** (split on activity bursts) | Better at capturing bursty attack sequences; much harder to implement and to feed to fixed-input ML models. |
| **More features** | Adding parent-child process pairs, rare EventID sequences, or time-of-day could improve ML detector signal at negligible extra cost. |
| **`process_entropy` on full names vs basenames** | The current code lowercases to basename before entropy; full path entropy would give a different (not necessarily better) signal. |

---

## Step 3 — IsolationForest (`detectors.py → IForestDetector`)

### What happens

`IForestDetector` wraps sklearn's `IsolationForest` with a `StandardScaler` pre-processor. It is trained **on the same data it scores** — a one-class, unsupervised setup. The anomaly score is derived from `decision_function`, inverted (so higher = more anomalous), and min-max normalised to `[0, 1]`.

Parameters used:
- `n_estimators=200` — number of trees; more trees = more stable scores
- `contamination=0.05` — assumes 5 % of windows are anomalous (used only for `predict`; the raw scores used here are not affected)
- `n_jobs=-1` — uses all CPU cores

A fitted model is saved to `iforest.pkl` and reloaded on subsequent runs.

### Why IsolationForest

- No labelled data is needed — IsolationForest is purely unsupervised and well-suited to log data where attacks are rare and unknown in advance.
- It works directly on the 17-dimensional numeric feature vector without hyperparameter-heavy tuning.
- Training is fast even on 1,424 windows.

### What could be done differently

| Option | Trade-off |
|--------|-----------|
| **OCSVM (One-Class SVM)** | Often more accurate on high-dimensional data; significantly slower to train (~O(n²)). |
| **LOF (Local Outlier Factor)** | Better at detecting local clusters of anomalies; does not support `predict` on new data without refitting. |
| **Autoencoder (fully connected)** | Can learn non-linear relationships between features; requires more data and tuning to avoid overfitting to noise. |
| **Train on a labelled normal baseline, score on live data** | More realistic deployment; requires a separate clean baseline dataset to be collected and managed. |
| **PCA-based anomaly score** | Extremely fast; loses non-linear relationships captured by tree-based partitioning. |

---

## Step 4 — GRU Autoencoder (`detectors.py → GRUDetector`)

### What happens

`GRUDetector` implements a GRU-based autoencoder for **temporal anomaly detection**. Rather than scoring each window independently, it scores **sequences of 10 consecutive windows**. The model learns to reconstruct normal sequences; a high mean-squared reconstruction error indicates the sequence deviates from the learned normal pattern.

Architecture:
- **Encoder**: single GRU layer, `hidden_dim=64`
- **Decoder**: single GRU layer that takes the encoder's final hidden state expanded to sequence length, reconstructing the original input

Training:
- 30 epochs, Adam optimiser, MSE loss
- Anomaly threshold set at the 95th percentile of reconstruction errors on the training set
- Scores are normalised by the training maximum before adding to the ensemble

If PyTorch is not installed, the detector silently falls back to a stub that returns zeros (i.e. contributes nothing to the ensemble).

### Why a GRU

IsolationForest treats each window independently — it has no notion of temporal order. The GRU adds a complementary signal: whether the *sequence* of windows is unusual, which is valuable for detecting slow, multi-stage attacks that look individually normal but are anomalous in their progression.

### What could be done differently

| Option | Trade-off |
|--------|-----------|
| **LSTM instead of GRU** | Similar performance; slightly more parameters and slower to train. |
| **Transformer encoder** | Better long-range dependency modelling; overkill for 10-step sequences, more difficult to run without a GPU. |
| **Longer sequences (e.g. 30 windows = 30 minutes)** | Captures longer attack dwell times; requires more training data to converge. |
| **Supervised RNN** (with labelled attack sequences) | Significantly better detection quality when labels are available. |
| **Save/load the trained GRU model** | Currently the GRU is retrained from scratch every run. Persisting the model (like IForest does) would save 30–60 seconds of training time. This is the most impactful missing feature in this step. |

---

## Step 5 — ATT&CK Rule Tagger + Ensemble Score (`detectors.py → tag_techniques, ensemble_score`)

### What happens

**Rule tagger**: 7 hand-coded rules map feature values directly to MITRE ATT&CK techniques. Each rule is a lambda over the window dict; if it fires, a hit `{technique, name, confidence, source}` is appended. Examples:

| Rule | Condition | Technique |
|------|-----------|-----------|
| T1059.001 | `powershell_count > 0` | PowerShell Execution |
| T1003 | `has_mimikatz == True` | Credential Dumping |
| T1486 | `file_creation_count > 50` AND suspicious process | Ransomware |
| T1071 | `outbound_unique_ips > 10` | C2 Communication |

**Ensemble score**: combines the IsolationForest score, GRU score, and a boolean flag for ATT&CK rule hits into a single `detector_score [0, 1]` that drives escalation to the LLM stages. When detectors are skipped (`--skip-detectors`), `if_score` and `gru_score` are both 0.0, so `detector_score` is at most 0.2 (from rule hits alone).

### Why explicit rules alongside ML

Rules are **interpretable by default** — when a rule fires it names the ATT&CK technique and its confidence. The ML detectors produce a scalar score but no explanation. Rules also catch known-bad patterns (Mimikatz, PsExec) with near-certainty even on a dataset with very few such events.

### What could be done differently

| Option | Trade-off |
|--------|-----------|
| **Sigma rules parser** | Industry-standard detection rule format; would allow importing the community's full Sigma ruleset instead of 7 hand-coded rules. Implementation complexity is significant. |
| **Learned ensemble weights** (logistic regression meta-model) | Instead of hard-coded weights, learn the optimal combination of IF, GRU, and rule scores from labelled data. Requires labels. |
| **Detection confidence intervals** | Instead of a point score, produce a score distribution to quantify uncertainty before escalating to the LLM. |
| **More ATT&CK rules** | The current 7 rules cover common techniques but miss many others (e.g. T1055 Process Injection based on EID 8/10, T1078 Valid Accounts, T1562 Impair Defences). Expanding the ruleset is low-effort and high-value. |

---

## Step 6a — SLM Analyst (`slm_analyst.py → SLMAnalyst`)

### What happens

The SLM Analyst sends each window above the `detector_score` threshold to a **small language model** (default: `phi3:mini` via Ollama) for rapid first-pass triage. It returns a structured JSON pre-diagnosis:

```json
{
  "pre_score": 4,
  "risk_level": "medium",
  "suspected_techniques": ["PowerShell Execution"],
  "risk_indicators": ["powershell_count=3"],
  "summary": "Moderate PowerShell activity; no confirmed lateral movement.",
  "needs_deep_analysis": false
}
```

**Performance optimisations applied:**

1. **`_is_trivially_benign` pre-filter** — windows with zero suspicious processes, no PowerShell, no Mimikatz/PsExec, no ATT&CK hits, fewer than 5 network connections, and no lateral-movement ports are returned immediately as `pre_score=0, needs_deep_analysis=False` without touching Ollama.
2. **`num_predict=384`** — limits the token budget to what a pré-diagnosis needs; prevents the model from generating verbose prose.
3. **Selective sleep** — the 0.05 s yield only fires after real Ollama calls, not for pre-filtered windows.
4. **Evidence pack caching** — `build_evidence_pack` stores its result in `window["_evidence_pack"]`; if the same window is later processed by the Judge, the pack is not rebuilt.

The `analyse()` method returns `(SLMAnalysis, called_ollama: bool)` so `analyse_batch` can track how many windows actually hit Ollama.

### Why a small model for triage

Running the full Judge (llama3.2) on all 1,424 windows would be prohibitively slow. phi3:mini is ~2× faster than llama3.2 per call, produces enough signal to decide whether a window warrants deep analysis, and its pre-diagnosis is then provided to the Judge as a hypothesis to validate — improving the Judge's grounding without increasing its token budget.

### What could be done differently

| Option | Trade-off |
|--------|-----------|
| **`phi3:medium` instead of `phi3:mini`** | Better reasoning quality; ~2× slower. Worth considering when the dataset has many marginal windows. |
| **`gemma2:2b` or `qwen2.5:3b`** | Alternative small models with different strengths; quality is dataset-dependent. |
| **Batch Ollama inference** | Ollama does not natively support multi-sequence batching the way vLLM does; a local vLLM or llama.cpp server could run ~4–8 windows in parallel on a GPU, cutting wall-clock time by 4–8×. |
| **Stricter pre-filter thresholds** | Raising the pre-filter to also skip windows with only 1–2 network connections would reduce Ollama calls further; risk of missing edge-case anomalies. |
| **Cache SLM results across runs** | Persist `slm_analyses.json` keyed by `(window_start, event_count_hash)`; skip re-inference on re-runs with the same input. Very useful during development. |

---

## Step 6b — LLM Judge (`llm_judge.py → LLMJudge`)

### What happens

The LLM Judge is the final, most expensive stage. It runs **llama3.2** (default) on the top-50 windows by `detector_score`, using the SLM pre-diagnosis as a hypothesis to validate. The Judge is instructed to:

1. Validate or refute the SLM's pre-diagnosis using explicit evidence from the pack.
2. Map observed behaviours to ATT&CK techniques with evidence citations.
3. Assign an `anomaly_score [0–10]` and a `verdict` (`normal / suspicious / malicious`).
4. Flag SLM claims that are **not** supported by the evidence pack (`unsupported_claims`).

**Performance optimisations applied:**

1. **SLM pre_score tiebreaker sort** — when `--skip-detectors` is used, all `detector_score` values are equal. Without a tiebreaker, the first 50 windows in time order reach the Judge. With the tiebreaker `(detector_score, slm.pre_score)`, the 50 most suspicious windows (per SLM) are judged instead.
2. **Skip low-risk windows** — windows where `slm.needs_deep_analysis=False` and `slm.pre_score < 3` are dropped entirely before the Judge call.
3. **`num_predict=1024`** — sufficient for structured JSON with rationale and a few technique entries; a 2048-token response would mostly be empty padding.
4. **`sleep=0.1 s`** between calls — minimal thermal/rate pacing.

The JSON extraction uses a three-step fallback: direct parse → strip markdown fences → `re.search(r'\{.*\}', raw, re.DOTALL)`.

### The anti-hallucination design

The Judge prompt is explicitly adversarial: it tells the model to call out unsupported claims, penalise technique assertions without evidence, and mark each technique with `"Evidence: [cite]"`. This is important because LLMs will confidently invent details if not constrained. The instruction to treat the SLM output as a **hypothesis**, not a fact, prevents the Judge from simply echoing the SLM's mistakes.

### What could be done differently

| Option | Trade-off |
|--------|-----------|
| **`llama3.1:70b` or `mixtral:8x7b`** | Significantly better reasoning and fewer hallucinations; requires 48+ GB VRAM or a multi-GPU setup. |
| **Structured output with JSON schema enforcement** | Ollama supports `format=json` but does not validate against a schema. Using `outlines` or `guidance` would guarantee the response matches the expected schema and eliminate `_extract_json` entirely. |
| **Self-consistency sampling** | Run the Judge 3 times per window with `temperature=0.5` and take the majority verdict; reduces variance at 3× the cost. |
| **RAG (Retrieval-Augmented Generation)** | Embed ATT&CK technique descriptions and retrieve the relevant ones before prompting, giving the Judge precise technique definitions without baking them into the system prompt. |
| **Increase `max_windows` beyond 50** | The 50-window cap is a cost safeguard. For a smaller or pre-filtered dataset it could safely be raised to 100–200. |
| **Judge confidence score** | The current schema has `fp_risk` but not a calibrated confidence value. Adding `confidence: float [0,1]` to the JSON schema would enable downstream filtering. |

---

## Evidence Pack (`utils.py → build_evidence_pack`)

The evidence pack is the text representation of a window that both the SLM and the Judge see. It contains:

- Aggregate statistics (counts, entropy, flags)
- ATT&CK rule tagger hits with confidence scores
- Up to 50 individual event summary lines (EID, process, dst IP, file, truncated command line)

**Adaptive sample cap**: the number of individual event lines included scales with `event_count` — 15 lines for sparse windows, 30 for medium, 50 for dense. This avoids wasting tokens on identical repeated events in quiet windows.

**Injection hardening**: command lines are truncated to 120 characters and ` ``` ` sequences are replaced with `'''` to prevent a crafted log entry from breaking out of the evidence block and injecting instructions into the prompt.

**Caching**: the built string is stored in `window["_evidence_pack"]`. The first call (usually from the SLM) builds it; the second call (from the Judge on the same window) returns it instantly.

### What could be done differently

| Option | Trade-off |
|--------|-----------|
| **Token-count-aware cap** (use a tokeniser to count tokens) | More precise than a line count; avoids the case where long command lines push the pack over the model's context limit. Adds a dependency on `tiktoken` or similar. |
| **Deduplicate event summaries** | Many windows will have dozens of identical events (e.g. `EID=3 proc=chrome.exe dst=...`). Grouping repeated lines as `× N` would reduce pack size without losing information. |
| **Structured JSON evidence pack** | Passing the pack as JSON rather than plain text would let the model reference specific fields by name; plain text is simpler and equally effective in practice. |

---

## The `--skip-detectors --threshold 0.0` Mode

When both flags are used together, the pipeline bypasses IsolationForest and GRU entirely and routes **all 1,424 windows** through the LLM stages. This is useful when:

- No labelled normal baseline is available for the detectors to train on.
- The dataset is small enough that running LLMs on every window is feasible.
- You want to audit the entire dataset without trusting the ML layer's threshold.

The cost is that every non-trivially-benign window is sent to the SLM, and the top 50 by SLM score go to the Judge — without any prior filtering by detector signal. On the Normal LMD-2023 dataset this means ~400–800 real SLM Ollama calls (depending on how many windows the pre-filter catches), plus up to 50 Judge calls.

---

## End-to-End Execution Summary (LMD-2023, `--skip-detectors --threshold 0.0`)

| Step | Input | Output | Bottleneck |
|------|-------|--------|-----------|
| Parse | 1.75 M rows CSV | ~687 k filtered events | I/O + pandas |
| Windowing | 687 k events | 1,424 windows × 17 features | CPU (vectorised) |
| IForest/GRU | — | skipped | — |
| Rule tagger | 1,424 windows | attck_hits + detector_score | CPU |
| SLM | 1,424 windows | 1,424 SLMAnalysis | **Ollama GPU/CPU** |
| Judge | top-50 (by SLM score) | ≤50 JudgeResult | Ollama GPU/CPU |
| Report | all results | Markdown + 3 JSON files | I/O |
