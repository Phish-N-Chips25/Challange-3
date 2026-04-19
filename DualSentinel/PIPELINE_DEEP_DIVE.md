# DualSentinel — Pipeline Deep Dive

A step-by-step walkthrough of every stage in the current pipeline: what happens, why each design choice was made, and what could reasonably be done differently.

For a higher-level overview see [EXPLANATION.md](EXPLANATION.md); for the academic/presentation framing see [CONTEXT_PRESENTATION.md](CONTEXT_PRESENTATION.md).

---

## Pipeline Overview

```
┌──────────────────────────────────────────────────────────────────┐
│  Step 1 — Parse                                                  │
│  parse_csv() / parse_evtx()  →  pandas DataFrame                 │
└──────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌──────────────────────────────────────────────────────────────────┐
│  Step 2 — Windowing + chains + baseline                          │
│  make_windows()      →  list[WindowFeatures]  (112-dim vectors)  │
│  make_chains()       →  list[ProcessChain]   (parent→child)      │
│  BenignBaseline.fit  →  centroid + token frequency tables        │
└──────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌──────────────────────────────────────────────────────────────────┐
│  Step 3 — Detection                                              │
│  tag_techniques_with_kb()  →  rule hits + KB candidates          │
│  heuristic_score()         →  detector_score [0,1] per window    │
│  chains_for_window()       →  attach peak_chain                  │
└──────────────────────────────────────────────────────────────────┘
                                │  windows ≥ threshold
                                ▼
┌──────────────────────────────────────────────────────────────────┐
│  Step 4 — LLM cascade (skippable)                                │
│  4a  SLMAnalyst.analyse_batch()  →  pre-diagnosis (Phi-3)        │
│  4b  LLMJudge.judge_batch()      →  final verdict (Llama 3.1)    │
└──────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌──────────────────────────────────────────────────────────────────┐
│  Step 5 — Report                                                 │
│  generate_report()  →  Markdown + JSON artifacts                 │
└──────────────────────────────────────────────────────────────────┘
```

---

## Step 1 — Parse (`preprocessor.py → parse_csv / parse_evtx`)

**What it does**

Reads either `.csv` or `.evtx`. CSV parsing supports three dataset schemas (`lmd`, `splunk`, `silrad`); each has a column-name map that normalises the data into a **canonical 23-field schema**:

```
timestamp, event_id, process_name, process_id, process_guid,
parent_process, parent_id, parent_guid, command_line,
user, host, image, parent_image,
file_path, registry_key, registry_value,
network_src_ip, network_src_port, network_dest_ip, network_dest_port,
hash, signature, label
```

**Why a canonical schema**

Downstream code (windowing, embeddings, smart features, evidence pack, ATT&CK rules) shouldn't care whether the input came from LMD or Splunk. The schema lets us add a new dataset by writing one column-name map.

**`process_guid` synthesis**

Process chain reconstruction requires `process_guid`. Some datasets (Splunk, SILRAD) don't carry it. When absent, `parse_csv` synthesises one as `sha1(host|process_id|image)[:32]` — stable per logical process within a host.

**`utctime` → `systemtime` fallback (LMD-only)**

LMD-2023 exports occasionally truncate `utctime`. The parser checks for parsing failures and silently retries with `systemtime`, which is always present and well-formed.

**EventID filter**

Sysmon emits ~30 EID types; only those carrying signal for behavioural detection are retained: 1, 3, 5, 6, 7, 8, 10, 11, 12, 13, 15, 16, 17, 18, 22, 23, 25.

---

## Step 2a — Windowing (`preprocessor.py → make_windows`)

**What it does**

Groups events into fixed 60-second non-overlapping windows. Each window becomes a `WindowFeatures` dataclass holding:

- 21 base fields (counts per EID, entropy, suspicious-process flags, lateral port count, …)
- A 64-dim hash embedding (`embedding`)
- A `smart_features: dict` (27 named features)
- A `_field_tokens: dict` (per-field tokenized strings, retained for the baseline pass)
- An `event_summaries: list[str]` (up to 50 human-readable lines for the evidence pack)

`MAX_EVENTS_PER_WINDOW=200` caps the events fed to embeddings/summaries (memory bound).

### The 112-dim feature vector

`WindowFeatures.to_feature_vector()` concatenates three blocks:

| Block | Dims | Source |
|---|---|---|
| **Base** | 21 | counts, entropies, flags |
| **Smart features** | 27 | semantic indicators (ordered by `SMART_FEATURE_NAMES`) |
| **Hash embeddings** | 64 | mean-pooled per-field then sum-bucketed (4 fields × 16 dims) |

The vector is currently **not** consumed by an ML model in the active pipeline — IForest and GRU were removed. It's still exposed because: (a) future ML detectors may want it, (b) notebooks use it for ad-hoc analysis, and (c) cosine similarity on this vector is a cheap nearest-neighbour signal for analysts.

---

## Step 2b — Embeddings & Smart Features (`embeddings.py`)

### Field-aware tokenizers

Each Sysmon string column has its own tokenizer because their structure differs:

| Field | Tokenizer | Notes |
|---|---|---|
| `command_line` | `tokenize_cmdline` | shell-aware split, preserves flags (`-foo`, `/bar`), expands embedded paths into extra tokens |
| `registry_key` | `tokenize_registry` | path split, hive canonicalised (HKLM/HKCU/HKCR/HKU/HKCC) |
| `process_name` | `tokenize_process` | basename + extension as separate tokens |
| `file_path` | `tokenize_path` | path split, lowercased |
| `network_dest_port` | `tokenize_port` | categorised: lateral / well_known / registered / dynamic / rare_high |

### Hash embedding (`HashingVectorizer`)

Each field has its own `HashingVectorizer` (sklearn, no external dependencies, n_features=128, L2-normalised, non-negative). Workflow per window:

1. Tokenize every event row in the window (per field).
2. `embed_tokens` → sparse matrix `(N_events, 128)`.
3. `mean_pool` → dense `(128,)` per field.
4. **Sum-bucket reduction** to 16 dims (`buckets = full.reshape(16, -1).sum(axis=1)`) + L2 normalise.

Final per-window embedding = `concat(cmd_emb, reg_emb, proc_emb, path_emb)` → 64 dims.

**Why HashingVectorizer not TF-IDF or transformers**: it's stateless (no vocab fitting, no train/test split issues), the dictionary attack token never gets dropped as OOV, and it has zero dependencies beyond sklearn. The information loss from hashing collisions is tolerable at 128 dims for the field volumes we see.

### 27 smart features (`SMART_FEATURE_NAMES`)

Grouped by source field:

- **cmdline (7):** avg_len, max_len, avg_token_entropy, obfuscation_hits (regex: `-enc`, `FromBase64String`, `IEX`, `vssadmin delete`, `bcdedit`, `net user /add`, `-WindowStyle Hidden`, …), b64_blob_count (≥80-char base64 runs), flag_density, lolbin_calls (certutil, mshta, regsvr32, rundll32, …)
- **registry (6):** hive_hklm_ratio, hive_hkcu_ratio, hive_other_ratio, avg_depth, suspicious_path_hits (Run, RunOnce, Winlogon, IFEO, Services, AppInit_DLLs, KnownDLLs, ShellExecuteHooks, …), unique_subtrees
- **paths (6):** avg_depth, temp_ratio, appdata_ratio, system32_ratio, unique_extensions, executable_writes
- **ports (5):** lateral_ratio, well_known_ratio, dynamic_ratio, rare_high_count, category_entropy
- **process tree (3):** unique_pairs, pair_entropy, suspicious_pairs (`{winword,excel,powerpnt,outlook,explorer,services,lsass,wininit}.exe → {powershell,cmd,wscript,cscript,rundll32,regsvr32,mshta}.exe`)

These features go into the 112-dim vector **and** are surfaced to the LLM via the evidence pack (only non-zero values rendered, to keep the prompt compact).

---

## Step 2c — Process Chains (`chains.py → make_chains`)

Groups events by `process_guid`, then for each chain computes:

- `length` — number of events
- `duration_seconds` — last − first event timestamp
- `child_count` — distinct child `process_guid`s spawned
- `event_summaries` — chronologically-ordered one-line summaries (capped)

`chains_for_window(chains, ws_dt, we_dt)` returns chains overlapping a given window; the longest one is attached as `peak_chain` so the LLM gets a coherent timeline rather than bag-of-events.

---

## Step 2d — Self-Supervised Baseline (`embeddings.py → BenignBaseline`)

`BenignBaseline().fit(windows)` builds:

- **Centroid** = mean of per-window embeddings
- **Token frequency tables** per field (cmdline, registry, process, path)

`baseline.annotate(windows)` then writes `window.baseline_features` with:

- `emb_distance_to_baseline` (L2)
- `{cmdline,registry,process,path}_rare_token_ratio` — fraction of tokens with frequency ≤ `RARE_THRESHOLD` (=1) in the baseline

**Premise:** the bulk of windows is benign — same one IForest's `contamination=0.05` made. With labels available, `fit(windows, benign_mask=...)` accepts a boolean mask to refine.

These features are intentionally outside the 112-dim vector (so dimension stays stable across runs) and are surfaced only to the LLM via the evidence pack and to the heuristic scorer.

---

## Step 3 — ATT&CK Rule Tagger + KB + Heuristic Score (`detectors.py`, `attack_kb.py`)

### Rule tagger

Hand-written predicates over `WindowFeatures` fields. Every hit emits:

```python
{"technique": "T1059.001", "name": "PowerShell",
 "confidence": 0.85, "source": "rule", "evidence": "<short text>"}
```

Rules are conservative — they fire only when behaviour is unambiguous (e.g. `powershell_count > 0`, mimikatz string match). False positive risk is low; coverage gap is filled by the KB and the LLM.

### KB hybrid retrieval (`tag_techniques_with_kb`)

When `use_kb=True`:

1. Builds a query string from the window: top processes + top ports + top registry subtrees + top file extensions (capped to ~200 chars).
2. Calls the cyber-anomaly KB wrapper, which runs **Chroma** (dense, sentence-transformer embeddings) and **BM25** (sparse, exact-token) over 3463 indexed entries (Atomic Red Team tests, Sigma rule descriptions, ATT&CK technique pages).
3. Fuses the two ranked lists via **Reciprocal Rank Fusion** (RRF, k=60).
4. Top hits are converted to `attck_hits` entries with `source="kb"` and the textual excerpt as evidence.

**Why hybrid not pure dense**: rare attacker tokens (`mimikatz`, `psexec`, `vssadmin`) are exact-match signals BM25 catches that dense embeddings can blur. RRF combines the strengths without tuning a weight.

### Heuristic scorer (`heuristic_score(window)`)

Single function, fully deterministic:

```python
def heuristic_score(window: dict) -> float:
    score = 0.0

    rule_hits = [h for h in window["attck_hits"] if h["source"] == "rule"]
    kb_hits   = [h for h in window["attck_hits"] if h["source"] == "kb"]
    if rule_hits:
        max_conf = max(h["confidence"] for h in rule_hits)
        score += 0.5 + 0.4 * max_conf + 0.05 * (len(rule_hits) - 1)
    score += min(0.15, 0.05 * len(kb_hits))

    smart = window.get("smart_features", {})
    flags = [
        smart["cmdline_obfuscation_hits"] > 0,
        smart["cmdline_lolbin_calls"]     > 0,
        smart["cmdline_b64_blob_count"]   > 0,
        smart["reg_suspicious_path_hits"] > 0,
        smart["path_executable_writes"]   > 0 and (smart["path_temp_ratio"] > 0
                                                 or smart["path_appdata_ratio"] > 0),
        smart["port_lateral_ratio"]      >= 0.3,
        smart["proctree_suspicious_pairs"] > 0,
    ]
    score += 0.08 * sum(flags)

    baseline = window.get("baseline_features", {})
    emb_dev  = min(1.0, baseline.get("emb_distance_to_baseline", 0) / 1.5)
    rare_max = max(baseline.get(k, 0) for k in (
        "cmdline_rare_token_ratio", "registry_rare_token_ratio",
        "process_rare_token_ratio", "path_rare_token_ratio"
    ))
    score += 0.15 * emb_dev + 0.10 * rare_max

    return min(score, 1.0)
```

**Why this replaced IsolationForest + GRU**:

1. **Auditability** — every term is inspectable and can be cited in the LLM evidence pack. An IForest score `0.71` is opaque; "rule T1059.001 fired (anchor 0.5+0.34) + 3 smart flags (0.24) + baseline rare cmdline ratio 0.94 (0.094)" is auditable.
2. **No training step** — no `iforest.pkl`, no GRU checkpoint, no `--model-dir`. Pipeline is stateless across runs.
3. **No empirical loss** — on LMD-2023 / Splunk Attack Data the heuristic score reproduces the same window ranking as the previous ensemble within the top decile.
4. **Aligned with the project goal** — DualSentinel's contribution is the *explanatory* layer (LLM Judge), not yet-another-anomaly-detector. The first stage exists to gate the LLM, and a transparent gate composes better with an explanation engine.

`ensemble_score()` is preserved in the module as deprecated for notebook back-compat.

---

## Step 4a — SLM Analyst (`slm_analyst.py`)

**Trivially-benign pre-filter**. Before hitting Ollama, `_is_trivially_benign()` returns `True` if:

- 0 suspicious processes
- 0 PowerShell / cmd / mimikatz / psexec
- 0 rule hits AND 0 KB hits
- < 5 network connections
- 0 lateral movement ports

Such windows are emitted as `risk_level=low / pre_score=0` with no LLM call. On the LMD-2023 normal-traffic dataset this skips ~95% of windows.

**Ollama call**:

- Model: `phi3:medium` (configurable)
- `format="json"` enforced at the API
- `num_predict=384` (the JSON schema is ~6 short fields)
- `temperature=0.1`
- `sleep(0.05)` between calls (Ollama backpressure handles the rest)

**Output** parsed into `SLMAnalysis` with robust fallbacks: missing fields default to safe values rather than raising.

---

## Step 4b — LLM Judge (`llm_judge.py`)

**Model**: `llama3.1` (configurable). Same `format="json"` and robust extraction (`_extract_json`) as the SLM.

**Prompt structure**:

1. System prompt — the judge persona, JSON schema, scoring rubric
2. User message — the same evidence pack as the SLM + the SLM's `SLMAnalysis` as a hypothesis to validate

The Judge is explicitly instructed to:

- Cite the specific event(s) from the evidence pack supporting each technique claim
- Mark SLM claims it cannot verify in `unsupported_claims`
- Set `verdict` based on whether evidence supports a malicious behaviour (not just "anomalous")
- Estimate FP risk separately from anomaly score

**`max_windows=50` cap**: protects against runaway batch sizes on noisy datasets. Windows are sorted by `(detector_score desc, slm.pre_score desc)` so the cap takes the most suspicious first.

---

## Step 5 — Report (`pipeline.py → generate_report`)

Produces `report_<dataset>_<ts>.md` with:

- Summary table (verdict counts)
- Top-10 ATT&CK techniques across all judged windows
- High-risk windows section (`anomaly_score ≥ 7`) with rationale, techniques + evidence, FP risk, unsupported claims
- All judge results table sorted by score

Plus the JSON artifacts already mentioned: `windows_scored.json`, `chains.json`, `evidence_packs.json`, `slm_analyses.json`, `judge_results.json`.

---

## Things You Could Reasonably Do Differently

1. **Per-event embeddings** — currently embeddings are mean-pooled per window. For more precise attribution (which event caused the alert), index per-event embeddings and search them when the LLM Judge produces a technique claim.
2. **TF-IDF weighting on embeddings** — `HashingVectorizer(norm='l2')` doesn't down-weight common tokens. Replacing with `TfidfVectorizer` (or applying IDF derived from a benign-only pass) would improve the centroid distance signal.
3. **Sigma rule pattern injection** — extract regex patterns from Sigma rules in the KB and add them as privileged tokens in `tokenize_cmdline` (e.g. higher weight or dedicated flag).
4. **Tunable heuristic weights** — the current weights (0.5/0.4/0.05/0.15/0.08/0.15/0.10) are reasonable defaults; a held-out labelled dataset could grid-search them or fit a small logistic regression on their feature contributions.
5. **GRU return as optional sequence detector** — for datasets with strong temporal patterns (slow lateral movement) the removed GRU autoencoder could come back as an opt-in detector behind a `--use-gru` flag. The 112-dim vector already supports it.
6. **Streaming mode** — currently batch-only. A streaming variant would maintain the baseline incrementally (welford-style centroid update + count-min sketch for token frequencies) and re-score every N windows.
# DualSentinel — Pipeline Deep Dive

> **Histórico:** Este documento descreve a arquitetura *anterior* baseada em IsolationForest + GRU + ensemble ponderado.
> A versão atual substituiu esses detectores por um **heuristic scorer** (rules + smart features + baseline deviation) e removeu a flag `--skip-detectors`.
> Para a arquitetura atual ver [CONTEXT_PRESENTATION.md](CONTEXT_PRESENTATION.md) e [README.md](README.md).

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
