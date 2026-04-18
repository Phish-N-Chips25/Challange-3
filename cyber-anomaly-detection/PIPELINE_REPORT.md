# Cyber Anomaly Detection & ATT&CK Attribution — Technical Report

## Overview

This project builds a two-stage pipeline for Sysmon-based threat detection and attribution:

1. **Detection layer** — unsupervised autoencoders (single-event + sequence) trained on benign
   activity flag anomalous process chains
2. **Attribution layer** — retrieval-augmented generation (RAG) over an ATT&CK knowledge base
   feeds a local LLM (Qwen 2.5 32B via Ollama) to map flagged chains to MITRE ATT&CK techniques

Work spans 10 notebooks: EDA (01-04), model development (05-08), KB construction and event
indexing (09), and the end-to-end attribution pipeline (10).

---

## Datasets

### LMD-2023 (notebooks 02, 05-08)
- ~2.3M Sysmon events across three size variants (1.75M / 1.87M / 2.3M rows)
- Labels: Normal (76%), EoRS — End-of-RansomwareSession (18%), EoHT — End-of-HardTarget (6%)
- **Role:** Benign-only training corpus for all unsupervised models; no T-code labels → used for
  distribution learning, not technique attribution
- **Key characteristic:** Labels mark session endpoints (ransomware terminated / APT exited),
  not individual technique executions. This is the primary reason supervised classifiers
  trained on LMD fail to generalize (see CASH section below)

### OTRF Atomic Red Team (notebooks 03, 08-10)
- 543k events covering 53 unique T-codes from isolated atomic exercises
- Additionally: APT29 compound campaign (551k events, Day 1 + Day 2)
- **Role:** Primary evaluation set; ground-truth T-codes available per event (`attck_technique`)
- Row range in merged index: [511,105 - 1,054,182)

### Splunk Attack Range (notebooks 04, 08-10)
- 293 T-code folders + 14 malware families (Emotet, Trickbot, REvil, LockBit, etc.)
- ~2.07M events, 177 unique T-codes
- **Role:** Generalisation evaluation; broader T-code coverage than OTRF
- Row range in merged index: [1,382,201 - 3,447,667)

### SILRAD (notebook 01)
- 39,999 training + 156,841 test events; binary labels (benign / ransomware)
- Pre-embedded as 36-dim FastText vectors
- **Role:** Initial EDA and baseline supervised experiment only; not used in final pipeline

---

## Feature Engineering

### Embedding Strategies Evaluated

| Strategy | Dims | Description |
|----------|------|-------------|
| TF-IDF + SVD | 370-371 | Bag-of-words on concatenated Sysmon fields, truncated SVD |
| **Word2Vec** | **352-353** | **Skip-gram on Sysmon field tokens; chosen for all production models** |
| FastText | 1,313 | Subword-aware; excluded from HPO runs (VRAM / time cost prohibitive) |

**Decision:** Word2Vec outperformed TF-IDF by 0.02-0.03 AP across all model families and all
datasets. Semantic token embeddings capture field-value co-occurrences (e.g., `lsass.exe` ↔
`GrantedAccess=0x1410`) that TF-IDF treats as independent vocabulary entries.

### `rule_name` Feature Handling
- Single-event AE uses the full 353-dim vector (includes `rule_name`)
- Sequence AE uses a 352-dim norule variant (`rule_name` removed)
- **Rationale:** `rule_name` is available in labelled datasets but absent in real-world LMD
  traffic. Including it in the sequence model would create a train/deploy mismatch.
  Single-event AE operates per-event and the field is sparse enough to be safe.

---

## Anomaly Detection

### Approaches Compared (notebooks 05-06)

All models trained benign-only on LMD. Evaluation at 95%:5% benign:malicious production ratio.

#### Isolation Forest
- Optuna HPO, 50 trials per feature strategy
- Word2Vec best: AP=0.535, ROC-AUC=0.963
- **Limitation:** Linear ensemble of random trees; poor capacity for the nonlinear boundary
  between benign and attack event distributions

#### MiniBatchKMeans
- Optuna HPO, 50 trials; Word2Vec best: AP=0.667, ROC-AUC=0.987
- Strong sensitivity to cluster count (509 vs 490) and batch size (4,096 vs 65,536)
- Competitive but no latent representation; cannot produce reconstruction-based scores

#### SGD OneClass-SVM
- Word2Vec: AP=0.168, ROC-AUC=0.859 — worst performer across all strategies
- Linear kernel assumption is too restrictive for high-dimensional semantic feature space
- **Abandoned** after initial trials

#### CASH — Combined Algorithm Selection & Hyperparameter Optimization (Optuna)
- Algorithms: XGBoost (GPU), LightGBM (CPU), CatBoost (GPU), HistGradientBoosting (CPU)
- Supervised training on LMD benign + malicious splits; LMD AP: ~0.65-0.68
- **Why abandoned:** T-code leakage in the train/test split. `make_splits` performs a random
  event-level permutation (`rng.permutation(n)`) over the entire malicious event array — there
  is no campaign- or exercise-level grouping. Events from the same T-code exercise (e.g., 50
  consecutive T1003 LSASS dump events) are randomly distributed 60/20/20 across train/val/test.
  The CASH classifiers memorised the specific Sysmon fingerprints of each exercise during
  training and recognised the held-out 20% of those same exercises at test time, producing
  inflated in-distribution AP (~0.67). When evaluated on held-out datasets (notebook 08) with
  entirely different exercise runs, tools, and environments, that memorisation transferred
  nothing and performance collapsed. A proper evaluation would require splitting at the
  campaign level; however, fixing the split would also expose that T-code-specific supervised
  classifiers need far more diverse per-technique training data than is available here.
  Unsupervised autoencoders are immune to this because they model only the benign distribution
  and make no use of T-code labels at training time.

#### Autoencoder — NAS + HPO (Optuna, 60 trials)

**Single-event Autoencoder (chosen primary detector)**

Architecture search: depth (1-5 layers), width ratios, latent ratio, activation function,
dropout, batch norm, learning rate, weight decay, optimizer.

Best Word2Vec configuration:
- Layers: [231, 176, 176, 162], latent=8
- Activation: ELU, dropout=0.1, batch norm=True
- Optimizer: Adam, lr=1.71e-3, weight_decay=1.04e-5
- Training: 72 epochs (early stopping), batch size=1,024

**Performance across datasets (Word2Vec):**

| Dataset | ROC-AUC | AP | F1 | TPR@0.1% FPR |
|---------|---------|----|----|--------------|
| LMD Malicious | 0.9870 | 0.9395 | 0.9529 | 0.0143 |
| OTRF Atomic | 0.9922 | 0.9680 | 0.9671 | 0.2197 |
| OTRF Compound | 0.9886 | 0.9170 | 0.9451 | 0.0393 |
| Splunk | 0.9898 | 0.9883 | 0.9825 | 0.0658 |

> ROC-AUC 0.988-0.992 across all unseen datasets demonstrates genuine cross-domain generalisation.

---

### Sequence-Level Detection (notebook 07)

**Motivation:** Single-event scoring ignores temporal context. A single `cmd.exe` creation is
benign; `winword.exe → cmd.exe → powershell.exe -encoded` is a macro execution chain. The
sequence AE operates on W-event windows and learns the joint distribution of consecutive events.

**Architecture search space:**
- Architecture: LSTM / GRU-LSTM / **Transformer** (joint NAS+HPO)
- Window size W: 5-50 (step 5)
- Stride: W, W/2, W/4
- Hidden dim: 64 / 128 / **256**
- Layers: 1-6
- Latent dim: 32 / 64 / **128**

**Best configuration (60 Optuna trials):**
- Architecture: TransformerAE
- Feature strategy: Word2Vec (352 dims, norule)
- Window size W = 45, stride = 45 (non-overlapping)
- Hidden dim = 256, 2 layers, latent = 128, nhead = 8
- AdamW, lr=0.00196, weight_decay=2.21e-6, dropout=0.0186
- Training: 16 epochs (early stopping, patience=15)

**Performance:**

| Dataset | ROC-AUC | AP | F1 | TPR@1% FPR | TPR@0.1% FPR |
|---------|---------|----|----|------------|--------------|
| LMD Malicious | 0.9833 | 0.9492 | 0.9544 | 0.9396 | 0.0019 |
| OTRF Atomic | 0.9097 | 0.8141 | 0.7453 | 0.6022 | 0.1181 |
| OTRF Compound | 0.8627 | 0.5947 | 0.6313 | 0.3352 | 0.0317 |
| Splunk | 0.9703 | 0.9499 | 0.9445 | 0.8970 | 0.0958 |

**Calibrated threshold:** 0.627528 at 0.1% FPR operating point.

**Why non-overlapping stride:** Overlapping windows (stride=W/2, W/4) multiply the window count
2-4x with marginal AP improvement. Non-overlapping significantly reduces training and inference
time with negligible accuracy cost.

**Where sequence AE is weaker:** OTRF Compound (AP=0.595) — short isolated exercises and
tool-switching across LSASS variants break window continuity. Sequence models require
sustained activity patterns; one-shot technique demonstrations produce sparse windows.

**LSTM/GRU abandoned:** Transformer outperformed RNN variants in early Optuna trials for
this feature space. Attention over the full W-event context better captures arbitrary-position
dependencies (e.g., initial process creation far from the subsequent registry modification).

---

## ATT&CK Knowledge Base (notebook 09)

### Event Index (`events_m.parquet`)
- 3,447,667 rows matching the feature matrix X_m row order exactly
- Load order: LMD → OTRF Atomic → OTRF Compound → Splunk
- Sysmon fields retained: `event_id`, `utc_time`, `image`, `command_line`, `parent_image`,
  `parent_cmdline`, `image_loaded`, `details`, `granted_access`, `target_object`,
  `target_image`, `dest_ip`, `dest_hostname`, `target_filename`, `query_name`, `hashes`,
  `attck_technique`, `dataset_source`

### KB Sources and Coverage

| Source | Entries | Unique T-codes | Notes |
|--------|---------|---------------|-------|
| MITRE ATT&CK | 564 | ~564 | Official technique descriptions |
| Sigma rules | 2,862 | 603 | Community detection rules — primary event-to-technique mapping |
| Splunk Security Content | 33 | ~30 | Detection analytics |
| OTRF | 4 | 4 | Red team detection rules |
| **Total** | **3,463** | **603** | |

### Embedding Models Evaluated for Retrieval

| Model | Dense recall@15 |
|-------|----------------|
| all-MiniLM-L6-v2 | 11.9% |
| BAAI/bge-base-en-v1.5 | 13.9% |
| intfloat/e5-base-v2 | 12.7% |
| **all-mpnet-base-v2** | **16.3%** ← selected |

### Retrieval Strategy

| Strategy | Recall@15 |
|----------|----------|
| Dense only (mpnet) | 16.3% |
| BM25 only | ~14% |
| **Hybrid dense + BM25 (RRF k=60)** | **25.4%** ← selected |

**Hybrid retrieval** improves recall by ~9pp over dense alone. BM25 recovers candidates the
dense model misses due to vocabulary gaps — vendor names, port numbers, specific tool paths
that embeddings compress into common semantic space.

**Important:** 25.4% recall@15 is the hard ceiling for the attribution pipeline. If the
correct technique is not in the top-15 candidates, the LLM cannot produce a correct answer.
This ceiling is the primary performance constraint of the system.

---

## SLM Attribution Pipeline (notebook 10)

### Architecture

```
Flagged chain (from Sequence AE)
    │
    ├─ peak_start, peak_score (highest-scoring window index)
    │
    ▼
Peak window: all_rows[peak_start : peak_start + seq_W]   (45 events)
    │
    ▼
Multi-query RAG
    ├─ Per-EID-type behavioural queries (top-3 dominant EID groups)
    └─ Combined query (all events in chain)
         │
         ▼
    ChromaDB hybrid retrieval (k=15)
    → top-15 unique T-code candidates
    │
    ▼
ATTRIBUTION_PROMPT
    ├─ ## Events in Flagged Chain Window  (formatted Sysmon events)
    ├─ ## Candidate ATT&CK Techniques     (RAG results with Sigma descriptions)
    └─ ## Task  (CoT: Step 1 observe, Step 2 match, Step 3 JSON)
         │
         ▼
    Qwen 2.5 32B (Ollama, temperature=0.1)
         │
         ▼
    JSON: {technique_id, technique_name, confidence, explanation, recommended_action}
```

### Event Selection Evolution

The method for selecting which events to present to the LLM went through four iterations:

**Iteration 1 — Single-event AE score (initial)**
Score every event in the chain by reconstruction MSE; take top-32.
*Problem:* High-volume EID types (e.g. 38 registry `Create/Delete` events from Azure Agent)
dominated the selection by sheer count, scoring high due to specific path rarity rather than
technique relevance. The one DNS query event in the chain — potentially the most informative —
was consistently excluded.

**Iteration 2 — Sigma-guided AE score**
Multiply AE score by a bonus: +3.0 if the event's EID matches the top-1 RAG candidate's
Sigma EIDs; +0.5 per Sigma indicator string match.
*Problem:* If the chain has no events of the expected EID type (common for RAG-miss cases),
the bonus is zero and the result collapses back to iteration 1.

**Iteration 3 — EID-stratified selection (no AE)**
Group events by EID type. Allocate budget: priority EIDs (top-1 candidate's Sigma EIDs)
get 50% of the slot budget, remaining budget split evenly across all other EID types (min 2
per type). Within each group, rank by Sigma indicator match count.
*Result:* Every EID type in the chain gets at least one representative event. The DNS query
that was excluded in iteration 1 was guaranteed a slot in iteration 3. Addressed the EID
dominance problem.

**Iteration 4 — Full anomalous window (final)**
`peak_rows = all_rows[peak_start : peak_start + seq_W]`
Send all 45 events of the detected anomalous window. No selection.
*Rationale:* The sequence AE already identifies a 45-event window of concentrated anomalous
activity. Sub-selecting 32 from those 45 risks discarding any technique-defining event.
*Important correction:* Initial implementation used `all_rows` (the full chain, potentially
300-400 events) instead of the peak window — this sent enormous prompts and degraded LLM
reasoning. Corrected to slice `[peak_start : peak_start + seq_W]`.

### RAG Evolution

**Single-query → Multi-query:** Initial RAG used one combined behavioural summary query.
Multi-query (one per dominant EID group + combined) improved candidate diversity: process
creation events pull execution/persistence techniques; registry events pull persistence/defence
evasion; DNS/network events pull C2/discovery.

**k=5 → k=15 (RAG_K):** At k=5, GT T-code appeared in candidates for ~35% of chains.
Increasing to k=15 raised it to 60% for OTRF (while 0% for Splunk reflects a KB coverage
gap, not a retrieval issue — those techniques simply don't have Sigma rules in the KB).

### Final Evaluation Results

Sample: 20 chains per source (N_EVAL=20), random seed=42.

```
otrf_at  (n=20, model ran on 12 GT-in-RAG chains)
  RAG recall        : 60.0%  (avg 22 candidates per chain)
  Model exact match : 0.0%   (conditional on GT in RAG)
  Model parent match: 8.3%   (1/12 chains, T1546.003 → T1546.011)
  Avg latency       : 99s

splunk  (n=20, model ran on 0 GT-in-RAG chains)
  RAG recall        : 0.0%   (all 20 chains are RAG misses)

Overall  (n=40, model ran on 12 GT-in-RAG chains)
  RAG recall        : 30.0%
  Model exact match : 0.0%
  Model parent match: 8.3%
  Pipeline exact    : 0.0%   (all chains including RAG misses)
  Avg latency       : 99s
```

### Failure Analysis

**1. RAG recall ceiling (primary bottleneck)**
OTRF: 8 of 20 chains are RAG misses. Splunk: 20/20 are RAG misses.
Techniques consistently missed: T1021 / T1021.003 (DCOM), T1003.003 / T1003.006 (LSASS
variants), T1110.003 (Password Spraying), T1055 / T1055.001 (Process Injection), T1547.012,
T1069.001, T1566.001, T1543.003, T1218.002, T1218.005, T1552.002.
These are either not covered by Sigma rules or described in ways that don't match the
behavioural summary query generated from Sysmon fields.

**2. LLM candidate-anchored hallucination (secondary bottleneck)**
Reading the Step 1 reasoning for chains where the model fails: it consistently names processes
like `wmic.exe`, `rundll32.exe`, `ntdsutil.exe`, `regsvr32.exe` — which appear in the Sigma
candidate descriptions as detection indicators, but are absent from the actual event list.
The model appears to reason backwards from the candidate reference material rather than forward
from the observed events. This leads to confident but wrong attributions even when the correct
technique is in the candidate list.

Observed pattern: chain events show only `EID=12 x44, EID=10 x1` (44 registry operations,
1 process access); LLM reasoning invents `CreateRemoteThread` (EID=8) and DPAPI key access.
The Sigma candidate descriptions for the offered techniques mention these — the model
confuses reference material with observed evidence.

**3. Chain-to-technique label mismatch**
Some chains flagged by the sequence AE contain no technique-defining events — the AE detected
statistical anomaly in the window, but the MITRE T-code label attached to those events
describes activity that occurred elsewhere in the campaign (e.g., a T1021.003 DCOM execution
label on a chain consisting entirely of Azure Guest Agent certificate store operations).

---

## Summary of Key Decisions

| Decision | Choice | Alternative | Reason |
|----------|--------|-------------|--------|
| Feature embedding | Word2Vec | TF-IDF, FastText | +0.02-0.03 AP; semantic co-occurrence; FastText too costly |
| Detector type | Unsupervised AE | Supervised CASH | CASH overfit to LMD session labels; AE generalises cross-dataset |
| Sequence architecture | TransformerAE | LSTM, GRU | Attention captures arbitrary-range dependencies; best in Optuna |
| Sequence window | W=45, stride=45 | W=10/20/30, overlap | Non-overlapping: 2-4x fewer windows, marginal AP loss |
| Threshold calibration | 0.1% FPR operating point | F1-optimal | Production-appropriate FPR; F1 threshold used for single-event |
| RAG embedding | all-mpnet-base-v2 | MiniLM, BGE, E5 | Best recall@15 (16.3%) among models evaluated |
| RAG retrieval | Hybrid dense+BM25 | Dense only | +9pp recall; BM25 recovers vocabulary-specific misses |
| Attribution model | Qwen 2.5 32B (local) | OpenAI API | No external dependency; privacy; explicit CoT reasoning |
| Event selection | Full peak window (W=45) | AE top-32, stratified-32 | AE selection biased toward statistical rarity; stratified better but still discards events; full window is complete |

---

## Limitations

### Detection Layer

1. **AE benign-distribution dependency:** Both autoencoders are trained exclusively on LMD-2023
   benign traffic. "Normal" is defined by whatever processes, registry keys, and network calls
   appeared in that specific environment. Deploying in a different organisation would produce
   elevated false-positive rates for org-specific software (enterprise tools, EDR agents,
   bespoke services not present in LMD) and potentially miss living-off-the-land attacks that
   happen to resemble LMD's benign traffic patterns. Correct deployment requires retraining the
   AEs on a benign baseline representative of the target environment.

   This asymmetry partly justifies the two-stage AE design: the TransformerAE's anomaly signal
   is structural — it detects unusual EID *sequences* within a 45-event window (e.g., a process
   access immediately followed by a DNS query to a rare domain), which is somewhat
   environment-agnostic. The single-event AE scores individual events in isolation and is more
   sensitive to distribution shift, making it more suitable as a supporting signal (intra-chain
   event ranking) than as a standalone detector.

2. **Sequence AE + isolated exercises:** AP=0.595 on OTRF Compound vs 0.949 on LMD. Short
   atomic exercises produce few 45-event windows; the AE relies on sustained temporal patterns
   that short, scripted exercises may not generate.

3. **Ground-truth alignment:** OTRF T-code labels attach to the entire exercise, not to
   individual Sysmon events. A chain flagged within a T1547.001 exercise may contain only
   background registry noise from co-running benign processes.

### Attribution Layer

4. **RAG recall hard ceiling:** 25.4% hybrid recall@15 means ~75% of chains cannot be correctly
   attributed even with a perfect LLM. KB expansion (more Sigma rules, fine-tuned domain
   embeddings) is the highest-leverage improvement.

5. **Splunk KB coverage gap:** The Splunk GT techniques (T1547.012, T1069.001, T1566.001, etc.)
   have no Sigma rules in the KB → 0% RAG recall regardless of retrieval strategy. This is a
   data coverage problem, not a retrieval algorithm failure.

6. **Insufficient Sysmon-to-technique labelled data:** Attribution requires grounding LLM
   reasoning in concrete mappings from raw Sysmon field values to ATT&CK techniques. The Sigma
   rules in the KB describe indicator patterns (process names, command-line fragments) but do
   not provide the semantic reasoning chain. Without a sufficiently large corpus of labelled
   (Sysmon event chain → T-code) examples — either for LLM fine-tuning or as few-shot prompt
   examples — the model defaults to reading back the candidate reference material as if it were
   observed evidence (see item 7 below).

7. **LLM candidate-anchored hallucination:** Qwen 2.5 reasons from the Sigma candidate
   descriptions rather than strictly from the observed events. When the correct technique is in
   the candidate list, the model extracts indicator names from the description (e.g.,
   `CreateRemoteThread`, `ntdsutil.exe`) and asserts them as observations even when they are
   absent from the event log. A two-stage prompt (observe events without candidates → then
   match) could reduce this, but doubles LLM calls and latency. The root fix is the labelled
   data gap noted in item 6.
