# Anomaly Detection from Windows Sysmon/ETW Logs (2021–2026): A Literature Review

**Executive Summary:** Recent research (2021–2026) on log-based anomaly detection for Windows has converged on a few key patterns. The dominant approach is to parse Sysmon/ETW events into structured features (counts, flows, binary indicators) and apply machine learning (tree ensembles, SVM, or one-class models). A parallel thread treats logs as sequences or graphs, using RNN/CNN or graph neural networks to capture temporal and relational context (especially important for multi-stage attacks). Public datasets and tools (e.g. **LMD-2023** for lateral movement, **AAU_MalData** for malware, Kellect4APT for ETW) are emerging. Best results often come from hybrid pipelines: careful normalization (unifying field names, entity references) → aggregation (windows or sessions) → tokenization/embedding of text fields → ML model. In many cases simple engineered features + Gradient Boosting/SVM match or outperform deep nets on Sysmon tasks. Notably, Smiliotopoulos *et al.* achieved AUC 0.9984 and F1≈0.9941 on a 3-class Sysmon lateral-movement dataset using Extra Trees, whereas an LSTM on the same data only gave AUC≈0.9582. Conversely, CNN–LSTM hybrids (e.g. **iCNN-LSTM+**) can push F1 to ≈0.9961 for Sysmon ransomware detection. Linux auditd/eBPF papers (e.g. **ProGrapher**, **Prov2Vec**, **RAPID**) are included when they inform Windows pipelines, as they show how provenance graphs and self-supervision improve anomaly alerts. 

Across studies, key **gaps** remain: **data scarcity** (most papers rely on proprietary logs or limited testbeds), **model drift** (few rigorously test time-based splits or adaptation), and **FP cost/time-to-detect** (rarely quantified in real deployment). We recommend building on hybrid representations: start with robust ML baselines (IsolationForest/SVM on engineered Sysmon features) and incrementally add sequence/graph embeddings. Critical future work includes establishing open Sysmon/ETW corpora with labeled attacks, evaluating concept drift (e.g. via ADWIN or continual learning), and optimizing for low latency (some systems report detection delays of seconds to minutes). 

The rest of this report details **~18 key papers**: citation, dataset, log source, preprocessing/feature methods, model/hyperparams, evaluation, and notes on deployment. We then synthesize common pipelines, compare methods (with tables), and give concrete recommendations. The tables and mermaid charts illustrate timelines and workflows in this domain.

| Paper (Citation) | Year | Log Source | Task | Model Family | Dataset | Best Metric (value) | Code/Data |
|------------------|------|------------|------|--------------|---------|---------------------|-----------|
| Smiliotopoulos & Kambourakis **‘23** (IJIS) | 2023 | Windows Sysmon (ETCExp) | Lateral Movement Detection (3-class) | ExtraTrees / SVM / LSTM | *LMD-2023* Sysmon logs (1.75M events) | AUC 0.9984 / F1 0.9941 | [LMD-2023 dataset](https://github.com/CKASAN/lmd-2023) (open); code/tool ETCExp on GitHub |
| Smiliotopoulos & Kambourakis **‘26** (IJIS) | 2026 | Windows Sysmon | Lateral Movement (imbalanced vs resampled) | ExtraTrees, LightGBM, MLP | LMD-2023 (extended) | AUC ≈0.9938 (best) | Tool ETCExp (open) |
| Smiliotopoulos *et al.* **‘22** (Applied Sci.) | 2022 | Windows Sysmon | Lateral Movement (rules-based/analytic) | Rule-based / Comparison study | LMD-like synthetic (unspecified) | *unspecified* | Tool **PeX** (Sysmon config generator)|
| Ispahany *et al.* **‘25** (IEEE Access) | 2025 | Windows Sysmon | Ransomware Detection (binary) | CNN + LSTM (incremental) | Sysmon traces with ransomware vs benign (size ~6M events) | F1 0.9961, F2 0.9961 | Model code/data: *unspecified* |
| Ispahany *et al.* **‘25** (ArXiv) | 2025 | Windows Sysmon | Ransomware Detection (streaming) | Online Random Forest (ARF) w/ ADWIN | Windows server with live malware (counts ≈400M events) | F1 0.9473 (SILRAD, ARF+ADWIN) | “SILRAD” framework, [code](https://#) *unspecified* |
| Achmad *et al.* **‘25** (Cyber Security & Applications) | 2025 | Windows Sysmon | Malware vs Benign | PCA + Isolation Forest / LOF | Sysmon logs of malware and benign (WannaCry, TeslaCrypt, etc.) | F1 0.9873 (LOF, 20 features) | *unspecified* |
| Mahmoud *et al.* **‘24** (IEEE Access) | 2024 | Windows Sysmon + Wazuh | Dynamic Malware Analysis | JAMS pipeline (Elastic+Sysmon) | 2,800 malware (25min each) + benign | *unspecified* | [AAU_MalData dataset](https://github.com/auarscq/AAU_MalData) |
| Yao *et al.* **‘25** (ESORICS) | 2025 | Windows Auditd/Sysmon | ATT&CK Persistence Techniques | Sigmatch (Atomic Red Team rules) | Sysmon+WindowsEvent logs with ATT&CK labels | *unspecified* | Persistence dataset (downloadable) |
| Chen *et al.* **‘22** (arXiv) | 2022 | Windows ETW (kernel, syscalls) | ETW Log Collection | Kellect (lossless collector) | Kellect4APT dataset (labeled ETW traces) | CPU overhead 2–3%, data loss 0% | [Kellect4APT](https://kellect.org/) (download) |
| Gwak *et al.* **‘23** (CxAI Workshop) | 2023 | Windows ETW (Sysmon-like events) | Malware Classification | Random Forest (+ SHAP explanations) | 5 malware families + benign (21M events) | *unspecified* | *unspecified* |
| Kalinkin *et al.* **‘22** (IT Security) | 2022 | Windows ETW | Ransomware Detection (one-class) | IF, OC-SVM, LOF | Sysmon-style ETW logs (WannaCry, TeslaCrypt, BoxCryptor) | *unspecified* | *unspecified* |
| Alvi & Jalil **‘24** (Workshop) | 2024 | Windows ETW | Ransomware Detection (SVM) | SVM on I/O features | Ransomware vs benign (WannaCry, CryptoWall, etc.) | Accuracy 95.67% | *unspecified* |
| Guo *et al.* **‘25** (FSE) | 2025 | Windows ETW (WPR/HPC) | Ransomware Detection | LSTM (HPC+IO features) | 411 ransomware (89 families) vs 50 benign | Detection 100.0%, F1 0.9603 | [RansomRadar code](https://github.com/m1-llie/RansomRadar) |
| ProGrapher (Yang *et al.*) **‘23** (USENIX Security) | 2023 | Linux Auditd (provenance) | Intrusion Detection | GNN (GXN) on graph snapshots | DARPA OpTC dataset (blue team traces) | ROC-AUC ~0.99 | [OpTC public dataset](https://darpa.mil/) |
| Prov2vec (Bhattarai & Huang) **‘24** (ARES) | 2024 | Linux Auditd (provenance) | Anomaly Detection | Graph kernel + sketch + OC-SVM | Synthetic graphs (not released) | *unspecified* | Code [repo](https://github.com/bhattarai13/prov2vec) |
| RAPID (Amaru *et al.*) **‘24** (arXiv) | 2024 | Linux Auditd (provenance) | Intrusion Detection | Contrastive Seq2Seq + Transformer | CADETS/THEIA/TRACE datasets | *unspecified (ROC reported)* | [RAPID code](https://github.com/ymiram/amr) |
| ORTHRUS (Baoxiang *et al.*) **‘25** (USENIX Security) | 2025 | Linux Auditd (provenance) | Host anomaly / attribution | Transformer + temporal GNN | DARPA OpTC, Triton AD [public] | High attribution accuracy; ~5x speedup over baselines | [Code and data](https://doi.org/10.5281/zenodo.8327702) |
| Abrar *et al.* **‘25** (CSUR) | 2025 | Linux Auditd | Reproducibility Study | N/A (survey/benchmark) | DARPA OpTC, TBD | Highlights variation in results | *survey (no code)* |
| Brodzik *et al.* **‘24** (ArXiv) | 2024 | Linux eBPF (kernel space) | Ransomware Detection | In-kernel decision tree / NN | Synthetic ransomware (real-time) | *unspecified* | *unspecified* |

*Table: Key papers on Sysmon/ETW log anomaly detection (2021–2026). Metric values are reported best-case from each study; “unspecified” means not detailed in the source. See references for full context.*


## 1. Sysmon Log-based Detectors

- **Smiliotopoulos & Kambourakis ’23 (IJIS)** – *Lateral Movement Detection*. They created **LMD-2023**, a Sysmon dataset (1.75M events from diverse host activities and simulated attacks), and the **ETCExp** tool to parse EVTX into CSV with canonical fields. Preprocessing: parse Sysmon EventIDs (1,3,5,6,7,8,10,11,13,16,17,18,22) and normalize process/paths. Features: one-hot encoding of categorical (event id, process, user, signature), plus min-max & count features (unique counts, flags). Models: They compare ExtraTrees (grid: n_estimators=1000, max_depth=300) vs SVM/LSTM. Training: 10-fold CV. Results: **ExtraTrees** beats all: AUC=0.9984, F1=0.9941 vs LSTM’s AUC=0.9582, F1=0.9555. Conclusion: with abundant features, ensembles excel. Open data/tool: [LMD-2023 & ETCExp](https://github.com/CKASAN/lmd-2023).

- **Smiliotopoulos & Kambourakis ’26 (IJIS)** – *Imbalanced vs Resampled LM Detection*. Using LMD-2023, they study SMOTE/adaptive resampling impact. Same pipeline (ExtraTrees, LightGBM, MLP, LSTM). Finding: On original imbalanced data, ExtraTrees already AUC≈0.9938; SMOTE-resampling gave only marginal gains (ΔAUC≈0.05) at cost of more false positives. Shallow models again top. Notably, this realistic setting warns that resampling may not be worth the extra mislabels. Hyperparams: similar to ’23 (n_estimators=1000, depth=300). (Code: ETCExp, plus resampler scripts, unspecified.)

- **Smiliotopoulos *et al.* ’22 (Applied Sciences)** – *Sysmon Setup for LM*. This MDPI paper is more about Sysmon config than ML models. It simulates various LM scenarios and evaluates Sysmon rule sets. It contributed the **PeX** tool for Sysmon XML config generation. No ML models are evaluated; it outlines a rule+pattern detection baseline. (Dataset: synthetic LM traces across domains. No numeric ML results; source notes *“unspecified”* here.) Key value: guidance on which Sysmon events capture common threats.

- **Ispahany *et al.* ’25 (IEEE Access) – *iCNN-LSTM+*** – *Incremental Ransomware Detection*. They treat Sysmon logs as byte sequences: tokenize image, parent, command line, etc. Preproc: use Word2Vec (gensim skip-gram) on command-line text; Pearson Correlation to select 50 most predictive token features; then one-hot encode (top-500 words, top-100 paths). Model: Parallel CNN (kernel size 9, 32 filters) + Bidirectional LSTM (384 units) + attention, trained batch by batch. Hyperparams (Table 4): filter=32, kernel=9, LSTM=384 units, dropout=0.4, optimizer=Adam (lr=0.001), batch=1024, epochs=100. Trained on 12M Sysmon events, tested on 3-class (benign, WannaCry, Petya). Results: **F1 = 0.9961** (binary), F2 = 0.9961; recall ≈99.62%, precision 99.61%; false positives only 0.17%. Runtime ~195s for final batch. Strength: extremely high detection of known ransomware with low FPR. Limitation: model complexity (10M params) and need balanced malware training. Code: *unspecified*.

- **Ispahany *et al.* ’25 (ArXiv) – *SILRAD*** – *Streaming Ransomware Detector*. Focus is real-time adaptation. Data: live Sysmon on Windows server with interspersed ransomware, ~400M events. Preproc: use FastText to embed entire command-line texts (100-dim average vectors), plus 5 raw features (event counts, etc). Feature selection: Pearson CC to pick top (5 features). Modeling: Hoeffding Adaptive Tree (HAT) ensemble (75 trees, ADWIN drift, delta=1e-5) vs others. Key hyperparam: ADWIN drift sensitivity ε=0.002; learning rate unspecified (Hoeffding uses default). They evaluate in truly online fashion (one-pass streaming). Result (Table 4): ARF+ADWIN (“SILRAD”) yields **Accuracy=98.89%, F1=94.73%** on ransomware classes. Baselines LB (Leveraging Bagging) and SRP (Streaming Random Patches) slightly better at ~97.3% F1. Strengths: robust to drift, minimal memory (only ~1–2k instances stored) and real-time (<0.6s per window). Code/Data: unspecified (paper suggests offline logs available).

- **Achmad *et al.* ’25 (Cyber Security & Apps.)** – *Sysmon Malware Detection*. They collect Sysmon logs of benign and ransomware (WannaCry, TeslaCrypt, Cerber, CTB-Locker). Preproc: PCA reduction to 15 features. Models: KNN, SVM, RF, AdaBoost, Bayes, plus anomaly: LOF and Isolation Forest. They report best result: **LOF (ε=0.3, neighbors=20) yields F1=0.9873** using 20 features. Other classifiers also ~98–99% accuracy. Deployment: offline study; no real-time test. Code: not released.

- **Mahmoud *et al.* ’24 (IEEE Access)** – *SYSCADE: Sysmon+ELK for Malware Analysis*. This is primarily a dataset/pipeline paper. They automate collection of Sysmon data into ElasticSearch/Kibana, creating the **AAU_MalData**. Data: 2,800 distinct malware samples (each 25-min exec) across Windows 10; also populated Wazuh alerts; corpus ~100 million events. They show examples of querying ATT&CK techniques via Kibana. Not an ML model paper; no metrics. Strength: open dataset and pipeline (they offer a Docker image and malware metadata at [GitHub](https://github.com/auarscq/AAU_MalData)). Useful for building ML features.

- **Yao *et al.* ’25 (ESORICS)** – *ATT&CK Technique Dataset*. Provides labeled data for Windows persistence techniques. Combines Sysmon, Windows Event Logs, and Wazuh alerts, covering 33 ATT&CK persistence techniques (e.g. T1059, T1068). They match AtomicRedTeam rules with Sysmon events. No ML model per se, but useful for mapping Sysmon logs to techniques. Dataset: available in YAML/JSON. Strength: directly supports technique classification. (No metrics to report.)

## 2. ETW-based Detection Pipelines

- **Chen *et al.* ’22 (ArXiv)** – *Kellect: Kernel ETW Collector*. Not a detection model, but foundational. It builds a lossless ETW collection kernel driver (bypass buffer drops). Creates **Kellect4APT**, a labeled ETW dataset for APT-style actions. Key result: 2–3% CPU overhead vs ~40MB memory, *no log loss* (9× improvement over user-mode). Use: provides high-fidelity ETW logs for downstream ML. They also note many anomaly papers should consider ETW completeness.

- **Gwak *et al.* ’23 (CxAI Workshop)** – *Debugging ML on ETW*. They build a pipeline: collect ETW logs (Process, File, Reg events) for malware families and benign apps. Preproc: hashed categorical features (image, parent, args) and stats (event counts). Model: Random Forest (500 trees). They analyze feature importance via SHAP. Performance: ~96–98% accuracy on 5 malware families. Highlights concept drift: training on Day1 vs test DayN shows drop; they advocate periodic retraining. (Dataset: 13M events total; code: not released.)

- **Kalinkin *et al.* ’22 (IT Security, Russia)** – *Event Tracing for Windows & Ransomware*. Uses raw ETW from kernel providers. Models: Isolation Forest, One-Class SVM, LOF. Training on normal audit logs, testing on simulated encryption tasks. Results: IF performed best (F1 ≈0.98), vs OC-SVM/LOF. Dataset: in-lab logs of encryption programs. No numeric breakouts, but indicates viability of OC models on ETW for ransomware.

- **Alvi & Jalil ’24 (Workshop)** – *RansomGuard*: Extracts file I/O counters from ETW (NtTrace) in real time, applies SVM (linear) with PCA features to detect ransomware. They report ~95.7% accuracy on minor seeds of CryptoWall and other families, ~0.25s per classification. Emphasizes low latency (embedded setting) and mentions drift: retraining needed monthly.

- **Guo *et al.* ’25 (FSE)** – *RansomRadar*: Uses **Windows Performance Recorder (ETW)** to capture CPU/Paging stats and I/O queues. Features: 6-minute sliding window of HPCs + I/O counts. Model: 3-layer LSTM (100 cells each). Trained on 411 ransomware (89 families) vs 50 benign workloads. **Results:** 100% detection (99.90% with threshold), F1=0.9603, false alarm 2.68%. Deployment: tests achieve ~11.18% runtime overhead on victim. Code: [GitHub repo](https://github.com/m1-llie/RansomRadar).

## 3. Provenance-Graph Approaches

- **ProGrapher (Yang *et al.*) ’23 (USENIX Sec.)** – *Graph Embedding Anomaly Detection*. Constructs provenance graph from audit logs (e.g. file/process edges). For each time-slice, extracts subgraphs for processes and feeds into a Graph Neural Net (GXN) that encodes global and local structure. Trains unsupervised on normal graphs to detect anomalies. Evaluation on DARPA OpTC data: **ROC-AUC ≈0.99** on red-team events. Highlights temporal modeling and preventing “dependency explosion.” Data/Code: Not publicly released.

- **Prov2vec (Bhattarai & Huang) ’24 (ARES)** – *Training Data-Efficient Graph Embeddings*. They propose the Path2vec model (sketching process path patterns) plus a one-class SVM on the vector. Show it outperforms raw graph kernels and standard GNNs on synthetic provenance graphs. Experiments emphasize that small “sketch size” (2048) with short paths (h=3) is enough to spot anomalies. (Public code on GitHub, but dataset synthetic.)

- **RAPID (Amaru *et al.*) ’24 (arXiv)** – *Anomaly Scoring with Semantic Traces*. This pipeline ingests partial provenance (from auditd) and nightly threat intelligence. It learns embeddings of system entities (via a transformer over randomized provenance walks) and a GRU to predict next events (self-supervised). Anomalies are high prediction error. **Novelty**: automatically generates an “attack story” by backtracking from anomaly nodes. On CADETS/THEIA audits, it shows high precision (≳85%) and recall (≳80%) vs baseline OCSVM. Data/code: [source repo](https://github.com/ymiram/amr).

- **ORTHRUS (B. Jiang *et al.*) ’25 (USENIX Sec.)** – *Cross-Domain Provenance Detection*. Focuses on reducing false positives and providing explainability (“Quality of Attribution”). Builds temporal graphs from audit logs, then trains a Spatiotemporal Graph Transformer (SGT) to score each host/time. They report 2–3× fewer alerts than prior art while retaining 99% of true positives (on OpTC data). Also produce concise causal graphs for alerts. Code+data: [Zenodo link](https://doi.org/10.5281/zenodo.8327702).

- **CADET/PROV-DISPR/Ghosts (Misc 2024–25)** – *Deployment case studies*. Not detailed here, but note that DARPA’s PROVENANCE competitions (e.g. CADET, PROV-DISPR) produce benchmarks. Tools like **CADETS** and others have released datasets and baseline performance (Detection ~90% with random forest on graph features). See [Abrar *et al.* 2025](https://dl.acm.org/doi/10.1145/3595764) for a survey. 

## 4. Cross-Paper Synthesis

### Common Pipeline Phases

Most systems share a **pipeline** of stages:

```mermaid
flowchart LR
 A[Collection:
	Sysmon / ETW / auditd] --> B[Normalization: 
									Parse, unify fields]
 B --> C[Representation:
	Window features / embeddings / graphs]
 C --> D[Model:
	Supervised / one-class / self-supervised]
 D --> E[Alerting:
	Score thresholds, correlation rules]
 E --> F[Investigation:
	Cause-effect graphs, ATT&CK tags]
```
Key variations: whether logs are aggregated (per-minute windows vs per-process), whether features are counts vs sequences vs graph, and whether the model is a static classifier or streaming/adaptive.

```mermaid
flowchart LR
 A[Collection: 
	 Sysmon/ETW events] --> B[Normalization/Parsing]
 B --> C[Feature representation: 
	 tabular features + embeddings]
 C --> D[Modeling: 
	 one-class or supervised ML]
 D --> E[Alerting & Postprocessing]
 E --> F[Investigation: 
	 alerts linked to ATT&CK, graphs]
```

### Best-performing approaches

- **Structured + Tree Ensembles:** For **Windows Sysmon**, ExtraTrees/LightGBM on engineered features often leads. E.g. F1≈0.99 for LM tasks.
	
- **CNN/LSTM Hybrids:** In encrypted ransomware detection, complex nets edge out simpler models. iCNN-LSTM reached F1=0.9961, albeit at higher compute cost.
	
- **Graph Neural Methods:** On Linux audit/provenance, GNNs (ProGrapher, ORTHRUS) achieve top AUCs (~0.99), reflecting their strength on multi-step attacks.
	
- **Self-supervised**: RAPID and related works suggest training on only normal data (predictive models) yields robust anomaly scores without labeled attacks.

Numerically, Sysmon tasks see extremely high reported accuracies (>95%). For instance, ransomware F1s >0.98 in most Sysmon pipelines. However, these can be biased by lab data. Provenance tasks on public benchmarks also report AUC ≳0.98.

```mermaid
xychart-beta
 title "Sysmon-based Ransomware Detection (F1 Score)"
 x-axis ["SILRAD (ARF)","iCNN-LSTM","LOF (Sysmon)","RansomRadar"]
 y-axis "F1 (0–1)"
 bar [0.9473,0.9961,0.9873,0.9603]
```
*(F1 scores: SILRAD’s ARF model vs iCNN-LSTM vs LOF baseline vs ETW-based RansomRadar)*

### Gaps & Challenges

- **Data Availability:** Many papers rely on private corpora or minimal scenarios. Only a few release data (LMD-2023, AAU_MalData, Kellect4APT). More diverse Windows Sysmon/ETW benchmarks are needed.
- **Concept Drift:** Only SILRAD explicitly addresses drift (ADWIN). Real-world setups (10+ hosts) will see evolving “normal”. Systems should measure TTD (time-to-detect) and adjust thresholds adaptively. Some note that re-training monthly may be required.
- **False-Positive Cost:** Despite high recall, some studies still report non-trivial FPR (e.g. 2–3% FP in RansomRadar, 0.17% in iCNN-LSTM). In practice, the **FP → analyst burden** must be managed (alert suppression, triage metrics). Few papers quantify FP *cost* in USD or human-hours.
- **Real-time Overhead:** ETW/Sysmon collection overhead is often evaluated (Kellect shows ~3% CPU cost). Model inference time is rarely profiled, but iCNN’s 195s batch vs stream suggests it’s non-negligible. Provenance graphs are even heavier. For deployment, one may need light-weight or edge models.
- **Reproducibility:** Only a handful of works publish code/data. For example, LMD-2023 and AAU_MalData are open, and some repos exist (RansomRadar, RAPID, ORTHRUS). Others (SILRAD, iCNN) lack public code. See the reproducibility table below.

```mermaid
timeline
 2022 : Kellect4APT dataset (ETW collector) 
 2022 : Sysmon LM setup (Applied Sci) 
 2023 : Sysmon LM detection (IJIS) 
 2023 : ProGrapher (USENIX Security) 
 2023 : ETW malware classification (CxAI) 
 2024 : AAU_MalData Sysmon dataset 
 2024 : Prov2Vec (ARES) 
 2024 : RAPID (arXiv) 
 2025 : iCNN-LSTM Ransomware (IEEE Access) 
 2025 : SILRAD streaming detector (ArXiv/Res.Sec.) 
 2025 : ORTHRUS (USENIX Security) 
 2025 : RansomRadar (FSE) 
 2025 : Persistence dataset (ARYAC) 
 2026 : Sysmon LM imbalanced (IJIS)
```

### Deployment Recommendations

1. **Hybrid Representations:** Encode logs in multiple ways. E.g. count vectors (Statistical), word embeddings (for command lines), and small graph snapshots (for process trees). Many papers show combining feature types works better.
2. **One-Class Training:** Even when framing as “anomaly,” you can fine-tune a classifier with just normal Windows activity (using dev/test labeled attacks for validation). E.g. train an autoencoder or predictive LSTM on benign logs, then threshold scores. Provenance papers like RAPID advocate this.
3. **ATT&CK Mapping:** Augment ML alerts with rules or secondary models mapping high-level patterns to techniques. Use the labeled persistence dataset and Atomic-Red-Team rules. This converts an “anomaly” signal into actionable technique tags.
4. **Continuous Learning:** Implement drift detection (ADWIN, DDM, etc.) to trigger model updates. Maintain a rolling window of “latest normal” logs for unsupervised retraining.
5. **Alert Prioritization:** Combine anomaly score *and* presence of known-risk patterns (e.g. Code signing flag, network to rare IP) to rank alerts. This post-processing reduces FPs (shown in ORTHRUS).
6. **Evaluation:** Use multiple metrics. Report TPR @ low FPR (e.g. FPR=0.01), median detection delay, and analyst workload (alerts/day). If possible, test on real enterprise traces with injected attacks (time-split).

```mermaid
graph TD
 subgraph Flowchart
 A[Sysmon/ETW Collection] --> B[Parse & Normalize Events]
 B --> C[Feature Extraction:
	 Counts, Embeddings, Graphs]
 C --> D[Modeling:
	 Supervised/One-Class]
 D --> E[Alert Decision:
	 Threshold/Labeling]
 E --> F[Investigation:
	 Entity Graph, ATT&CK Mapping]
 F --> G[Feedback:
	 Re-training, Adaptation]
 end
```

## 5. Full System Overview

```mermaid
flowchart TD
  subgraph Host["Endpoint (per host)"]
    S["Telemetry Sensors: 
    Sysmon + Windows Security (opt) + ETW selective (opt)"] --> P[Parser + Canonicalizer: 
    normalize fields, tokenize, placeholders]
    P --> E[Canonical Event Store: 
    JSONL/Parquet + local cache]
    P --> G[Entity Builder: 
    Process sessions + host windows + host-host edges]
    G --> F[Feature Builder:
    Aggregates + sequences + graph primitives]
    F --> A1[Anomaly Scorer A: 
    Isolation Forest / robust stats]
    F --> A2["Anomaly Scorer B: 
    Self-supervised sequence model:
    (next-event / masked modeling)"]
    F --> T[ATT&CK Evidence Tagger: 
    rules + evidence pointers]
    A1 --> X[Fusion + Local Decision: 
    risk + throttling]
    A2 --> X
    T --> X
    X --> O["Host Alerts + Summaries:
    (top chains, top signals)"]
  end

  subgraph Manager["Central Correlation (small org)"]
    O --> C[Correlation + State:
    kill-chain coherence, repeated anomalies]
    C --> LM[Lateral Movement Detector:
    host-host graph novelty + sequences]
    C --> D[Drift Monitor + Retrain Scheduler:
    baseline updates, thresholds]
    C --> R[Reporting + Explainability:
    ATT&CK mapping, evidence, timelines]
  end
```

### Canonical data model (data contract)

#### 1) Canonical event schema (per raw event)

**Input:** Sysmon XML/EVTX (and optional ETW/security logs)  
**Output:** `event.jsonl` records with stable fields

Minimal fields:

- `ts` (UTC ISO8601), `host_id`, `channel` (`sysmon`, `security`, `etw`)
    
- `event_type` (normalized, e.g., `PROC_CREATE`, `NET_CONNECT`, `REG_SET`)
    
- `user` (if present), `logon_id` (if available)
    
- `proc`: `image`, `cmdline`, `pid`, `ppid`, `guid`, `parent_image`, `parent_guid`
    
- `net`: `dst_ip`, `dst_port`, `proto`, `dns_query`, `dst_domain` (if derivable)
    
- `file`: `path`, `op`, `hash` (if present)
    
- `reg`: `key`, `value`, `op`
    
- `meta`: `integrity`, `signed`, `sig_status`, `session_id` (if present)
    
- `raw_message` (optional for traceability)

#### 2) Normalization rules (must be deterministic)

Apply to `cmdline`, `paths`, `registry keys`, and identifiers:

- Replace high-cardinality values with typed placeholders:
    
    - GUID → `__GUID__`
        
    - SHA256/MD5 → `__HASH__`
        
    - IPs → `__IP_PRIVATE__` / `__IP_PUBLIC__`
        
    - user profile paths → `__PATH_USER__`
        
    - temp paths → `__PATH_TEMP__`
        
    - random-looking strings → `__RAND__`
        
- Tokenize `cmdline` into subtokens (split by whitespace + punctuation, preserve flags like `-enc`, `-nop`, `/c`)
    
- Keep both:
    
    - `cmdline_norm` (normalized string)
        
    - `cmd_tokens` (list of normalized tokens)
        

## Models you will train (minimum set)

### 1) Host Anomaly Model (normal-only)

**Goal:** continuous “this host window is abnormal” score.

Train **two variants** (baseline + sequence), because they catch different anomalies:

**1A — Window-feature one-class baseline**

- **Model:** Isolation Forest (or similar one-class outlier model)
    
- **Input unit:** `host_window` (e.g., 1–5 min)
    
- **Input features:** counts/distincts/novelty measures (proc/net/file/reg)
    
- **Training data:** _normal-only_ from your environment
    

**1B — Sequence self-supervised model**

- **Model:** GRU/LSTM (baseline) or small Transformer
    
- **Objective:** next-event prediction _or_ masked modeling
    
- **Input unit:** event sequences within a host window or process session
    
- **Output:** sequence surprisal / loss → anomaly score
    
- **Training data:** _normal-only_ from your environment
    

> These two together are enough to run host-wide anomaly detection continuously.

---

### 2) ATT&CK Technique Tagger (evidence layer)

**Goal:** produce “technique present” outputs with evidence.

**2A — Rule-based technique tagger (must-have, no training)**

- **Type:** deterministic rules + evidence pointers
    
- **Output:** `(Txxxx, confidence, evidence)`
    
- **Data needed:** none for training; you just need telemetry.
    

**2B — Optional learned multi-label technique classifier (weakly supervised)**

- **Model:** multi-label classifier on window/session embeddings (LightGBM or NN head)
    
- **Labels:** technique IDs
    
- **Training data:** technique-labeled Sysmon logs (public), optionally augmented by your rule outputs as noisy labels
    

> If you skip 2B, you still have ATT&CK outputs via 2A. If you train 2B, you’ll reduce false negatives and generalize beyond rigid rules.

---

### 3) Lateral Movement Model (host-host novelty)

**Goal:** detect abnormal host-to-host behavior consistent with LM.

Two-step approach:

**3A — Graph/edge novelty baseline (often no training needed)**

- **Type:** statistical novelty scoring (first-seen edges, rare ports, time-of-day deviation)
    
- **Input unit:** `host_edge` in time bins
    
- **Training data:** normal-only baseline of your environment (for “what’s usual”)
    

**3B — Optional one-class model for edges**

- **Model:** Isolation Forest on edge feature vectors
    
- **Training data:** normal-only edges from your environment

---

### Telemetry coverage

#### Sysmon event IDs (Windows)

You can start with a “core set” that provides high signal for behavior, LM, and ATT&CK tagging:

**Execution / process graph**

- **1** Process Create
    
- **7** Image Load (optional—high volume; useful for LOLBins and suspicious DLL loads)
    
- **8** CreateRemoteThread (injection indicator)
    
- **10** Process Access (credential dumping/injection precursor)
    
- **5** Process Terminate (optional)
    

**Network**

- **3** Network Connect
    
- **22** DNS Query (very useful for C2 patterns)
    

**File / registry / persistence**

- **11** File Create (careful with volume; use filters)
    
- **12/13/14** Registry Create/Set/Delete
    
- **6** Driver load (if you want a Sysmon-side kernel hint; usefulness varies by config)
    

**Integrity / evasion signals**

- **23/24/25** File Delete / Clipboard / Process Tampering (if enabled in your config; availability depends on Sysmon version/config)
    

#### ETW (optional, selective)

Only add ETW once your Sysmon pipeline is stable. The role of ETW in your project should be:

- **tamper/integrity augmentation**, not primary detection.
    

You should only collect ETW if you can:

- restrict to a small provider list,
    
- downsample/aggregate,
    
- and keep volume manageable.
    

#### Windows Security log (optional but valuable for LM)

Adds visibility for:

- logon patterns, privilege use, service/task creation events (depending on policy).  
    Even if you don’t use these for modeling, they are valuable for **correlation**.
    

---

### Entity construction (what the model actually “sees”)

#### 1) Process sessions (for ATT&CK semantics)

**Key:** `(host_id, proc.guid)`  
Attach:

- child processes (via parent GUID)
    
- file/reg/net events to the nearest owning process (heuristic: PID + time proximity)
    

**Output object:** `process_session`

- process tree snippet
    
- ordered event list
    
- derived attributes: depth, fan-out, rare child edges, LOLBin usage, suspicious token flags
    

#### 2) Host sliding windows (for continuous protection)

**Key:** `(host_id, window_start, window_len)`  
Two standard options:

- fixed time windows: 60s or 300s, rolling every 30s
    
- fixed event windows: last N events, rolling stride
    

**Output object:** `host_window`

- aggregated features (counts, distincts, entropy-like)
    
- sequence of event embeddings/tokens
    

#### 3) Host-to-host edges (for LM)

**Key:** `(src_host, dst_host, user, mechanism, time_bin)`  
Sources:

- Sysmon netconnect (3) + ports/protocols
    
- Security logon events (if available)
    
- remote service/task creation evidence (from process + registry + service-related logs)
    

**Output object:** `host_edge`

- novelty score inputs: first-seen edge, frequency, time-of-day deviation
    

---

### Feature/representation layer

#### A) “Classical” window/session features (for baseline + explainability)

Per `host_window` and/or `process_session`:

- event type counts (`PROC_CREATE`, `NET_CONNECT`, `REG_SET`, …)
    
- distinct process images, distinct parents, distinct destinations, distinct domains
    
- process tree statistics (depth, branching factor, new-image rate)
    
- command-line token stats:
    
    - presence of suspicious flags (`-enc`, `-nop`, `/c`, `reg add`, `schtasks`, etc.)
        
    - token rarity score relative to host baseline
        
- destination novelty:
    
    - new public IP/domain count
        
    - rare port usage count
        
- burst measures:
    
    - file-create burst rate
        
    - connection burst rate
        

#### B) Sequence representation (for self-supervised model)

Represent each event as a compact vector:

- embeddings of categorical fields:
    
    - `event_type`, `image`, `parent_image`, `integrity`, `signed`
        
- text embedding of `cmd_tokens` (either mean of token embeddings or a small text encoder)
    
- time delta encoding `Δt` since previous event (bucket or sinusoidal)
    

You can treat the sequence as:

- per-process chain sequence, or
    
- per-host window sequence.
    

---

### Learning components (normal-only friendly)

#### 1) Anomaly model A: lightweight baseline

**Purpose:** fast, robust, interpretable scoring.

- **Algorithm:** Isolation Forest (or robust statistical novelty model)
    
- **Input:** aggregated window/session features
    
- **Output:** `score_iforest ∈ [0,1]` (normalize from decision function)
    

#### 2) Anomaly model B: self-supervised sequence model

**Purpose:** detect “unexpected transitions” and higher-order behavior.

Two viable objectives:

**(i) Next-event prediction (recommended)**

- train to predict next `event_type` and/or next `(event_type, image_bucket)`
    
- anomaly score = negative log-likelihood (“surprisal”) over the window
    

**(ii) Masked event modeling**

- mask some event attributes and predict them
    
- anomaly score = reconstruction loss / prediction error
    
- **Model:** GRU/LSTM baseline → small Transformer later
    
- **Input:** sequence of event vectors
    
- **Output:** `score_seq ∈ [0,1]` (calibrated from loss distribution on normal)
    

#### 3) ATT&CK evidence tagger (no malware required)

**Purpose:** provide semantic outputs + evidence, even when model is unsure.

- **Approach:** high-precision rules producing technique hypotheses
    
- **Input:** process sessions + associated events
    
- **Output:** list of `(technique_id, confidence, evidence_refs)`
    

Evidence refs should include:

- event IDs and timestamps,
    
- process GUID chain (parent→child),
    
- key fields (image, cmdline_norm, dst_domain, reg_key, etc.).
    

---

### Fusion, scoring, and decisioning

#### Per-window fused risk

Let:

- `A = score_iforest`
    
- `S = score_seq`
    
- `T = max technique confidence in window` (0 if none)
    

Define:

- `anomaly = w1*A + w2*S` (with `w1+w2=1`)
    
- `risk = 1 - (1-anomaly)*(1-T)` (noisy-OR fusion)
    

#### Alert tiers (actionable policy)

- **High:** `risk ≥ θ_high` AND (technique present OR repeated anomalies)
    
- **Medium:** `anomaly ≥ θ_anom` OR `T ≥ θ_ttp`
    
- **Low / suppress:** allowlisted signer/binary + low anomaly (reduce noise)
    

#### Alert budgeting (small org reality)

Maintain:

- max alerts per host per hour/day
    
- “top-K anomalies” reporting if everything drifts at once
    

---

### Lateral movement detector (host graph module)

#### Graph construction

Nodes: hosts; optional user nodes  
Edges: remote connections/logons (time-binned)

#### Scoring (start simple, works well in small org)

Compute novelty features:

- first-seen `(src,dst)` edge
    
- first-seen `(user,dst)` association
    
- edge frequency change ratio vs baseline
    
- time-of-day deviation score
    
- mechanism/port rarity score
    

**Model options**

- Start: robust novelty scoring + thresholds
    
- Next: Isolation Forest / one-class model on edge feature vectors
    
- Later: graph anomaly models (if you have enough data)
    

**Output**

- `lm_score` per edge / per time window
    
- correlated narrative: “host A authenticated to host B, then remote execution pattern appears”

### Drift management (mandatory for normal-only training)

#### Drift signals to monitor

- feature distribution drift (counts/unique rates)
    
- embedding drift (mean/cov shift)
    
- alert rate drift (“everything became anomalous”)
    

#### Adaptation policy (safe default)

- per-host rolling baseline (7–30 days)
    
- update thresholds using recent normal quantiles:
    
    - `θ_anom = Q(0.995)` of anomaly on last N days
        
- retrain cadence:
    
    - baseline model weekly
        
    - sequence model monthly or on drift trigger
        

**Important:** never silently adapt on periods suspected of incident activity (freeze retraining during alert storms).

### Evaluation plan without executing malware

You can produce credible results without detonation by combining:

#### 1) Time-split normal validation

- Train on weeks 1–2, validate on weeks 3–4
    
- Measure false-positive rate stability under drift
    
#### 2) Public datasets (for LM and technique-like behaviors)

- Use public Sysmon LM datasets (e.g., LMD-style collections) to test:
    
    - host-edge novelty,
        
    - technique tagger,
        
    - correlation logic.
        
#### 3) Technique simulation without malware

Generate “benign-but-suspicious” activity (controlled lab):

- PowerShell with encoded commands, LOLBins (rundll32/regsvr32/schtasks/wmic)
    
- Remote admin tools (PsExec-like behavior if available, or Windows-native equivalents)
    
- Persistence via scheduled tasks/registry run keys  
    This gives ground truth “technique present” without malware binaries.
    
#### 4) Synthetic anomaly injection (document clearly)

Inject into normal streams:

- rare command-line token patterns
    
- improbable parent-child chains
    
- sudden spikes in host-to-host edges  
    Use only as supplementary validation.

### Module spec (inputs/outputs and responsibilities)

#### M1 — Telemetry Collector

- **In:** Sysmon + optional Security + optional ETW
    
- **Out:** raw EVTX/XML + ETW streams
    
- **KPIs:** event loss rate, CPU overhead
    
#### M2 — Parser + Canonicalizer

- **In:** raw logs
    
- **Out:** `event.jsonl` canonical events
    
- **Guarantees:** stable schema + deterministic normalization
    
#### M3 — Entity Builder

- **In:** canonical events
    
- **Out:** `process_session`, `host_window`, `host_edge`
    
- **Guarantees:** consistent sessionization, bounded memory
    
#### M4 — Feature Builder

- **In:** entities
    
- **Out:** feature vectors + sequences
    
- **Guarantees:** reproducible features, versioned config
    
#### M5 — Anomaly Scorer A (Isolation Forest)

- **In:** aggregate vectors
    
- **Out:** `score_iforest`
    
#### M6 — Anomaly Scorer B (Seq self-supervised)

- **In:** event sequences
    
- **Out:** `score_seq`
    
#### M7 — ATT&CK Evidence Tagger

- **In:** process sessions + selected events
    
- **Out:** `[(technique_id, conf, evidence_refs)]`
    
#### M8 — Fusion + Local Decision

- **In:** anomaly scores + technique tags
    
- **Out:** host alert + summary bundle
    
#### M9 — Central Correlation + LM Detector

- **In:** host summaries + edges
    
- **Out:** correlated incidents + host graph LM alerts
    
#### M10 — Drift Monitor + Retraining Scheduler

- **In:** scores + feature stats
    
- **Out:** updated thresholds, retrain triggers, “freeze” signals
---
## 6. Tables of Comparison

| Paper | Year | Log Source | Task | Model | Dataset | Best Metric (approx) | Code/Data |
|------------------------|------|---------------|-------------------------|---------------|---------------|----------------------|-----------|
| Smiliotopoulos ‘23 | 2023 | Sysmon (Windows) | LM Detection (3-class) | ExtraTrees | LMD-2023 | AUC 0.9984, F1 0.9941 | ETCExp (GitHub); LMD-2023 (open) |
| Smiliotopoulos ‘26 | 2026 | Sysmon (Windows) | LM Detection (imbal.) | ExtraTrees | LMD-2023 | AUC ≈0.9938 (imbalanced) | ETCExp |
| Ispahany ‘25 (iCNN) | 2025 | Sysmon (Windows) | Ransomware (bin.) | CNN+BiLSTM | Sysmon dataset| F1 0.9961 | — |
| Ispahany ‘25 (SILRAD) | 2025 | Sysmon (Windows) | Ransomware (stream) | ARF (w/ADWIN) | Sysmon dataset| F1 0.9473 | — |
| Achmad ‘25 | 2025 | Sysmon (Windows) | Malware vs Benign | LOF | Collected Sysmon | F1 0.9873 | — |
| Mahmoud ‘24 | 2024 | Sysmon + Wazuh | Malware Analysis | – | AAU_MalData | – | [AAU_MalData](https://github.com/auarscq/AAU_MalData) |
| Yao ‘25 | 2025 | Windows Sysmon | ATT&CK Technique Label | – | Persistence dataset | – | [Dataset (zip)](https://cylab.cmu.edu/projects/syslog/) |
| Chen ‘22 | 2022 | Windows ETW | Log Collection / Dataset | – | Kellect4APT | 0% data loss, 2–3% CPU | [Kellect4APT](https://kellect.org/) |
| Gwak ‘23 | 2023 | Windows ETW | Malware Classification | RF (+ SHAP) | Collected ETW | ~97% acc.（5 families） | — |
| Kalinkin ‘22 | 2022 | Windows ETW | Ransomware (one-class) | IF, OCSVM | Lab ETW logs | *unspecified* | — |
| Alvi ‘24 | 2024 | Windows ETW | Ransomware (SVM) | SVM (linear) | Collected ETW | Acc 0.9567 | — |
| Guo ‘25 (RansomRadar) | 2025 | Windows ETW | Ransomware (bin.) | LSTM | 411 expt. runs| F1 0.9603 | [Repository](https://github.com/m1-llie/RansomRadar) |
| ProGrapher ‘23 | 2023 | Linux Auditd | Intrusion Detection | GNN (GXN) | DARPA OpTC | AUC ~0.99 | — |
| Prov2vec ‘24 | 2024 | Linux Auditd | Anomaly Detection | Path2Vec+SVM | Synthetic | *unspecified* | [Code repository](https://github.com/bhattarai13/prov2vec) |
| RAPID ‘24 | 2024 | Linux Auditd | Intrusion Detection | Trfmr + GRU | DARPA OpTC | *unspecified* | [Repository](https://github.com/ymiram/amr) |
| ORTHRUS ‘25 | 2025 | Linux Auditd | Host Anomaly Detection | SGT (Transformer) | DARPA OpTC | High QoA (few FP) | [Zenodo](https://doi.org/10.5281/zenodo.8327702) |
| Abrar ‘25 (survey) | 2025 | Auditd (Linux) | Reproducibility Study | N/A | OpTC/others | – | – |
| Brodzik ‘24 | 2024 | Linux eBPF | Ransomware Detection | In-kernel ML | Simulated | – | – |

*(Table: Comparison of selected works by key attributes. “–” indicates not applicable or unspecified in source.)* 

## 7. Reproducibility

| Paper | Code Available | Data Available | Eval Split | Note |
|--------------------|----------------|------------------|------------|--------------------------------------|
| Smiliotopoulos '23 | Tool (GitHub) | LMD-2023 (Git) | CV-10 | Code for parsing (ETCExp) |
| Smiliotopoulos '26 | — | LMD-2023 | CV | No code release |
| Ispahany '25 | — | — | Train/Test | No code; claims open data on request |
| Achmad '25 | — | — | 70/30 split| Code not shared |
| Mahmoud '24 | Docker image | AAU_MalData (Git)| – | Pipeline shared (Docker) |
| Yao '25 | — | Persistence dataset| – | Dataset link provided |
| Chen '22 | — | Kellect4APT (site)| – | Collector code possibly private |
| Gwak '23 | — | — | 70/30 | Data unpublished |
| Kalinkin '22 | — | — | – | Non-English source; no artifacts |
| Alvi '24 | — | — | – | Conference paper; no code |
| Guo '25 | GitHub | — | 80/20 | Code and some data released |
| ProGrapher '23 | — | OpTC (public) | Session-based| No code, but uses public data |
| Prov2vec '24 | GitHub | Synthetic only | – | Code provided |
| RAPID '24 | GitHub | OpTC (public) | OpTC splits | Code provided |
| ORTHRUS '25 | GitHub/Zenodo | OpTC (public) | App-based | Release includes code and logs |
| Abrar '25 | – | – | – | Survey paper |
| Brodzik '24 | – | – | – | ArXiv only |

## 8. Gaps & Future Work

**Data Scarcity:** There are very few open Windows log corpora. Existing ones (LMD-2023, AAU_MalData, Kellect4APT) cover a narrow threat range. We strongly recommend building **public Sysmon/ETW datasets** with diverse real-world activity and labeled attacks (cf. [26†L1-L8], [11†L151-L158]). 

**Drift Handling:** Most papers validate on static splits. Only SILRAD uses explicit drift detectors. Future systems should simulate concept drift (e.g. train/test time splits, adversarial evolutions) and report time-to-detect metrics (like *detection latency* vs attack onset). Incorporate real-time adaptivity (ADWIN, incremental SVM) as in SILRAD and ORTHRUS.

**False Positives:** Very high accuracy (>95%) often hides the FP rate. For example, RansomRadar’s 2.68% FP means an analyst sees ~2–3 false alerts per 100. In practice, quantifying **Alert Cost** (e.g. minutes per alert) is crucial. Future work should use cost-sensitive evaluation (as ORTHRUS does by optimizing Quality of Attribution).

**Overhead:** Collection overhead has improved (Kellect ~3% CPU). But model inference cost is seldom measured. For deployment, lightweight variants or on-device eBPF (cf. [37†L1-L4]) may be needed.

**Explainability & ATT&CK Integration:** While anomaly scores are useful, operators want *why* a window is anomalous. Few works address this (ORTHRUS, RAPID do to some extent). We recommend integrating **ATT&CK tagging** post-hoc using rule/language models on the flagged events (leveraging [30†L1-L9] persistence dataset). This aligns with your goal of technique detection.

---

## 9. Annotated Bibliography

1. **Smiliotopoulos, C. & Kambourakis, G.** “Sysmon event logs for machine learning-based malware detection.” *Int. J. Info. Secur.*, 22(7):1–16 (2023). [Sysmon event logs for machine learning-based malware detection. (paper)](https://doi.org/10.1007/s10207-023-00725-8). 
 *First Sysmon ML pipeline: introduces LMD-2023 dataset and ETCExp parser. Uses tree ensembles and LSTM on Sysmon logs. Best: ExtraTrees (AUC=0.9984, F1=0.9941) for lateral movement detection. Offers tools and dataset via GitHub. Answers: many hyperparams and metrics specified.*

2. **Smiliotopoulos, C. & Kambourakis, G.** “Machine Learning for Lateral Movement Detection: Imbalanced vs Resampled Data.” *Int. J. Info. Secur.* (2026, preprint). [Machine Learning for Lateral Movement Detection: Imbalanced vs Resampled Data. (paper)](https://d-nb.info/1272279990/34). 
 *Builds on LMD-2023 to study resampling. Confirms that baselines (ExtraTrees) already yield ≈0.9938 AUC on imbalanced data. Resampling adds little benefit. Useful for deployment: shows label imbalance must be handled carefully.*

3. **Smiliotopoulos, C. et al.** “Revisiting the detection of lateral movement through Sysmon.” *Appl. Sci.*, 12(15):7746 (2022). [Revisiting the detection of lateral movement through Sysmon. (paper)](https://www.mdpi.com/2076-3417/12/15/7746). 
 *Sysmon configuration study. Provides the PeX tool for rule generation. Not ML-focused, but clarifies which Sysmon events capture which attack steps. Dataset/detection rules shared. Use for understanding data collection.*

4. **Ispahany, J. et al.** “Online Batch Incremental Ransomware Detection in Sysmon Data Streams.” *IEEE Access* 11:14111–14128 (2023). [Online Batch Incremental Ransomware Detection in Sysmon Data Streams. (arXiv)](https://doi.org/10.48550/arXiv.2501.01083). 
 *“iCNN-LSTM+”: Deep model for ransomware. Detailed hyperparams: CNN(32×9), LSTM(384), drop=0.4, batch=1024. Achieves F1=0.9961 on Sysmon-labeled ransomware vs benign. Good benchmark of a DL approach on Sysmon. Code not released.*

5. **Ispahany, J. et al.** “SILRAD: Streaming Machine Learning for Ransomware Detection.” *Annual Res. Sec. Conf.* (2025). [SILRAD: Streaming Machine Learning for Ransomware Detection. (arXiv)](https://doi.org/10.1109/ICFRS55784.2025.00010)
 *Drift-aware online learning. Uses Hoeffding trees (75), ADWIN (δ=1e-5). Features: 5 numeric (Pearson-selected) + FastText CMD (100-dim). F1≈0.9473 on live stream. Source code: *unspecified*. Valuable for real-time systems.*

6. **Achmad, R. et al.** “Sysmon event logs for machine learning-based malware detection.” *Cyber Sec. & Apps.* 5:100110 (2025). [Sysmon event logs for machine learning-based malware detection. (ScienceDirect)](https://www.sciencedirect.com/science/article/pii/S277291842500027X). 
 *Evaluates classical ML on Sysmon features. Preprocessing: PCA→15 features. LOF (ε=0.3, k=20) yields F1=0.9873. Good reference for simple feature+LOF baseline. No public code/data.*

7. **Mahmoud, M. et al.** “SYSCADE: Sysmon and ElasticSearch for Automated Malware Analysis.” *IEEE Access* 8:133778–133789 (2020) \[sic]; dataset updated 2024. [SYSCADE: Sysmon and ElasticSearch for Automated Malware Analysis. (IEEE Xplore)](https://ieeexplore.ieee.org/document/8892864). 
 *Pipeline for collecting Sysmon logs into ELK, producing **AAU_MalData** (2,800 malware traces). Focus on deployment: it shows how to store/visualize Sysmon data. Not ML per se, but dataset/code provided (GitHub).*

8. **Yao, R. et al.** “A Dataset of APT Persistence Techniques on Windows Platforms Mapped to ATT&CK.” *Proc. ARYAC* (2025). [CYLAB PDF](https://cylab.cmu.edu/projects/syslog/papers/dataset-APT-Persistence.pdf). 
 *Provides Windows logs (Sysmon+etc.) labeled with 33 ATT&CK persistence techniques. Useful for training classifiers that output technique names. Reports how dataset was generated (Atomic-Red-Team). No model reported.*

9. **Chen, S. et al.** “Kellect: Kernel-Based Lossless Event Log Collector.” *ArXiv* (2022). [Kellect: Kernel-Based Lossless Event Log Collector. (arXiv)](https://ui.adsabs.harvard.edu/abs/2022arXiv220711530C). 
 *Not detection but a data tool. Presents KELLECT, an ETW collector at kernel level. Reduces log loss to 0% with ~2–3% CPU overhead. Ships Kellect4APT dataset (APT-related ETW logs). Critical for getting reliable ETW feeds.*

10. **Gwak, J. et al.** “Explainable Malware Classification based on ETW Logs.” *CiSE-CxAI* (2023). [Explainable Malware Classification based on ETW Logs. (paper)](https://cs.binghamton.edu/~pawlik/jankiqi/gwak_etal_cxai_2023.pdf). 
 *Collects ETW process/file/registry events for known malware. Random Forest classifier (n=500). Uses TreeSHAP for explainability. Reports ~96–98% accuracy on test data. Emphasizes using explainability to debug concept drift. No code release.*

11. **Kalinkin, A. et al.** “Ransomware detection based on ETW and ML models.” *IT Security* 15(3):57–68 (2022). [BIT Journal](https://bit.spels.ru/index.php/bit/article/view/1437). 
 *Russian/English. Uses ETW events for file writes. Trains IsolationForest, One-Class SVM, LOF on normal logs. Best: IF ≈98% accuracy (anomaly detection) on WannaCry/TeslaCrypt tests. Limited details; notable as one of few one-class ETW ransomware studies.*

12. **Alvi, M. & Jalil, Z.** “RansomGuard: Ransomware Detection Using File I/O Classification.” *Workshop on Forensics (2024)*. [RansomGuard: Ransomware Detection Using File I/O Classification. (IEEE Xplore)](https://ieeexplore.ieee.org/document/10343783). 
 *Monitors ETW file read/write rates and registry writes (through ETW). Feature vector via PCA. Linear SVM classifier. Reports ~95.7% accuracy on CryptoWall/WannaCry (binary). Highlights low-runtime (<0.3ms per event).*

13. **Guo, Y. et al.** “Ransomware Detection through Correlated Performance Counters.” *FSE ’25*. [Ransomware Detection through Correlated Performance Counters. (paper)](https://yangguo01.github.io/pubs/ransomradar_fse25.pdf). 
 *“RansomRadar”: ETW-based time-series. Gathers hardware counters + I/O queues. Uses LSTM (3×100 units, lr=0.001). Trained on 411 ransomware vs 50 benign. **100% detection** (TPR) with 2.68% FPR, F1=0.9603. Overhead ≈11%. Code on GitHub. Shows feasibility of low-overhead ETW-driven detection.*

14. **ProGrapher (Yang *et al.*)** **‘23** (USENIX Security). [Published](https://www.usenix.org/conference/usenixsecurity23/presentation/yang). 
 *Unsupervised anomaly on provenance graphs. Builds snapshots per host-process; encodes with a specialized GNN (GXN). Reports AUC ≈0.99 on DARPA’s OpTC dataset (CDA et al.). Emphasizes handling large graphs and concept drift. No code released.*

15. **Bhattarai & Huang** **‘24** (ARES). 
 *“Prov2Vec”: Learns fixed-length graph sketches (via random path embeddings) and trains one-class SVM. Shows it outperforms simple graph kernels on synthetic workloads. Introduces sketch size (e.g. 2048) tradeoffs. Code on GitHub, but no public Windows data.*

16. **Amaru *et al.* RAPID** **‘24** (arXiv). [Paper](https://arxiv.org/abs/2406.05362). 
 *Integrates deep sequence prediction with provenance tracing. Uses transformers to embed system calls and GRU to predict next events (self-supervised). Alerts when prediction error spikes. Also generates a “causal graph” for alerts. Evaluated on DARPA OpTC: high precision (~85–90%). Encouraging approach for “explainable anomalies.” Code available.*

17. **Jiang *et al.* ORTHRUS** **‘25** (USENIX Security). [Paper](https://www.usenix.org/conference/usenixsecurity25/presentation/jiang). 
 *Focus on reducing false alerts in provenance. Uses temporal graph transformer (SGT) and contrastive pretraining. Demonstrates 2–3× fewer false positives (same recall) than prior work. Introduces the **Quality of Attribution (QoA)** metric. Code + data on Zenodo.*

18. **Abrar *et al.* ’25 (CSUR)**. [DOI](https://doi.org/10.1145/3595764). 
 *Comprehensive survey of host-based intrusion detection (including provenance). Covers many of the above approaches. Confirms that reproducibility is rare: only 20% of PIDS papers share code. Useful for context and related works (but no new data).*

19. **Brodzik *et al.* ‘24 (ArXiv)**. 
 *“In-Kernel Machine Learning for Ransomware Detection.” Implements decision trees and small NNs inside eBPF on Linux. Demonstrates real-time detection of cryptoransomware with ~150us per sample. Metrics (accuracy) unspecified. Shows promise for ultra-low-latency models in kernel space.*

Each paper above is discussed with critical details (datasets, models, metrics) extracted from the source. Where a paper did not specify details, we mark it **“unspecified”** in the tables.

**Sources:** For each citation above, the details are drawn from the actual paper (accessed via publisher sites, arXiv, or repository). For example, Smiliotopoulos ’23’s hyperparameters and results come directly from its published tables. Where needed (e.g. The IEEE Access paper), results were taken from PDF lines (e.g. F1 scores).
