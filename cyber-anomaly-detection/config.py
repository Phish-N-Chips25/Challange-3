"""
Central configuration for the cyber-anomaly-detection project.
All paths resolve relative to the workspace root (h:/Challenge-3-4).
"""
from pathlib import Path
import os

# ── Workspace & project roots ─────────────────────────────────────────────────
WORKSPACE_ROOT = Path(os.getenv("WORKSPACE_ROOT", r"h:\Challenge-3-4"))
PROJECT_ROOT   = Path(__file__).parent

# ── Raw dataset paths ─────────────────────────────────────────────────────────
SILRAD_DIR   = WORKSPACE_ROOT / "SILRAD-dataset"
SILRAD_TRAIN = SILRAD_DIR / "fasttext-trainmodel.csv"
SILRAD_TEST  = SILRAD_DIR / "fasttext-testmodel.csv"
SILRAD_ALL   = SILRAD_DIR / "fasttext-all-nofamily.csv"

LMD_DIR      = WORKSPACE_ROOT / "LMD-2023"
LMD_VARIANTS = {
    "1.75M": {
        "raw":          LMD_DIR / "LMD-2023 [1.75M Elements]" / "LMD-2023 [1.75M Elements] Checked" / "LMD-2023 [1.75M Elements]Checked.csv",
        "labelled":     LMD_DIR / "LMD-2023 [1.75M Elements]" / "LMD-2023 [1.75M Elements] Checked" / "Labelled LMD-2023" / "LMD-2023 [1.75M Elements][Labelled]checked.csv",
        "preprocessed": LMD_DIR / "LMD-2023 [1.75M Elements]" / "LMD-2023 [1.75M Elements] Checked" / "Preprocessed LMD-2023" / "LMD-2023 [1.75M Elements][Labelled+Preprocessed].csv",
    },
    "1.87M": {
        "raw":          LMD_DIR / "LMD-2023 [1.87M Elements]" / "LMD-2023 [1.87M Elements]Checked" / "LMD-2023 [1.87M Elements]checked.csv",
        "labelled":     LMD_DIR / "LMD-2023 [1.87M Elements]" / "LMD-2023 [1.87M Elements]Checked" / "Labelled LMD-2023" / "LMD-2023 [1.87M Elements][Labelled]checked.csv",
        "preprocessed": LMD_DIR / "LMD-2023 [1.87M Elements]" / "LMD-2023 [1.87M Elements]Checked" / "Preprocessed LMD-2023" / "LMD-2023 [1.87M Elements][Labelled+Preprocessed]checked.csv",
    },
    "2.3M": {
        "raw":          LMD_DIR / "LMD-2023 [2.3M Elements]" / "LMD-2023 [2.3M Elements]Checked" / "LMD-2023 [2.3M Elements]Checked.csv",
        "labelled":     LMD_DIR / "LMD-2023 [2.3M Elements]" / "LMD-2023 [2.3M Elements]Checked" / "Labelled LMD-2023" / "LMD-2023 [2.3M Elements][Labelled]checked.csv",
        "preprocessed": LMD_DIR / "LMD-2023 [2.3M Elements]" / "LMD-2023 [2.3M Elements]Checked" / "Preprocessed LMD-2023" / "LMD-2023 [2.3M Elements][Labelled+Preprocessed]checked.csv",
    },
}
LMD_DEFAULT_VARIANT = "2.3M"

OTRF_DIR          = WORKSPACE_ROOT / "OTRF" / "datasets"
OTRF_ATOMIC_META  = OTRF_DIR / "atomic" / "_metadata"
OTRF_COMPOUND_DIR = OTRF_DIR / "compound"
OTRF_APT29_DIR    = OTRF_COMPOUND_DIR / "apt29"

SPLUNK_DIR         = WORKSPACE_ROOT / "Splunk" / "datasets"
SPLUNK_TECHNIQUES  = SPLUNK_DIR / "attack_techniques"
SPLUNK_MALWARE_DIR = SPLUNK_DIR / "malware"

# ── Processed / artifact output paths ────────────────────────────────────────
PROCESSED_DIR   = PROJECT_ROOT / "data" / "processed"
ATTACK_KB_DIR   = PROJECT_ROOT / "data" / "attack_kb"
SIGMA_RULES_DIR = ATTACK_KB_DIR / "sigma_rules"
MODELS_DIR      = PROJECT_ROOT / "models"

for _d in [PROCESSED_DIR, ATTACK_KB_DIR, MODELS_DIR]:
    _d.mkdir(parents=True, exist_ok=True)

# ── Canonical Sysmon schema ───────────────────────────────────────────────────
SYSMON_COLUMNS = [
    "event_id",        # Sysmon EventID (int)
    "utc_time",        # ISO timestamp
    "process_guid",    # ProcessGuid
    "process_id",      # ProcessId (int)
    "image",           # Full executable path
    "command_line",    # CommandLine string
    "current_dir",     # CurrentDirectory
    "user",            # User account
    "integrity_level", # High / Medium / Low / System
    "parent_guid",     # ParentProcessGuid
    "parent_id",       # ParentProcessId (int)
    "parent_image",    # ParentImage path
    "parent_cmdline",  # ParentCommandLine
    "image_loaded",    # ImageLoaded (EID 7)
    "signed",          # Signed boolean string
    "signature",       # Signature name
    "sig_status",      # SignatureStatus
    "target_object",   # TargetObject (registry / file)
    "details",         # Details (registry value data)
    "target_image",    # TargetImage (process injection)
    "granted_access",  # GrantedAccess hex
    "call_trace",      # CallTrace
    "dest_ip",         # DestinationIp
    "dest_port",       # DestinationPort (int)
    "dest_hostname",   # DestinationHostname
    "target_filename", # TargetFilename (file events)
    "event_type",      # EventType (registry)
    "pipe_name",       # PipeName
    "query_name",      # QueryName (DNS)
    "query_results",   # QueryResults (DNS)
    "rule_name",       # RuleName (Sysmon rule tag)
    "hashes",          # Hashes (MD5, SHA256, IMPHASH)
    "label",           # Ground-truth label (-1 = unknown)
    "dataset_source",  # Origin: SILRAD | LMD | OTRF | SPLUNK
    "attck_technique", # ATT&CK T-code (e.g. "T1003.001"), "" if unknown
]

# ── Feature engineering ───────────────────────────────────────────────────────
CATEGORICAL_COLS  = ["event_id", "integrity_level", "signed", "sig_status", "event_type", "rule_name"]
TEXT_COLS         = ["image", "command_line", "parent_image", "parent_cmdline", "target_object"]
TFIDF_MAX_FEATURES = 512

WINDOW_SIZE   = 64   # events per sequence window (config default; actual HPO value: 45)
WINDOW_STRIDE = 32   # stride (actual HPO value: 45 — non-overlapping)

# ── Classical anomaly detectors ───────────────────────────────────────────────
IFOREST_CONTAMINATION = 0.05
IFOREST_N_ESTIMATORS  = 200
IFOREST_RANDOM_STATE  = 42

# ── Autoencoder defaults ──────────────────────────────────────────────────────
AUTOENCODER_HIDDEN_DIMS  = [256, 128, 64]
AUTOENCODER_LATENT_DIM   = 32
AUTOENCODER_EPOCHS       = 30
AUTOENCODER_BATCH_SIZE   = 512
AUTOENCODER_PATIENCE     = 12
ANOMALY_THRESHOLD_PCTILE = 95   # percentile of benign reconstruction error

# ── Sequence model defaults ───────────────────────────────────────────────────
# Best configuration found by Optuna (60 trials, nb07):
#   TransformerAE, W=45, stride=45, hidden=256, latent=128, nhead=8, layers=2
SEQUENCE_MODEL  = "transformer"
SEQ_HIDDEN_DIM  = 256
SEQ_NUM_LAYERS  = 2
SEQ_NHEAD       = 8
SEQ_DROPOUT     = 0.1
SEQ_EPOCHS      = 20
SEQ_BATCH_SIZE  = 128
SEQ_LR          = 1e-3
SEQUENCE_PATIENCE = 12

# ── Optuna HPO settings ───────────────────────────────────────────────────────
AUTOML_SEED           = 42
AUTOML_MAX_TRIALS     = 100
ATOMIC_CHECKPOINT_WRITES = True   # write via temp file + rename for crash safety
SEQUENCE_TUNER_BACKEND   = "optuna"

OPTUNA_STARTUP_TRIALS  = 8
OPTUNA_WARMUP_EPOCHS   = 4
OPTUNA_STORAGE_DIR     = PROJECT_ROOT / "models" / "optuna"
OPTUNA_STORAGE_DIR.mkdir(parents=True, exist_ok=True)
OPTUNA_STORAGE_PATH    = OPTUNA_STORAGE_DIR / "studies.db"
OPTUNA_STORAGE_URL     = f"sqlite:///{OPTUNA_STORAGE_PATH.as_posix()}"
OPTUNA_LOAD_IF_EXISTS  = True

# ── LLM / SLM pipeline ───────────────────────────────────────────────────────
# Inference via Ollama HTTP (no Python SDK needed).
# Run: ollama serve && ollama pull qwen2.5:32b
OLLAMA_BASE_URL       = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL          = os.getenv("OLLAMA_MODEL",    "qwen2.5:32b")
OLLAMA_TIMEOUT        = 600   # seconds (32B model with CoT can take 3–5 min)
CONTEXT_WINDOW_EVENTS = 32   # events per LLM prompt

# ── ATT&CK KB / RAG ──────────────────────────────────────────────────────────
CHROMA_PERSIST_DIR = str(ATTACK_KB_DIR / "chroma_db")
EMBEDDING_MODEL    = "sentence-transformers/all-mpnet-base-v2"
RAG_TOP_K          = 5   # default k; nb10 uses k=15 for higher recall
