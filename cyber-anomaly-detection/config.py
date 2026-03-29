"""
Central configuration for the cyber-anomaly-detection project.
All paths resolve relative to the workspace root (h:/Challenge-3-4).
"""
from pathlib import Path
import os

# ---------------------------------------------------------------------------
# Workspace & project roots
# ---------------------------------------------------------------------------
WORKSPACE_ROOT = Path(os.getenv("WORKSPACE_ROOT", r"h:\Challenge-3-4"))
PROJECT_ROOT = Path(__file__).parent

# ---------------------------------------------------------------------------
# Raw dataset paths (no files are moved – references only)
# ---------------------------------------------------------------------------
SILRAD_DIR = WORKSPACE_ROOT / "SILRAD-dataset"
SILRAD_TRAIN = SILRAD_DIR / "fasttext-trainmodel.csv"
SILRAD_TEST  = SILRAD_DIR / "fasttext-testmodel.csv"
SILRAD_ALL   = SILRAD_DIR / "fasttext-all-nofamily.csv"

LMD_DIR = WORKSPACE_ROOT / "LMD-2023"
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
# Default variant used in experiments
LMD_DEFAULT_VARIANT = "2.3M"

OTRF_DIR          = WORKSPACE_ROOT / "OTRF" / "datasets"
OTRF_ATOMIC_META  = OTRF_DIR / "atomic" / "_metadata"
OTRF_COMPOUND_DIR = OTRF_DIR / "compound"
OTRF_APT29_DIR    = OTRF_COMPOUND_DIR / "apt29"

SPLUNK_DIR         = WORKSPACE_ROOT / "Splunk" / "datasets"
SPLUNK_TECHNIQUES  = SPLUNK_DIR / "attack_techniques"
SPLUNK_MALWARE_DIR = SPLUNK_DIR / "malware"

# ---------------------------------------------------------------------------
# Processed / artifact output paths
# ---------------------------------------------------------------------------
PROCESSED_DIR  = PROJECT_ROOT / "data" / "processed"
ATTACK_KB_DIR  = PROJECT_ROOT / "data" / "attack_kb"
MODELS_DIR     = PROJECT_ROOT / "models"
MLFLOW_URI     = str(PROJECT_ROOT / "mlruns")

for _d in [PROCESSED_DIR, ATTACK_KB_DIR, MODELS_DIR]:
    _d.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# Canonical Sysmon schema
# ---------------------------------------------------------------------------
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
    "image_loaded",    # ImageLoaded (Event 7)
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

# ---------------------------------------------------------------------------
# Feature engineering settings
# ---------------------------------------------------------------------------
CATEGORICAL_COLS = [
    "event_id", "integrity_level", "signed", "sig_status",
    "event_type", "rule_name",
]
TEXT_COLS = ["image", "command_line", "parent_image", "parent_cmdline", "target_object"]
TFIDF_MAX_FEATURES = 512

WINDOW_SIZE   = 64    # number of events per sequence window
WINDOW_STRIDE = 32    # stride for sliding window

# ---------------------------------------------------------------------------
# Classical pipeline hyperparameters
# ---------------------------------------------------------------------------
IFOREST_CONTAMINATION = 0.05
IFOREST_N_ESTIMATORS  = 200
IFOREST_RANDOM_STATE  = 42

AUTOENCODER_HIDDEN_DIMS  = [256, 128, 64]
AUTOENCODER_LATENT_DIM   = 32
AUTOENCODER_EPOCHS       = 30
AUTOENCODER_BATCH_SIZE   = 512
ANOMALY_THRESHOLD_PCTILE = 95  # percentile of reconstruction error on benign data

SEQUENCE_MODEL   = "transformer"  # options: "gru" | "lstm" | "transformer"
SEQ_HIDDEN_DIM   = 256
SEQ_NUM_LAYERS   = 2
SEQ_NHEAD        = 4
SEQ_DROPOUT      = 0.1
SEQ_EPOCHS       = 20
SEQ_BATCH_SIZE   = 128
SEQ_LR           = 1e-3

# ---------------------------------------------------------------------------
# LLM / SLM pipeline settings
# ---------------------------------------------------------------------------
OLLAMA_BASE_URL   = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL      = os.getenv("OLLAMA_MODEL", "phi4:14b-q4_K_M")
OLLAMA_TIMEOUT    = 120  # seconds

CONTEXT_WINDOW_EVENTS = 32   # events per LLM prompt (sliding)

CHROMA_PERSIST_DIR  = str(ATTACK_KB_DIR / "chroma_db")
EMBEDDING_MODEL     = "all-MiniLM-L6-v2"  # sentence-transformers model
RAG_TOP_K           = 5

JUDGE_PROVIDER      = os.getenv("JUDGE_PROVIDER", "anthropic")  # "anthropic" | "openai"
ANTHROPIC_API_KEY   = os.getenv("ANTHROPIC_API_KEY", "")
OPENAI_API_KEY      = os.getenv("OPENAI_API_KEY", "")
JUDGE_MODEL_ANTHROPIC = "claude-haiku-4-5"
JUDGE_MODEL_OPENAI    = "gpt-4o-mini"

# ---------------------------------------------------------------------------
# Streaming settings
# ---------------------------------------------------------------------------
KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP", "localhost:9092")
KAFKA_TOPIC     = "sysmon-events"
KAFKA_GROUP_CLASSIC = "anomaly-classic"
KAFKA_GROUP_LLM     = "anomaly-llm"
REPLAY_EVENTS_PER_SEC = 100  # throttle for realistic simulation

# ---------------------------------------------------------------------------
# API settings
# ---------------------------------------------------------------------------
API_HOST = "0.0.0.0"
API_PORT = 8000

# ---------------------------------------------------------------------------
# AutoML / FLAML hyperparameter tuning settings
# ---------------------------------------------------------------------------
# Enable/disable AutoML tuning for each component
ENABLE_IFOREST_AUTOML      = False
ENABLE_AUTOENCODER_AUTOML  = False
ENABLE_SEQUENCE_AUTOML     = False

# Global AutoML budget constraints
AUTOML_TIME_BUDGET_SECONDS = 14400  # 4 hours per component; set to None to disable time budget
AUTOML_MAX_TRIALS          = 100   # max trials per component
AUTOML_VERBOSE_LEVEL       = 2     # 0=silent, 1=info, 2=debug
AUTOML_SEED                = 42
FLAML_HPO_METHOD           = "bs"  # use BlendSearch instead of random search for FLAML tuners

# Early stopping / resilience during long training runs
AUTOML_PATIENCE            = 12    # stop after N non-improving trials / epochs
AUTOENCODER_PATIENCE       = 12    # epochs without improvement before stopping
SEQUENCE_PATIENCE          = 12    # epochs without improvement before stopping
ATOMIC_CHECKPOINT_WRITES   = True  # write checkpoints via temp file + replace

# Sequence-model HPO backend
SEQUENCE_TUNER_BACKEND     = "optuna"  # preferred for GRU/LSTM/Transformer tuning
OPTUNA_STARTUP_TRIALS      = 8
OPTUNA_WARMUP_EPOCHS       = 4
OPTUNA_STORAGE_DIR         = PROJECT_ROOT / "models" / "optuna"
OPTUNA_STORAGE_DIR.mkdir(parents=True, exist_ok=True)
OPTUNA_STORAGE_PATH        = OPTUNA_STORAGE_DIR / "studies.db"
OPTUNA_STORAGE_URL         = f"sqlite:///{OPTUNA_STORAGE_PATH.as_posix()}"
OPTUNA_LOAD_IF_EXISTS      = True

# ---------------------------------------------------------------------------
# IForest AutoML search space
# ---------------------------------------------------------------------------
IFOREST_SEARCH_SPACE = {
    "n_estimators": {
        "domain": lambda: int(__import__("random").uniform(100, 500)),
        "log_scale": False,
        "min": 50,
        "max": 1000,
    },
    "contamination": {
        "domain": lambda: __import__("random").uniform(0.01, 0.2),
        "log_scale": True,
        "min": 0.001,
        "max": 0.5,
    },
    "max_samples": {
        "domain": lambda: int(__import__("random").uniform(128, 512)),
        "log_scale": False,
        "min": 64,
        "max": 1024,
    },
    "max_features": {
        "domain": lambda: __import__("random").uniform(0.5, 1.0),
        "log_scale": False,
        "min": 0.1,
        "max": 1.0,
    },
    "bootstrap": {"domain": [False, True]},
}

# IForest AutoML metric to optimize
IFOREST_AUTOML_METRIC = "roc_auc"  # "precision", "recall", "f1", "roc_auc"

# ---------------------------------------------------------------------------
# Autoencoder AutoML search space
# ---------------------------------------------------------------------------
AUTOENCODER_SEARCH_SPACE = {
    "learning_rate": {
        "domain": lambda: float(10 ** __import__("random").uniform(-4, -2)),
        "log_scale": True,
        "min": 1e-5,
        "max": 1e-2,
    },
    "batch_size": {
        "domain": lambda: int(__import__("random").choice([128, 256, 512, 1024])),
        "log_scale": False,
        "min": 32,
        "max": 2048,
    },
    "epochs": {
        "domain": lambda: int(__import__("random").uniform(10, 50)),
        "log_scale": False,
        "min": 5,
        "max": 100,
    },
    "weight_decay": {
        "domain": lambda: float(10 ** __import__("random").uniform(-6, -3)),
        "log_scale": True,
        "min": 1e-7,
        "max": 1e-3,
    },
    "dropout": {
        "domain": lambda: __import__("random").uniform(0.0, 0.5),
        "log_scale": False,
        "min": 0.0,
        "max": 0.7,
    },
}

# Autoencoder hidden dimensions alternatives (categorical)
AUTOENCODER_HIDDEN_DIMS_CHOICES = [
    [128, 64, 32],
    [256, 128, 64],
    [512, 256, 128],
    [256, 128, 64, 32],
    [512, 256, 128, 64],
]

# Autoencoder AutoML metric to optimize
AUTOENCODER_AUTOML_METRIC = "roc_auc"  # "precision", "recall", "f1", "roc_auc"
AUTOENCODER_GPU_VRAM_GB = float(os.getenv("AUTOENCODER_GPU_VRAM_GB", "16"))
AUTOENCODER_VRAM_UTILIZATION = float(os.getenv("AUTOENCODER_VRAM_UTILIZATION", "0.85"))
AUTOENCODER_MAX_ESTIMATED_PARAMS = int(os.getenv("AUTOENCODER_MAX_ESTIMATED_PARAMS", "12000000"))

# ---------------------------------------------------------------------------
# Sequence Model (Transformer/GRU/LSTM) AutoML search space
# ---------------------------------------------------------------------------
SEQUENCE_SEARCH_SPACE = {
    "hidden_dim": {
        "domain": lambda: int(__import__("random").choice([128, 256, 512])),
        "log_scale": False,
        "min": 64,
        "max": 1024,
    },
    "num_layers": {
        "domain": lambda: int(__import__("random").choice([1, 2, 3, 4])),
        "log_scale": False,
        "min": 1,
        "max": 6,
    },
    "dropout": {
        "domain": lambda: __import__("random").uniform(0.0, 0.5),
        "log_scale": False,
        "min": 0.0,
        "max": 0.7,
    },
    "learning_rate": {
        "domain": lambda: float(10 ** __import__("random").uniform(-4, -2)),
        "log_scale": True,
        "min": 1e-5,
        "max": 1e-2,
    },
    "batch_size": {
        "domain": lambda: int(__import__("random").choice([32, 64, 128, 256])),
        "log_scale": False,
        "min": 16,
        "max": 512,
    },
    "epochs": {
        "domain": lambda: int(__import__("random").uniform(10, 50)),
        "log_scale": False,
        "min": 5,
        "max": 100,
    },
    "weight_decay": {
        "domain": lambda: float(10 ** __import__("random").uniform(-6, -3)),
        "log_scale": True,
        "min": 1e-7,
        "max": 1e-3,
    },
}

# Transformer-specific search space (additional)
TRANSFORMER_SEARCH_SPACE = {
    **SEQUENCE_SEARCH_SPACE,
    "nhead": {
        "domain": lambda: int(__import__("random").choice([2, 4, 8])),
        "log_scale": False,
        "min": 1,
        "max": 16,
    },
    "activation": {
        "domain": lambda: __import__("random").choice(["relu", "gelu", "elu"]),
        "log_scale": False,
    },
}

# Sequence model AutoML metric to optimize
SEQUENCE_AUTOML_METRIC = "roc_auc"  # "precision", "recall", "f1", "roc_auc"

# ---------------------------------------------------------------------------
# FLAML configuration presets
# ---------------------------------------------------------------------------
FLAML_ESTIMATOR_SETTINGS = {
    # IForest tuning preset
    "iforest": {
        "time_budget": AUTOML_TIME_BUDGET_SECONDS,
        "metric": IFOREST_AUTOML_METRIC,
        "task": "classification",
        "seed": AUTOML_SEED,
        "verbose": AUTOML_VERBOSE_LEVEL,
        "n_jobs": -1,
    },
    # Autoencoder tuning preset (custom, not standard FLAML task)
    "autoencoder": {
        "time_budget": AUTOML_TIME_BUDGET_SECONDS,
        "metric": AUTOENCODER_AUTOML_METRIC,
        "task": "custom",
        "seed": AUTOML_SEED,
        "verbose": AUTOML_VERBOSE_LEVEL,
    },
    # Sequence model tuning preset (custom)
    "sequence": {
        "time_budget": AUTOML_TIME_BUDGET_SECONDS,
        "metric": SEQUENCE_AUTOML_METRIC,
        "task": "custom",
        "seed": AUTOML_SEED,
        "verbose": AUTOML_VERBOSE_LEVEL,
    },
}
