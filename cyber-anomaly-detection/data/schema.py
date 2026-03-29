"""
Canonical 20-field Sysmon schema shared across all dataset loaders.
All loaders produce a pandas DataFrame conforming to SYSMON_SCHEMA.
"""
import pandas as pd
from config import SYSMON_COLUMNS

# Dtypes applied after loading.  Fields absent in a source are filled with
# appropriate defaults (empty string or -1 for numeric).
DTYPE_MAP: dict[str, str] = {
    "event_id":   "int16",
    "process_id": "int32",
    "parent_id":  "int32",
    "dest_port":  "int32",
    "label":      "int8",
}

STRING_COLS = [c for c in SYSMON_COLUMNS if c not in DTYPE_MAP]


def empty_frame() -> pd.DataFrame:
    """Return an empty DataFrame with the canonical schema."""
    return pd.DataFrame(columns=SYSMON_COLUMNS)


def enforce_schema(df: pd.DataFrame) -> pd.DataFrame:
    """
    Add missing columns with defaults and cast dtypes.
    Does NOT reorder rows or drop extra columns.
    """
    for col in SYSMON_COLUMNS:
        if col not in df.columns:
            if col in DTYPE_MAP:
                df[col] = -1
            else:
                df[col] = ""

    for col, dtype in DTYPE_MAP.items():
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(-1).astype(dtype)

    for col in STRING_COLS:
        df[col] = df[col].fillna("").astype(str)

    return df[SYSMON_COLUMNS]
