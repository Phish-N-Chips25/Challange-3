"""
preprocessor.py
Pré-processamento de logs Sysmon/ETW:
  1. Parse de EVTX ou CSV
  2. Normalização de campos
  3. Windowing temporal (default 60s)
  4. Feature engineering por janela
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterator

import numpy as np
import pandas as pd
import typer

logger = logging.getLogger(__name__)

# Sysmon EventIDs relevantes para deteção de anomalias
RELEVANT_EVENT_IDS = {1, 3, 5, 6, 7, 8, 10, 11, 12, 13, 15, 16, 17, 18, 22, 23, 25}

# Processos considerados suspeitos (baseline)
SUSPICIOUS_PROCESSES = {
    "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "regsvr32.exe", "rundll32.exe", "msiexec.exe",
    "certutil.exe", "bitsadmin.exe", "net.exe", "net1.exe",
    "sc.exe", "schtasks.exe", "at.exe", "whoami.exe",
    "mimikatz.exe", "psexec.exe", "wmic.exe",
}

# Portas tipicamente associadas a lateral movement
LATERAL_MOVEMENT_PORTS = {445, 135, 139, 3389, 5985, 5986, 22}


@dataclass
class SysmonEvent:
    timestamp: datetime
    event_id: int
    process_name: str = ""
    process_id: int = 0
    parent_process: str = ""
    target_process: str = ""
    network_dest_ip: str = ""
    network_dest_port: int = 0
    file_path: str = ""
    registry_key: str = ""
    user: str = ""
    command_line: str = ""
    raw: dict = field(default_factory=dict)


@dataclass
class WindowFeatures:
    window_start: datetime
    window_end: datetime
    event_count: int = 0
    unique_event_ids: int = 0
    unique_processes: int = 0
    unique_users: int = 0
    process_creation_count: int = 0        # EventID 1
    network_connection_count: int = 0      # EventID 3
    file_creation_count: int = 0           # EventID 11
    registry_modification_count: int = 0   # EventID 13
    suspicious_process_count: int = 0
    lateral_movement_port_count: int = 0
    powershell_count: int = 0
    cmd_count: int = 0
    outbound_unique_ips: int = 0
    has_mimikatz: bool = False
    has_psexec: bool = False
    event_id_entropy: float = 0.0
    process_entropy: float = 0.0
    # Lista de eventos resumidos para o evidence pack do judge
    event_summaries: list = field(default_factory=list)

    def to_feature_vector(self) -> np.ndarray:
        """Converte para array numérico para ML."""
        return np.array([
            self.event_count,
            self.unique_event_ids,
            self.unique_processes,
            self.unique_users,
            self.process_creation_count,
            self.network_connection_count,
            self.file_creation_count,
            self.registry_modification_count,
            self.suspicious_process_count,
            self.lateral_movement_port_count,
            self.powershell_count,
            self.cmd_count,
            self.outbound_unique_ips,
            float(self.has_mimikatz),
            float(self.has_psexec),
            self.event_id_entropy,
            self.process_entropy,
        ], dtype=np.float32)

    def to_dict(self) -> dict:
        d = {k: v for k, v in self.__dict__.items() if k != "event_summaries"}
        d["window_start"] = self.window_start.isoformat()
        d["window_end"] = self.window_end.isoformat()
        d["event_summaries"] = self.event_summaries
        return d


def _entropy(series: pd.Series) -> float:
    """Entropy de Shannon normalizada."""
    counts = series.value_counts(normalize=True)
    if len(counts) <= 1:
        return 0.0
    return float(-np.sum(counts * np.log2(counts + 1e-9)))


def parse_csv(path: Path, dataset: str = "lmd") -> pd.DataFrame:
    """
    Lê CSV de logs Sysmon. Suporta formatos LMD-2023 e Splunk Attack Data.
    Normaliza para colunas canónicas.
    """
    df = pd.read_csv(path, low_memory=False, on_bad_lines="warn")
    df.columns = df.columns.str.lower().str.strip()

    # Mapeamentos de nomes de colunas por dataset.
    # For lmd, `utctime` is preferred but some exports have it truncated;
    # `systemtime` is the fallback full timestamp column.
    column_maps = {
        "lmd": {
            "utctime": "timestamp",
            "systemtime": "_systemtime_fallback",
            "eventid": "event_id",
            "image": "process_name",
            "processid": "process_id",
            "parentimage": "parent_process",
            "targetimage": "target_process",
            "destinationip": "network_dest_ip",
            "destinationport": "network_dest_port",
            "targetfilename": "file_path",
            "targetobject": "registry_key",
            "user": "user",
            "commandline": "command_line",
        },
        "splunk": {
            "systemtime": "timestamp",
            "eventid": "event_id",
            "image": "process_name",
            "processid": "process_id",
            "parentimage": "parent_process",
            "destinationip": "network_dest_ip",
            "destinationport": "network_dest_port",
            "targetfilename": "file_path",
            "targetobject": "registry_key",
            "user": "user",
            "commandline": "command_line",
        },
        "silrad": {
            "timestamp": "timestamp",
            "event_id": "event_id",
            "process_name": "process_name",
            "pid": "process_id",
            "parent_process_name": "parent_process",
            "dest_ip": "network_dest_ip",
            "dest_port": "network_dest_port",
            "target_filename": "file_path",
            "user_name": "user",
            "cmdline": "command_line",
        },
    }

    mapping = column_maps.get(dataset, column_maps["lmd"])
    df = df.rename(columns={k: v for k, v in mapping.items() if k in df.columns})

    # Garantir colunas mínimas
    for col in ["timestamp", "event_id", "process_name", "user"]:
        if col not in df.columns:
            df[col] = ""

    df["timestamp"] = pd.to_datetime(df["timestamp"], format="mixed", errors="coerce", utc=True)

    # If utctime was corrupt (all NaT), fall back to the systemtime column
    if df["timestamp"].isna().all() and "_systemtime_fallback" in df.columns:
        logger.warning("utctime column unusable; falling back to systemtime for timestamps")
        df["timestamp"] = pd.to_datetime(
            df["_systemtime_fallback"], format="mixed", errors="coerce", utc=True
        )

    # Drop the temporary fallback column if present
    df = df.drop(columns=["_systemtime_fallback"], errors="ignore")

    df = df.dropna(subset=["timestamp"]).sort_values("timestamp").reset_index(drop=True)
    df["event_id"] = pd.to_numeric(df["event_id"], errors="coerce").fillna(0).astype(int)

    # Normalizar nome do processo (basename) — vectorised str ops, no per-row Path()
    if "process_name" in df.columns:
        df["process_name"] = (
            df["process_name"].astype(str)
            .str.replace("\\\\", "/", regex=False)
            .str.split("/").str[-1]
            .str.lower()
        )

    # Filtrar apenas EventIDs relevantes
    df = df[df["event_id"].isin(RELEVANT_EVENT_IDS)]

    logger.info(f"Loaded {len(df)} events from {path.name} (dataset={dataset})")
    return df


def parse_evtx(path: Path) -> pd.DataFrame:
    """
    Parse direto de ficheiro EVTX usando python-evtx.
    Retorna o mesmo schema normalizado que parse_csv.
    """
    try:
        from evtx import PyEvtxParser  # type: ignore
    except ImportError:
        raise ImportError("Instala python-evtx: pip install python-evtx")

    rows = []
    with PyEvtxParser(str(path)) as parser:
        for record in parser.records_json():
            try:
                data = json.loads(record["data"])
                system = data.get("Event", {}).get("System", {})
                event_data = data.get("Event", {}).get("EventData", {})

                event_id = int(system.get("EventID", {}).get("#text", 0))
                if event_id not in RELEVANT_EVENT_IDS:
                    continue

                ts_str = system.get("TimeCreated", {}).get("@SystemTime", "")
                ts = pd.to_datetime(ts_str, errors="coerce", utc=True)

                # EventData pode ser dict ou lista de Data tags
                if isinstance(event_data, dict):
                    ed = {k.lower(): v for k, v in event_data.items()}
                else:
                    ed = {}

                rows.append({
                    "timestamp": ts,
                    "event_id": event_id,
                    "process_name": Path(ed.get("image", "")).name.lower(),
                    "process_id": int(ed.get("processid", 0) or 0),
                    "parent_process": Path(ed.get("parentimage", "")).name.lower(),
                    "target_process": Path(ed.get("targetimage", "")).name.lower(),
                    "network_dest_ip": ed.get("destinationip", ""),
                    "network_dest_port": int(ed.get("destinationport", 0) or 0),
                    "file_path": ed.get("targetfilename", ""),
                    "registry_key": ed.get("targetobject", ""),
                    "user": ed.get("user", ""),
                    "command_line": ed.get("commandline", ""),
                })
            except Exception as e:
                logger.debug(f"Skipping record: {e}")
                continue

    df = pd.DataFrame(rows)
    if df.empty:
        return df
    df = df.dropna(subset=["timestamp"]).sort_values("timestamp").reset_index(drop=True)
    logger.info(f"Parsed {len(df)} events from EVTX {path.name}")
    return df


def make_windows(
    df: pd.DataFrame,
    window_size_seconds: int = 60,
    max_events: int = 200,
) -> Iterator[WindowFeatures]:
    """
    Agrupa eventos em janelas temporais fixas e extrai features por janela.
    Janelas com 0 eventos são ignoradas.
    """
    if df.empty:
        return

    start = df["timestamp"].iloc[0].floor("min")
    end = df["timestamp"].iloc[-1]
    delta = timedelta(seconds=window_size_seconds)

    current = start
    while current < end:
        w_end = current + delta
        mask = (df["timestamp"] >= current) & (df["timestamp"] < w_end)
        chunk = df[mask]

        if chunk.empty:
            current = w_end
            continue

        # Limitar eventos por janela para não explodir o context do judge
        chunk = chunk.head(max_events)

        wf = WindowFeatures(window_start=current, window_end=w_end)
        wf.event_count = len(chunk)
        wf.unique_event_ids = chunk["event_id"].nunique()
        wf.unique_processes = chunk["process_name"].nunique()
        wf.unique_users = chunk["user"].nunique() if "user" in chunk else 0

        wf.process_creation_count = (chunk["event_id"] == 1).sum()
        wf.network_connection_count = (chunk["event_id"] == 3).sum()
        wf.file_creation_count = (chunk["event_id"] == 11).sum()
        wf.registry_modification_count = (chunk["event_id"] == 13).sum()

        if "process_name" in chunk.columns:
            proc_lower = chunk["process_name"].str.lower()
            wf.suspicious_process_count = proc_lower.isin(SUSPICIOUS_PROCESSES).sum()
            wf.powershell_count = (proc_lower == "powershell.exe").sum()
            wf.cmd_count = (proc_lower == "cmd.exe").sum()
            wf.has_mimikatz = proc_lower.str.contains("mimikatz", na=False).any()
            wf.has_psexec = proc_lower.str.contains("psexec", na=False).any()
            wf.process_entropy = _entropy(proc_lower)

        if "network_dest_port" in chunk.columns:
            ports = pd.to_numeric(chunk["network_dest_port"], errors="coerce").dropna()
            wf.lateral_movement_port_count = int(ports.isin(LATERAL_MOVEMENT_PORTS).sum())

        if "network_dest_ip" in chunk.columns:
            ips = chunk["network_dest_ip"].dropna()
            wf.outbound_unique_ips = ips[ips != ""].nunique()

        wf.event_id_entropy = _entropy(chunk["event_id"].astype(str))

        # Criar resumo textual dos eventos para o evidence pack
        # itertuples is ~10x faster than iterrows for simple field access
        summaries = []
        ip_col = "network_dest_ip" in chunk.columns
        port_col = "network_dest_port" in chunk.columns
        file_col = "file_path" in chunk.columns
        cmd_col = "command_line" in chunk.columns
        for row in chunk.itertuples(index=False):
            parts = [f"EID={row.event_id}"]
            pname = getattr(row, 'process_name', '')
            if pname:
                parts.append(f"proc={pname}")
            if ip_col:
                ip = getattr(row, 'network_dest_ip', '')
                if ip:
                    parts.append(f"dst={ip}:{getattr(row, 'network_dest_port', '?')}")
            if file_col:
                fp = getattr(row, 'file_path', '')
                if fp:
                    parts.append(f"file={fp}")
            if cmd_col:
                cmd = str(getattr(row, 'command_line', ''))
                if cmd and cmd != 'nan':
                    parts.append(f"cmd={cmd[:120]}")
            summaries.append(" | ".join(parts))
        wf.event_summaries = summaries[:50]  # máximo 50 linhas no evidence pack

        yield wf
        current = w_end


# CLI
app = typer.Typer()

@app.command()
def main(
    input: Path = typer.Option(..., help="CSV ou EVTX de input"),
    output: Path = typer.Option(Path("results/windows.json"), help="JSON de output"),
    dataset: str = typer.Option("lmd", help="Formato: lmd, splunk, silrad"),
    window_size: int = typer.Option(60, help="Tamanho da janela em segundos"),
    max_events: int = typer.Option(200, help="Max eventos por janela"),
):
    logging.basicConfig(level=logging.INFO)

    if input.suffix.lower() == ".evtx":
        df = parse_evtx(input)
    else:
        df = parse_csv(input, dataset=dataset)

    windows = list(make_windows(df, window_size_seconds=window_size, max_events=max_events))
    logger.info(f"Created {len(windows)} windows")

    output.parent.mkdir(parents=True, exist_ok=True)
    with open(output, "w") as f:
        json.dump([w.to_dict() for w in windows], f, indent=2, default=str)

    logger.info(f"Saved windows to {output}")


if __name__ == "__main__":
    app()
