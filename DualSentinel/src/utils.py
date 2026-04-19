"""utils.py — helpers partilhados"""

import json
import logging
from pathlib import Path
from typing import Any

import numpy as np


def setup_logging(level: str = "INFO") -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def save_json(obj: Any, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(obj, f, indent=2, default=_json_default)


def _json_default(o: Any) -> Any:
    if isinstance(o, np.integer):
        return int(o)
    if isinstance(o, np.floating):
        return float(o)
    if isinstance(o, np.ndarray):
        return o.tolist()
    raise TypeError(f"Object of type {type(o)} is not JSON serializable")


def load_json(path: Path) -> Any:
    with open(path) as f:
        return json.load(f)


def precision_recall_f1(tp: int, fp: int, fn: int) -> dict:
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    return {"precision": precision, "recall": recall, "f1": f1}


# ─────────────────────────────────────────────
# Evidence Pack builder (shared by SLM + LLM)
# ─────────────────────────────────────────────

def build_evidence_pack(window: dict) -> str:
    """
    Constrói texto estruturado com os factos da janela.
    Contém apenas o que existe nos dados — sem inferências.
    Command lines são truncadas a 120 chars para evitar prompt injection.
    The result is cached on the window dict under '_evidence_pack' to avoid
    rebuilding when both SLM and Judge process the same window.
    """
    if "_evidence_pack" in window:
        return window["_evidence_pack"]
    lines = [
        "=== EVIDENCE PACK ===",
        f"Window: {window.get('window_start')} → {window.get('window_end')}",
        f"Total events: {window.get('event_count', 0)}",
        "",
        "--- Aggregate stats ---",
        f"Unique EventIDs: {window.get('unique_event_ids', 0)}",
        f"Unique processes: {window.get('unique_processes', 0)}",
        f"Unique users: {window.get('unique_users', 0)}",
        f"Process creations (EID 1): {window.get('process_creation_count', 0)}",
        f"Network connections (EID 3): {window.get('network_connection_count', 0)}",
        f"File creations (EID 11): {window.get('file_creation_count', 0)}",
        f"Registry modifications (EID 13): {window.get('registry_modification_count', 0)}",
        f"Suspicious processes detected: {window.get('suspicious_process_count', 0)}",
        f"Lateral movement ports seen: {window.get('lateral_movement_port_count', 0)}",
        f"PowerShell executions: {window.get('powershell_count', 0)}",
        f"CMD executions: {window.get('cmd_count', 0)}",
        f"Outbound unique IPs: {window.get('outbound_unique_ips', 0)}",
        f"Mimikatz present: {window.get('has_mimikatz', False)}",
        f"PsExec present: {window.get('has_psexec', False)}",
        f"EventID entropy: {window.get('event_id_entropy', 0.0):.3f}",
        f"Process entropy: {window.get('process_entropy', 0.0):.3f}",
    ]

    attck_hits = window.get("attck_hits", [])
    if attck_hits:
        rule_hits = [h for h in attck_hits if h.get("source", "rule") == "rule"]
        kb_hits = [h for h in attck_hits if h.get("source") == "kb"]
        if rule_hits:
            lines += ["", "--- Rule tagger hits (pre-computed) ---"]
            for h in rule_hits:
                lines.append(
                    f"  {h['technique']} {h['name']} (confidence={h['confidence']:.2f})"
                )
        if kb_hits:
            lines += ["", "--- ATT&CK KB candidates (retrieved, not confirmed) ---"]
            for h in kb_hits:
                ev = str(h.get("evidence", ""))[:160].replace("```", "'''")
                lines.append(
                    f"  {h['technique']} {h['name']} (similarity={h['confidence']:.2f}) :: {ev}"
                )

    peak = window.get("peak_chain")
    if peak and peak.get("event_summaries"):
        lines += [
            "",
            "--- Peak process chain (longest overlap) ---",
            f"  process: {peak.get('process_name','?')} (guid={peak.get('process_guid','')[:12]}...)",
            f"  parent:  {peak.get('parent_process','?')}",
            f"  user:    {peak.get('user','?')}  host: {peak.get('host','?')}",
            f"  length:  {peak.get('length',0)} events  duration: {peak.get('duration_seconds',0):.1f}s  children: {peak.get('child_count',0)}",
            "  ordered events:",
        ]
        for i, s in enumerate(peak.get("event_summaries", [])[:25], 1):
            safe = str(s)[:140].replace("```", "'''")
            lines.append(f"    [{i:02d}] {safe}")

    summaries = window.get("event_summaries", [])
    if summaries:
        # Cap sample lines based on window activity: low-event windows need fewer examples
        event_count = window.get("event_count", 0)
        max_samples = 15 if event_count < 20 else 30 if event_count < 60 else 50
        lines += ["", f"--- Individual event samples (max {max_samples}) ---"]
        for i, s in enumerate(summaries[:max_samples], 1):
            # Truncate to 120 chars to prevent prompt injection via log content
            safe = str(s)[:120].replace("```", "'''")
            lines.append(f"  [{i:02d}] {safe}")

    result = "\n".join(lines)
    window["_evidence_pack"] = result  # cache to avoid rebuilding for Judge after SLM
    return result
