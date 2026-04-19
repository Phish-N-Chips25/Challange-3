"""utils.py — helpers partilhados"""

import json
import logging
import re
from pathlib import Path
from typing import Any

import numpy as np


# ── Prompt-injection defence ─────────────────────────────────────────────
# Log records can carry attacker-controlled strings (cmdlines, file paths,
# registry values). Without sanitisation those strings end up verbatim inside
# the SLM/Judge prompt and can hijack the model.

# Chat-template / role markers used by Phi / Llama / GPT family models.
_ROLE_MARKER_RE = re.compile(
    r"<\|(?:im_start|im_end|start_header_id|end_header_id|eot_id|begin_of_text|end_of_text|fim_prefix|fim_middle|fim_suffix|system|user|assistant)\|>",
    re.IGNORECASE,
)
# Common natural-language injection openers (kept conservative to avoid
# false positives in benign logs).
_INJECT_OPENERS_RE = re.compile(
    r"(?i)\b(?:ignore (?:all|the|previous|above) (?:prior |earlier )?(?:instructions?|prompts?|rules?)"
    r"|disregard (?:all|the|previous|above) (?:instructions?|prompts?|rules?)"
    r"|forget (?:all|the|previous|above) (?:instructions?|prompts?)"
    r"|you are now (?:a |an |the )?"
    r"|new instructions?:"
    r"|system prompt:"
    r"|jailbreak"
    r"|do anything now"
    r"|DAN mode)\b",
)
# Markdown fences and zero-width chars that can break out of code blocks
# or hide content from a human reviewer.
_FENCE_RE = re.compile(r"`{3,}")
_ZERO_WIDTH_RE = re.compile(r"[\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF]")


def sanitize_for_prompt(text: Any, max_len: int = 240) -> str:
    """Make an attacker-controlled string safe to embed inside an LLM prompt.

    - Trims to `max_len` chars
    - Strips ASCII control chars (except space/tab) and bidi/zero-width chars
    - Neutralises chat-template role markers (`<|im_start|>`, `<|system|>`, ...)
    - Replaces backtick fences with single quotes (no code-block escape)
    - Marks classic instruction-injection openers with `[!INJ]` so the LLM
      can see they were neutralised by the pipeline, not silently dropped
    """
    if text is None:
        return ""
    s = str(text)
    s = s.replace("\r\n", "\n").replace("\r", "\n")
    s = _ZERO_WIDTH_RE.sub("", s)
    s = "".join(ch for ch in s if ch == "\n" or ch == "\t" or ch >= " ")
    s = _ROLE_MARKER_RE.sub("[role-marker-stripped]", s)
    s = _FENCE_RE.sub("'''", s)
    s = _INJECT_OPENERS_RE.sub(lambda m: f"[!INJ:{m.group(0)[:40]}]", s)
    if len(s) > max_len:
        s = s[: max_len - 1] + "…"
    return s


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


# ── Robust JSON extraction from LLM output ───────────────────────────────
# Local SLMs (Phi-3, Llama-3.1) frequently produce *almost* valid JSON:
# truncated strings, stray prose, single quotes, bad \uXXXX escapes, or
# trailing commas. This extractor tries progressively more aggressive
# repairs before giving up.

_BAD_BACKSLASH_RE = re.compile(r'\\(?!["\\/bfnrt]|u[0-9a-fA-F]{4})')
_TRAILING_COMMA_RE = re.compile(r",(\s*[}\]])")


def _repair_json(s: str) -> str:
    """Best-effort cleanup of common LLM JSON defects."""
    # Escape every backslash that isn't part of a valid JSON escape sequence
    # (covers `C:\users\admin`, `\a`, `\u` not followed by 4 hex digits, ...)
    s = _BAD_BACKSLASH_RE.sub(r"\\\\", s)
    # Remove trailing commas before } or ]
    s = _TRAILING_COMMA_RE.sub(r"\1", s)
    # Convert smart-quotes to ASCII
    s = (s.replace("\u201c", '"').replace("\u201d", '"')
           .replace("\u2018", "'").replace("\u2019", "'"))
    # Close an unterminated string (odd number of unescaped " ⇒ append ")
    unescaped_quotes = len(re.findall(r'(?<!\\)"', s))
    if unescaped_quotes % 2 == 1:
        s = s + '"'
    # Close unbalanced braces/brackets (happens when num_predict truncates)
    open_a = s.count("[") - s.count("]")
    if open_a > 0:
        s = s + ("]" * open_a)
    open_b = s.count("{") - s.count("}")
    if open_b > 0:
        s = s + ("}" * open_b)
    return s


def extract_json(raw: str) -> dict:
    """Tolerant JSON parser for LLM responses. Raises json.JSONDecodeError
    only when nothing salvageable can be found."""
    if not raw or not raw.strip():
        raise json.JSONDecodeError("Empty response", raw or "", 0)
    raw = raw.strip()

    # 1. Direct parse
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass

    # 2. Strip markdown fences ```json ... ``` or ``` ... ```
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw, re.DOTALL)
    if fence:
        try:
            return json.loads(fence.group(1))
        except json.JSONDecodeError:
            try:
                return json.loads(_repair_json(fence.group(1)))
            except json.JSONDecodeError:
                pass

    # 3. Locate first balanced {...} block (greedy fallback)
    brace = re.search(r"\{.*\}", raw, re.DOTALL)
    if brace:
        candidate = brace.group(0)
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            try:
                return json.loads(_repair_json(candidate))
            except json.JSONDecodeError:
                pass

    # 4. Last-ditch: take from first `{` to end and repair (handles truncation)
    first = raw.find("{")
    if first >= 0:
        try:
            return json.loads(_repair_json(raw[first:]))
        except json.JSONDecodeError:
            pass

    raise json.JSONDecodeError("No salvageable JSON object in response", raw, 0)


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

    # ── Smart features (semantic signals derived from cmdline / registry / paths /
    # ports / process tree). Only render groups where at least one value is
    # non-zero — keeps the prompt focused on actual signal.
    smart = window.get("smart_features", {}) or {}
    if smart:
        groups = {
            "cmdline": [
                ("avg_len",            "cmdline_avg_len",            ".0f"),
                ("max_len",            "cmdline_max_len",            "d"),
                ("avg_token_entropy",  "cmdline_avg_token_entropy",  ".2f"),
                ("obfuscation_hits",   "cmdline_obfuscation_hits",   "d"),
                ("base64_blob_count",  "cmdline_b64_blob_count",     "d"),
                ("flag_density",       "cmdline_flag_density",       ".2f"),
                ("lolbin_calls",       "cmdline_lolbin_calls",       "d"),
            ],
            "registry": [
                ("hklm_ratio",         "reg_hive_hklm_ratio",        ".2f"),
                ("hkcu_ratio",         "reg_hive_hkcu_ratio",        ".2f"),
                ("avg_depth",          "reg_avg_depth",              ".1f"),
                ("suspicious_path_hits", "reg_suspicious_path_hits", "d"),
                ("unique_subtrees",    "reg_unique_subtrees",        "d"),
            ],
            "paths": [
                ("avg_depth",          "path_avg_depth",             ".1f"),
                ("temp_ratio",         "path_temp_ratio",            ".2f"),
                ("appdata_ratio",      "path_appdata_ratio",         ".2f"),
                ("system32_ratio",     "path_system32_ratio",        ".2f"),
                ("unique_extensions",  "path_unique_extensions",     "d"),
                ("executable_writes",  "path_executable_writes",     "d"),
            ],
            "ports": [
                ("lateral_ratio",      "port_lateral_ratio",         ".2f"),
                ("dynamic_ratio",      "port_dynamic_ratio",         ".2f"),
                ("rare_high_count",    "port_rare_high_count",       "d"),
                ("category_entropy",   "port_category_entropy",      ".2f"),
            ],
            "process_tree": [
                ("unique_pairs",       "proctree_unique_pairs",      "d"),
                ("pair_entropy",       "proctree_pair_entropy",      ".2f"),
                ("suspicious_pairs",   "proctree_suspicious_pairs",  "d"),
            ],
        }
        emitted = []
        for group_name, fields in groups.items():
            parts = []
            for label, key, fmt in fields:
                v = smart.get(key, 0)
                # Skip zero / empty values to keep prompt compact
                if not v:
                    continue
                if fmt == "d":
                    parts.append(f"{label}={int(v)}")
                else:
                    parts.append(f"{label}={float(v):{fmt}}")
            if parts:
                emitted.append(f"  [{group_name}] " + ", ".join(parts))
        if emitted:
            lines += ["", "--- Smart features (semantic signals) ---", *emitted]

    # ── Baseline deviation: how much does this window depart from the bulk?
    # Computed by BenignBaseline (centroid + per-field token frequency).
    baseline = window.get("baseline_features", {}) or {}
    if baseline:
        dist = baseline.get("emb_distance_to_baseline", 0.0)
        rare_parts = []
        for label, key in (
            ("cmdline",  "cmdline_rare_token_ratio"),
            ("registry", "registry_rare_token_ratio"),
            ("process",  "process_rare_token_ratio"),
            ("path",     "path_rare_token_ratio"),
        ):
            v = baseline.get(key, 0.0)
            if v > 0:
                rare_parts.append(f"{label}={float(v):.2f}")
        if dist > 0 or rare_parts:
            lines += ["", "--- Baseline deviation (vs bulk-of-windows) ---"]
            lines.append(f"  embedding_distance={float(dist):.3f}")
            if rare_parts:
                lines.append("  rare_token_ratio: " + ", ".join(rare_parts))

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
                ev = sanitize_for_prompt(h.get("evidence", ""), max_len=160)
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
            safe = sanitize_for_prompt(s, max_len=140)
            lines.append(f"    [{i:02d}] {safe}")

    summaries = window.get("event_summaries", [])
    if summaries:
        # Cap sample lines based on window activity: low-event windows need fewer examples
        event_count = window.get("event_count", 0)
        max_samples = 15 if event_count < 20 else 30 if event_count < 60 else 50
        lines += ["", f"--- Individual event samples (max {max_samples}) ---"]
        for i, s in enumerate(summaries[:max_samples], 1):
            # Truncate to 120 chars to prevent prompt injection via log content
            safe = sanitize_for_prompt(s, max_len=120)
            lines.append(f"  [{i:02d}] {safe}")

    result = "\n".join(lines)
    window["_evidence_pack"] = result  # cache to avoid rebuilding for Judge after SLM
    return result
