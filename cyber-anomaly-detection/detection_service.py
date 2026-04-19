"""
detection_service.py — Stateless detection + attribution API for the Flask dashboard.

Mirrors the logic of demo_app.py but with no Streamlit dependency.
All heavy resources are loaded once and cached as module-level singletons.

Public API
----------
get_flagged_chains(source_name, limit)     → list[dict]
score_chain_events(chain_indices)          → list[dict]
attribute_chain(chain_indices, model, url) → dict
check_ollama(base_url, model)              → tuple[bool, list[str]]
SOURCE_NAMES                               → list[str]
"""

from __future__ import annotations

import json
import pickle
import re
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd
import requests
import torch
import torch.nn as nn

# ── Make project-relative imports available ───────────────────────────────────
_HERE = Path(__file__).parent
sys.path.insert(0, str(_HERE))

# ── Paths (matching demo_app.py exactly) ─────────────────────────────────────
CKPT_DIR       = _HERE / "notebooks" / "checkpoints"
AE_DIR         = CKPT_DIR / "models" / "autoencoder"
SEQ_MODEL_DIR  = CKPT_DIR / "models" / "seq"
SEQ_CHAINS_DIR = CKPT_DIR / "seq"

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

# ── Pipeline constants (must match notebook 07 / demo_app.py) ─────────────────
SEQ_THRESHOLD = 0.627528
SEQ_W         = 45
SEQ_STRIDE    = 45
RAG_K         = 15

SOURCE_NAMES = ["OTRF Atomic Red Team", "Splunk Attack Range"]

SOURCE_BOUNDS: dict[str, tuple[int, int]] = {
    "OTRF Atomic Red Team": (511_105,   1_054_182),
    "Splunk Attack Range":  (1_382_201, 3_447_667),
}

EID_NAMES: dict[int, str] = {
    1:  "Process Create",       3:  "Network Connection",
    5:  "Process Terminate",    7:  "Image Load",
    8:  "CreateRemoteThread",   10: "Process Access",
    11: "File Create",          12: "Registry Object Create/Delete",
    13: "Registry Value Set",   15: "File Create Stream",
    17: "Pipe Created",         18: "Pipe Connected",
    22: "DNS Query",            23: "File Delete",
    25: "Process Tampering",    26: "File Delete Detected",
}

_SKIP = {"", "-1", "nan", "None", "0", "-", "N/A", "n/a"}

ATTRIBUTION_PROMPT = (
    "You are a cybersecurity analyst reviewing Windows Sysmon events flagged as anomalous.\n\n"
    "## Events in Flagged Chain Window\n"
    "{event_text}\n\n"
    "## Candidate ATT&CK Techniques\n"
    "{candidates_text}\n\n"
    "## Task\n"
    "Work through these steps before giving your final answer:\n\n"
    "**Step 1** - What specific suspicious behaviors do these events show?\n"
    "Focus on: process names, registry paths, command lines, network destinations, EID types.\n\n"
    "**Step 2** - Which candidate technique from the list above best matches these behaviors,\n"
    "and why does it fit better than the other candidates?\n\n"
    "**Step 3** - Return your final answer as valid JSON (no markdown fences).\n"
    "Fields: technique_id, technique_name, confidence (high/medium/low), "
    "explanation, recommended_action.\n\n"
)


# ═══════════════════════════════════════════════════════════════════════════════
# Model definitions (identical to demo_app.py / notebook 10)
# ═══════════════════════════════════════════════════════════════════════════════

class Autoencoder(nn.Module):
    _ACT = {
        "relu":       nn.ReLU,
        "gelu":       nn.GELU,
        "leaky_relu": lambda: nn.LeakyReLU(0.1),
        "selu":       nn.SELU,
        "elu":        nn.ELU,
    }

    def __init__(self, input_dim, layer_sizes, latent_dim,
                 activation="relu", use_batchnorm=True, dropout=0.1):
        super().__init__()
        act_fn = self._ACT[activation]

        def _block(in_d, out_d, final=False):
            layers: list = [nn.Linear(in_d, out_d)]
            if use_batchnorm and not final:
                layers.append(nn.BatchNorm1d(out_d))
            if not final:
                layers.append(act_fn())
                if dropout > 0:
                    layers.append(nn.Dropout(dropout))
            return layers

        enc_dims = [input_dim] + list(layer_sizes) + [latent_dim]
        enc: list = []
        for i in range(len(enc_dims) - 1):
            enc.extend(_block(enc_dims[i], enc_dims[i + 1], final=(i == len(enc_dims) - 2)))
        enc.append(act_fn())
        self.encoder = nn.Sequential(*enc)

        dec_dims = [latent_dim] + list(reversed(layer_sizes)) + [input_dim]
        dec: list = []
        for i in range(len(dec_dims) - 1):
            dec.extend(_block(dec_dims[i], dec_dims[i + 1], final=(i == len(dec_dims) - 2)))
        self.decoder = nn.Sequential(*dec)

    def forward(self, x):
        return self.decoder(self.encoder(x))


class TransformerAE(nn.Module):
    def __init__(self, input_dim, hidden_dim, latent_dim, n_layers, nhead, dropout):
        super().__init__()
        if hidden_dim % nhead != 0:
            hidden_dim = max(nhead, (hidden_dim // nhead) * nhead)
        self.input_proj  = nn.Linear(input_dim, hidden_dim)
        enc_layer = nn.TransformerEncoderLayer(
            d_model=hidden_dim, nhead=nhead, dim_feedforward=hidden_dim * 2,
            dropout=dropout, batch_first=True,
        )
        self.transformer = nn.TransformerEncoder(enc_layer, num_layers=n_layers)
        self.latent_fc   = nn.Linear(hidden_dim, latent_dim)
        self.decode_fc   = nn.Linear(latent_dim, hidden_dim)
        self.output_proj = nn.Linear(hidden_dim, input_dim)

    def forward(self, x):
        h = self.transformer(self.input_proj(x))
        z = self.latent_fc(h.mean(dim=1))
        d = self.decode_fc(z).unsqueeze(1).expand(-1, x.size(1), -1)
        return self.output_proj(d)


# ═══════════════════════════════════════════════════════════════════════════════
# Module-level singletons (loaded once on first use)
# ═══════════════════════════════════════════════════════════════════════════════

_ae_model:  Optional[Autoencoder]   = None
_seq_model: Optional[TransformerAE] = None
_seq_params: Optional[dict]         = None
_events_m:  Optional[pd.DataFrame]  = None
_X_m_ae:    Optional[np.ndarray]    = None
_X_m_seq:   Optional[np.ndarray]    = None
_chains_m:  Optional[list]          = None
_kb_entries: Optional[list]         = None
_retrieve_fn = None

# Per-source flagged chain cache (populated lazily)
_flagged_cache: dict[str, list[dict]] = {}


def _load_models() -> None:
    global _ae_model, _seq_model, _seq_params
    if _ae_model is not None:
        return

    ae_cfg = json.loads((AE_DIR / "ae_best.json").read_text())["word2vec"]
    layer_sizes = sorted(
        [max(16, int(353 * ae_cfg[f"ratio_{i}"])) for i in range(ae_cfg["n_layers"])],
        reverse=True,
    )
    latent_dim = max(8, int(353 * ae_cfg["latent_ratio"]))
    ae = Autoencoder(353, layer_sizes, latent_dim,
                     ae_cfg["activation"], ae_cfg["use_batchnorm"],
                     ae_cfg["dropout"]).to(DEVICE)
    ae_ckpt = torch.load(AE_DIR / "word2vec" / "best.pt", map_location=DEVICE, weights_only=True)
    ae.load_state_dict(ae_ckpt["model_state"])
    ae.eval()
    _ae_model = ae

    seq_raw    = json.loads((SEQ_MODEL_DIR / "best_params.json").read_text())
    seq_p      = seq_raw.get("params", seq_raw)
    seq = TransformerAE(
        352, seq_p["hidden_dim"], seq_p["latent_dim"],
        seq_p["n_layers"], seq_p.get("nhead", 4), seq_p["dropout"],
    ).to(DEVICE)
    seq_state = torch.load(
        SEQ_MODEL_DIR / f"seq_ae_{seq_p['strategy']}.pt",
        map_location=DEVICE, weights_only=True,
    )
    seq.load_state_dict(seq_state)
    seq.eval()
    _seq_model  = seq
    _seq_params = seq_p


def _load_data() -> None:
    global _events_m, _X_m_ae, _X_m_seq, _chains_m
    if _events_m is not None:
        return
    _events_m = pd.read_parquet(CKPT_DIR / "events_m.parquet")
    _X_m_ae   = np.load(CKPT_DIR / "word2vec" / "X_m_w2v.npy",        mmap_mode="r")
    _X_m_seq  = np.load(CKPT_DIR / "word2vec" / "X_m_w2v_norule.npy", mmap_mode="r")
    with open(SEQ_CHAINS_DIR / "seq_chains_m.pkl", "rb") as f:
        _chains_m = pickle.load(f)


def _load_kb() -> None:
    global _kb_entries, _retrieve_fn
    if _kb_entries is not None:
        return
    from data.attack_kb.builder import build_kb
    from data.attack_kb.vector_store import retrieve_hybrid
    _kb_entries  = build_kb(force=False)
    _retrieve_fn = retrieve_hybrid


def load_all() -> None:
    """Pre-warm all resources. Call once at Flask startup."""
    _load_models()
    _load_data()
    _load_kb()


# ═══════════════════════════════════════════════════════════════════════════════
# Internal pipeline helpers (ported 1-to-1 from demo_app.py)
# ═══════════════════════════════════════════════════════════════════════════════

def _flag_chains(model, chains, X, batch_size: int = 512) -> list[dict]:
    model.eval()
    buf, chain_info, all_results = [], [], []

    for ci, chain in enumerate(chains):
        if len(chain) < SEQ_W:
            continue
        for start in range(0, len(chain) - SEQ_W + 1, SEQ_STRIDE):
            buf.append(np.array(X[list(chain[start: start + SEQ_W])], dtype=np.float32))
            chain_info.append((ci, start))
            if len(buf) >= batch_size:
                x = torch.from_numpy(np.stack(buf)).to(DEVICE)
                with torch.no_grad():
                    rec = model(x)
                scores = ((x - rec) ** 2).mean(dim=(1, 2)).cpu().numpy()
                for (ci2, st), sc in zip(chain_info, scores):
                    all_results.append((ci2, st, float(sc)))
                buf, chain_info = [], []

    if buf:
        x = torch.from_numpy(np.stack(buf)).to(DEVICE)
        with torch.no_grad():
            rec = model(x)
        scores = ((x - rec) ** 2).mean(dim=(1, 2)).cpu().numpy()
        for (ci2, st), sc in zip(chain_info, scores):
            all_results.append((ci2, st, float(sc)))

    best: dict = {}
    for ci, start, sc in all_results:
        if ci not in best or sc > best[ci][1]:
            best[ci] = (start, sc)

    return [
        {"chain": chains[ci], "peak_score": sc, "peak_start": start}
        for ci, (start, sc) in best.items()
        if sc >= SEQ_THRESHOLD
    ]


@torch.no_grad()
def _score_events_ae(rows: list[int], X, batch_size: int = 1024) -> np.ndarray:
    _ae_model.eval()
    out = []
    for s in range(0, len(rows), batch_size):
        batch = rows[s: s + batch_size]
        x = torch.from_numpy(np.array(X[batch], dtype=np.float32)).to(DEVICE)
        rec = _ae_model(x)
        out.append(((x - rec) ** 2).mean(dim=1).cpu().numpy())
    return np.concatenate(out) if out else np.array([])


def _get_chain_gt(chain) -> str:
    rows  = list(chain)
    techs = [
        str(_events_m.iloc[r].get("attck_technique", "")).strip()
        for r in rows if r < len(_events_m)
    ]
    techs = [t for t in techs if t and t not in _SKIP]
    return Counter(techs).most_common(1)[0][0] if techs else ""


def _format_events_for_slm(rows: list[int]) -> str:
    lines = []
    for i, r in enumerate(rows):
        ev        = _events_m.iloc[r]
        eid       = ev.get("event_id", "")
        eid_label = EID_NAMES.get(int(eid), "") if str(eid).isdigit() else ""
        parts = [f"Event {i+1}: EID={eid}" + (f" ({eid_label})" if eid_label else "")]
        for field in [
            "image", "command_line", "parent_image", "parent_cmdline",
            "image_loaded", "target_object", "details", "granted_access",
            "target_image", "dest_ip", "dest_hostname", "target_filename", "query_name",
        ]:
            val = str(ev.get(field, "")).strip()
            if val and val not in _SKIP:
                parts.append(f"  {field}: {val}")
        lines.append("\n".join(parts))
    return "\n---\n".join(lines)


def _build_retrieval_query(rows: list[int]) -> str:
    eid_counts: Counter = Counter()
    images, targets, cmdlines, dest_ips, dns = [], [], [], [], []

    for r in rows:
        ev  = _events_m.iloc[r]
        eid = ev.get("event_id", "")
        if str(eid).isdigit():
            eid_counts[int(eid)] += 1
        for lst, field in [
            (images,   "image"),
            (targets,  "target_object"), (targets, "target_image"), (targets, "target_filename"),
            (cmdlines, "command_line"),
            (dest_ips, "dest_ip"),
            (dns,      "query_name"),
        ]:
            val = str(ev.get(field, "")).strip()
            if val and val not in _SKIP:
                lst.append(val)

    eid_summary = ", ".join(
        f"{EID_NAMES.get(e, f'EID={e}')} x{c}"
        for e, c in sorted(eid_counts.items(), key=lambda x: -x[1])
    )
    parts = [f"Suspicious Windows Sysmon activity — event types: {eid_summary}."]

    def _top_unique(lst, n=4):
        seen, out = set(), []
        for v in lst:
            key = v.split("\\")[-1].lower()
            if key not in seen:
                seen.add(key); out.append(v)
            if len(out) >= n:
                break
        return out

    if images:   parts.append("Key processes: "        + ", ".join(_top_unique(images)))
    if cmdlines: parts.append("Command lines: "        + "; ".join(_top_unique(cmdlines, 2)))
    if targets:  parts.append("Targets: "              + ", ".join(_top_unique(targets)))
    if dest_ips: parts.append("Network destinations: " + ", ".join(set(dest_ips)))
    if dns:      parts.append("DNS queries: "          + ", ".join(set(dns)))
    return " ".join(parts)


def _multi_queries(rows: list[int], max_q: int = 3) -> list[str]:
    eid_groups: dict = defaultdict(list)
    for r in rows:
        eid = _events_m.iloc[r].get("event_id", "")
        if str(eid).isdigit():
            eid_groups[int(eid)].append(r)
    top_eids = sorted(eid_groups, key=lambda e: -len(eid_groups[e]))[:max_q]
    queries  = [_build_retrieval_query(eid_groups[e]) for e in top_eids]
    queries.append(_build_retrieval_query(rows))
    return list(dict.fromkeys(queries))


def _retrieve_multi_query(rows: list[int], k: int = RAG_K) -> list[dict]:
    best_hit: dict  = {}
    best_rank: dict = {}
    for query in _multi_queries(rows):
        for rank, hit in enumerate(_retrieve_fn(query, k=k)):
            tid = hit["technique_id"]
            if tid not in best_rank or rank < best_rank[tid]:
                best_rank[tid] = rank
                best_hit[tid]  = hit
    return sorted(best_hit.values(), key=lambda h: best_rank[h["technique_id"]])[: k * 2]


def _parse_json_response(text: str) -> dict:
    import ast as _ast
    clean      = re.sub(r"```(?:json)?\s*|```", "", text).strip()
    last_open  = clean.rfind("{")
    last_close = clean.rfind("}")
    if last_open != -1 and last_close > last_open:
        blob = clean[last_open: last_close + 1]
        try:
            return json.loads(blob)
        except json.JSONDecodeError:
            try:
                r = _ast.literal_eval(blob)
                if isinstance(r, dict):
                    return {str(k): v for k, v in r.items()}
            except Exception:
                pass
    result: dict = {}
    fragment = clean[last_open:] if last_open != -1 else clean
    for key in ("technique_id", "technique_name", "confidence", "explanation"):
        m = re.search('"' + key + r'"\s*:\s*"([^"]+)"', fragment)
        if m:
            result[key] = m.group(1)
    if "technique_id" in result:
        return result
    raise ValueError(f"No JSON found in LLM response: {text[:300]}")


# ═══════════════════════════════════════════════════════════════════════════════
# Public API
# ═══════════════════════════════════════════════════════════════════════════════

def check_ollama(base_url: str, model: str) -> tuple[bool, list[str]]:
    """Return (is_available, list_of_installed_models)."""
    try:
        r      = requests.get(f"{base_url}/api/tags", timeout=3)
        r.raise_for_status()
        models = [m["name"] for m in r.json().get("models", [])]
        return any(model.split(":")[0] in m for m in models), models
    except Exception:
        return False, []


def get_flagged_chains(source_name: str, limit: int = 20) -> list[dict]:
    """
    Return up to `limit` flagged chains for a given source, sorted by peak score desc.

    Each dict contains:
      chain_id, peak_score, peak_start, event_count,
      ground_truth, sample_images, eid_counts
    """
    _load_models()
    _load_data()

    if source_name not in SOURCE_BOUNDS:
        raise ValueError(f"Unknown source: {source_name}. Choose from {SOURCE_NAMES}")

    if source_name not in _flagged_cache:
        lo, hi = SOURCE_BOUNDS[source_name]
        src_chains = [
            c for c in _chains_m
            if len(c) > 0 and int(c.min()) >= lo and int(c.max()) < hi
        ]
        _flagged_cache[source_name] = _flag_chains(_seq_model, src_chains, _X_m_seq)

    flagged = _flagged_cache[source_name]
    top     = sorted(flagged, key=lambda e: -e["peak_score"])[:limit]

    results = []
    for idx, entry in enumerate(top):
        chain  = entry["chain"]
        rows   = [int(r) for r in chain]  # cast numpy int32 → Python int for JSON
        gt     = _get_chain_gt(chain)

        # Sample up to 3 distinct image names for the summary card
        images = []
        seen   = set()
        for r in rows:
            val = str(_events_m.iloc[r].get("image", "")).strip()
            key = val.split("\\")[-1].lower()
            if val and val not in _SKIP and key not in seen:
                seen.add(key); images.append(val.split("\\")[-1])
            if len(images) >= 3:
                break

        eid_counts = Counter(
            int(_events_m.iloc[r].get("event_id", 0))
            for r in rows
            if str(_events_m.iloc[r].get("event_id", "")).isdigit()
        )

        results.append({
            "chain_id":     idx,
            "peak_score":   round(float(entry["peak_score"]), 4),
            "peak_start":   int(entry["peak_start"]),
            "event_count":  len(rows),
            "ground_truth": gt,
            "sample_images": images,
            "eid_counts":   {EID_NAMES.get(k, f"EID {k}"): int(v)
                             for k, v in eid_counts.most_common(5)},
            "_chain_indices": rows,
        })

    return results


def score_all_windows(chain_indices: list[int]) -> list[dict]:
    """
    Score every non-overlapping SEQ_W window of the full chain with the TransformerAE.
    Returns one dict per window: {start, score, above_threshold, window_indices}.
    """
    _load_models()

    rows    = chain_indices
    windows, starts = [], []
    for s in range(0, len(rows) - SEQ_W + 1, SEQ_STRIDE):
        windows.append(np.array(_X_m_seq[rows[s: s + SEQ_W]], dtype=np.float32))
        starts.append(s)

    if not windows:
        return []

    x = torch.from_numpy(np.stack(windows)).to(DEVICE)
    with torch.no_grad():
        rec = _seq_model(x)
    scores = ((x - rec) ** 2).mean(dim=(1, 2)).cpu().numpy().tolist()

    return [
        {
            "start":           start,
            "score":           round(float(sc), 4),
            "above_threshold": float(sc) >= SEQ_THRESHOLD,
            "window_indices":  rows[start: start + SEQ_W],
        }
        for start, sc in zip(starts, scores)
    ]


def score_chain_events(chain_indices: list[int]) -> list[dict]:
    """
    Run the single-event AE on the peak window of a chain.
    Returns one dict per event: {row, event_id, eid_name, image, ae_score, fields}.
    """
    _load_models()
    _load_data()

    scores = _score_events_ae(chain_indices, _X_m_ae)
    result = []
    for i, (r, sc) in enumerate(zip(chain_indices, scores)):
        ev     = _events_m.iloc[r]
        eid    = ev.get("event_id", "")
        fields = {}
        for field in ["command_line", "parent_image", "target_object",
                      "dest_ip", "dest_hostname", "query_name"]:
            val = str(ev.get(field, "")).strip()
            if val and val not in _SKIP:
                fields[field] = val
        result.append({
            "idx":      i,
            "row":      int(r),
            "event_id": int(eid) if str(eid).isdigit() else eid,
            "eid_name": EID_NAMES.get(int(eid), "") if str(eid).isdigit() else "",
            "image":    str(ev.get("image", "")).split("\\")[-1],
            "ae_score": round(float(sc), 4),
            "fields":   fields,
        })

    return result


def attribute_chain(
    chain_indices: list[int],
    ollama_model: str,
    ollama_base_url: str,
    ollama_timeout: int = 600,
) -> dict:
    """
    Run hybrid RAG retrieval then call Ollama for chain-of-thought attribution.

    Returns:
      {technique_id, technique_name, confidence, explanation,
       recommended_action, rag_candidates, latency_s, raw_response}
    """
    _load_data()
    _load_kb()

    t0 = time.time()

    candidates  = _retrieve_multi_query(chain_indices)
    event_text  = _format_events_for_slm(chain_indices)
    cand_text   = "\n".join(
        f"- {h['technique_id']}: {h['technique_name']}"
        for h in candidates[:RAG_K]
    )
    prompt = ATTRIBUTION_PROMPT.format(
        event_text=event_text,
        candidates_text=cand_text,
    )

    resp = requests.post(
        f"{ollama_base_url}/api/chat",
        json={
            "model":    ollama_model,
            "messages": [{"role": "user", "content": prompt}],
            "stream":   False,
            "options":  {"temperature": 0.1},
        },
        timeout=ollama_timeout,
    )
    resp.raise_for_status()
    raw = resp.json()["message"]["content"]

    parsed = _parse_json_response(raw)
    parsed.setdefault("recommended_action", "")
    parsed.setdefault("technique_name",     "")

    return {
        "technique_id":      parsed.get("technique_id", ""),
        "technique_name":    parsed.get("technique_name", ""),
        "confidence":        parsed.get("confidence", ""),
        "explanation":       parsed.get("explanation", ""),
        "recommended_action": parsed.get("recommended_action", ""),
        "rag_candidates":    [
            {"id": h["technique_id"], "name": h["technique_name"]}
            for h in candidates[:RAG_K]
        ],
        "latency_s": round(time.time() - t0, 1),
        "raw_response": raw,
    }