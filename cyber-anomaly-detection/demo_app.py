"""
Cyber Anomaly Detection — Interactive Demo
==========================================
Streamlit app demonstrating the two-stage pipeline:
  Stage 1 — Detection   : Sequence TransformerAE flags anomalous chains;
                           single-event AE scores individual events.
  Stage 2 — Attribution : Multi-query RAG retrieves ATT&CK candidates;
                           Qwen 2.5 32B (via Ollama) attributes to a technique.

Run from cyber-anomaly-detection/:
    streamlit run demo_app.py
"""

from __future__ import annotations

import json
import pickle
import random
import re
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
import pandas as pd
import requests
import torch
import torch.nn as nn

# ── Make project imports available ───────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent))

import streamlit as st

# ── Page config (must be first Streamlit call) ────────────────────────────────
st.set_page_config(
    page_title="Cyber Anomaly Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Paths ─────────────────────────────────────────────────────────────────────
_HERE          = Path(__file__).parent
CKPT_DIR       = _HERE / "notebooks" / "checkpoints"
AE_DIR         = CKPT_DIR / "models" / "autoencoder"
SEQ_MODEL_DIR  = CKPT_DIR / "models" / "seq"
SEQ_CHAINS_DIR = CKPT_DIR / "seq"

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

# ── Pipeline constants (must match notebook 10) ────────────────────────────────
SEQ_THRESHOLD = 0.627528   # threshold at 0.1% FPR from notebook 07
seq_W         = 45         # sequence window size
seq_stride    = 45         # non-overlapping windows
RAG_K         = 15

SOURCE_BOUNDS: dict[str, tuple[int, int]] = {
    "OTRF Atomic Red Team": (511_105,   1_054_182),
    "Splunk Attack Range":  (1_382_201, 3_447_667),
}

EID_NAMES: dict[int, str] = {
    1:  "Process Create",           3:  "Network Connection",
    5:  "Process Terminate",        7:  "Image Load",
    8:  "CreateRemoteThread",       10: "Process Access",
    11: "File Create",              12: "Registry Object Create/Delete",
    13: "Registry Value Set",       15: "File Create Stream",
    17: "Pipe Created",             18: "Pipe Connected",
    22: "DNS Query",                23: "File Delete",
    25: "Process Tampering",        26: "File Delete Detected",
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
# Model class definitions (identical to notebook 10)
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
# Cached resource loaders
# ═══════════════════════════════════════════════════════════════════════════════

@st.cache_resource(show_spinner="Loading AE models…")
def load_models():
    ae_cfg = json.loads((AE_DIR / "ae_best.json").read_text())["word2vec"]
    layer_sizes = sorted(
        [max(16, int(353 * ae_cfg[f"ratio_{i}"])) for i in range(ae_cfg["n_layers"])],
        reverse=True,
    )
    latent_dim = max(8, int(353 * ae_cfg["latent_ratio"]))
    ae_model = Autoencoder(353, layer_sizes, latent_dim,
                           ae_cfg["activation"], ae_cfg["use_batchnorm"],
                           ae_cfg["dropout"]).to(DEVICE)
    ae_ckpt = torch.load(AE_DIR / "word2vec" / "best.pt", map_location=DEVICE, weights_only=True)
    ae_model.load_state_dict(ae_ckpt["model_state"])
    ae_model.eval()

    seq_raw    = json.loads((SEQ_MODEL_DIR / "best_params.json").read_text())
    seq_params = seq_raw.get("params", seq_raw)
    seq_model  = TransformerAE(
        352, seq_params["hidden_dim"], seq_params["latent_dim"],
        seq_params["n_layers"], seq_params.get("nhead", 4), seq_params["dropout"],
    ).to(DEVICE)
    seq_state = torch.load(
        SEQ_MODEL_DIR / f"seq_ae_{seq_params['strategy']}.pt",
        map_location=DEVICE, weights_only=True,
    )
    seq_model.load_state_dict(seq_state)
    seq_model.eval()

    return ae_model, seq_model, seq_params


@st.cache_resource(show_spinner="Loading event data…")
def load_data():
    events_m = pd.read_parquet(CKPT_DIR / "events_m.parquet")
    X_m_ae   = np.load(CKPT_DIR / "word2vec" / "X_m_w2v.npy",        mmap_mode="r")
    X_m_seq  = np.load(CKPT_DIR / "word2vec" / "X_m_w2v_norule.npy", mmap_mode="r")
    with open(SEQ_CHAINS_DIR / "seq_chains_m.pkl", "rb") as f:
        chains_m = pickle.load(f)
    return events_m, X_m_ae, X_m_seq, chains_m


@st.cache_resource(show_spinner="Loading ATT&CK knowledge base…")
def load_kb():
    from data.attack_kb.builder import build_kb
    from data.attack_kb.vector_store import retrieve_hybrid
    kb_entries = build_kb(force=False)
    return kb_entries, retrieve_hybrid


@st.cache_data(show_spinner="Flagging chains (first load only)…")
def get_flagged_for_source(
    _seq_model, _X_m_seq, _chains_m,
    source_name: str, lo: int, hi: int,
) -> list[dict]:
    """Flag chains for one source; result is pickled and reused across reruns."""
    src_chains = [
        c for c in _chains_m
        if len(c) > 0 and int(c.min()) >= lo and int(c.max()) < hi
    ]
    return _flag_chains(_seq_model, src_chains, _X_m_seq)


# ═══════════════════════════════════════════════════════════════════════════════
# Pipeline functions (mirror notebook 10)
# ═══════════════════════════════════════════════════════════════════════════════

def _flag_chains(model, chains, X, batch_size: int = 512) -> list[dict]:
    model.eval()
    buf, chain_info, all_results = [], [], []

    for ci, chain in enumerate(chains):
        if len(chain) < seq_W:
            continue
        for start in range(0, len(chain) - seq_W + 1, seq_stride):
            buf.append(np.array(X[list(chain[start : start + seq_W])], dtype=np.float32))
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


def score_all_windows(model, chain, X) -> tuple[list[int], list[float]]:
    """Batch-score all non-overlapping windows for a single chain."""
    rows = list(chain)
    windows, starts = [], []
    for s in range(0, len(rows) - seq_W + 1, seq_stride):
        windows.append(np.array(X[rows[s : s + seq_W]], dtype=np.float32))
        starts.append(s)
    if not windows:
        return [], []
    x = torch.from_numpy(np.stack(windows)).to(DEVICE)
    with torch.no_grad():
        rec = model(x)
    scores = ((x - rec) ** 2).mean(dim=(1, 2)).cpu().numpy().tolist()
    return starts, scores


@torch.no_grad()
def score_events(model, rows: list[int], X, batch_size: int = 1024) -> np.ndarray:
    model.eval()
    out = []
    for s in range(0, len(rows), batch_size):
        batch = rows[s : s + batch_size]
        x = torch.from_numpy(np.array(X[batch], dtype=np.float32)).to(DEVICE)
        rec = model(x)
        out.append(((x - rec) ** 2).mean(dim=1).cpu().numpy())
    return np.concatenate(out) if out else np.array([])


def get_chain_gt(chain, df: pd.DataFrame) -> str:
    rows  = list(chain)
    techs = [str(df.iloc[r].get("attck_technique", "")).strip() for r in rows if r < len(df)]
    techs = [t for t in techs if t and t not in _SKIP]
    return Counter(techs).most_common(1)[0][0] if techs else ""


def format_events_for_slm(rows: list[int], df: pd.DataFrame) -> str:
    lines = []
    for i, r in enumerate(rows):
        ev        = df.iloc[r]
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


def build_retrieval_query(rows: list[int], df: pd.DataFrame) -> str:
    eid_counts: Counter = Counter()
    images, targets, cmdlines, dest_ips, dns = [], [], [], [], []

    for r in rows:
        ev  = df.iloc[r]
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

    if images:   parts.append("Key processes: "         + ", ".join(_top_unique(images)))
    if cmdlines: parts.append("Command lines: "         + "; ".join(_top_unique(cmdlines, 2)))
    if targets:  parts.append("Targets: "               + ", ".join(_top_unique(targets)))
    if dest_ips: parts.append("Network destinations: "  + ", ".join(set(dest_ips)))
    if dns:      parts.append("DNS queries: "           + ", ".join(set(dns)))
    return " ".join(parts)


def _multi_queries(rows: list[int], df: pd.DataFrame, max_q: int = 3) -> list[str]:
    eid_groups: dict = defaultdict(list)
    for r in rows:
        eid = df.iloc[r].get("event_id", "")
        if str(eid).isdigit():
            eid_groups[int(eid)].append(r)
    top_eids = sorted(eid_groups, key=lambda e: -len(eid_groups[e]))[:max_q]
    queries  = [build_retrieval_query(eid_groups[e], df) for e in top_eids]
    queries.append(build_retrieval_query(rows, df))
    return list(dict.fromkeys(queries))


def retrieve_multi_query(rows: list[int], df: pd.DataFrame, retrieve_fn, k: int = RAG_K) -> list[dict]:
    best_hit: dict  = {}
    best_rank: dict = {}
    for query in _multi_queries(rows, df):
        for rank, hit in enumerate(retrieve_fn(query, k=k)):
            tid = hit["technique_id"]
            if tid not in best_rank or rank < best_rank[tid]:
                best_rank[tid] = rank
                best_hit[tid]  = hit
    return sorted(best_hit.values(), key=lambda h: best_rank[h["technique_id"]])[: k * 2]


def get_sigma_patterns(technique_ids: list[str], entries) -> dict:
    patterns = {tid: {"eids": set(), "indicators": []} for tid in technique_ids}
    for entry in entries:
        if entry.source != "Sigma" or entry.technique_id not in patterns:
            continue
        for line in entry.description.splitlines():
            line = line.strip()
            if line.startswith("Sysmon EventID:"):
                try:
                    patterns[entry.technique_id]["eids"].add(
                        int(line.split(":", 1)[1].strip().split()[0])
                    )
                except ValueError:
                    pass
            elif line.startswith("Detection indicators:"):
                for item in line.split(":", 1)[1].strip().split(","):
                    val = item.strip().split("=", 1)[-1].strip().lower()
                    if val and val not in patterns[entry.technique_id]["indicators"]:
                        patterns[entry.technique_id]["indicators"].append(val)
    return patterns


def extract_reasoning(raw: str) -> str:
    m = re.search(
        r"(?:\*{2}|#{2,3}\s*)Step(?:\s*1|\s*-by-Step).*?(?=(?:\*{2}|#{2,3}\s*)Step\s*2|\Z)",
        raw, re.DOTALL | re.IGNORECASE,
    )
    if m:
        lines = [
            ln for ln in m.group().splitlines()
            if not re.match(r"^(?:\*{2}|#{2,3})\s*Step", ln.strip(), re.IGNORECASE)
        ]
        text = "\n".join(lines).strip()
        if text:
            return text
    cutoff = min((i for i in [raw.rfind("```"), raw.rfind("{")] if i > 0), default=len(raw))
    pre    = "\n".join(
        ln for ln in raw[:cutoff].splitlines() if not ln.strip().startswith("```")
    ).strip()
    paras  = [
        p.strip() for p in pre.split("\n")
        if len(p.strip()) > 20
        and not re.match(r"^#{2,3}\s*Step", p.strip(), re.IGNORECASE)
    ]
    return "\n".join(paras[:2]) if paras else ""


def check_ollama(base_url: str, model: str) -> tuple[bool, list[str]]:
    try:
        r      = requests.get(f"{base_url}/api/tags", timeout=3)
        r.raise_for_status()
        models = [m["name"] for m in r.json().get("models", [])]
        return any(model.split(":")[0] in m for m in models), models
    except Exception:
        return False, []


def ollama_chat(base_url: str, model: str, prompt: str, timeout: int = 600) -> str:
    resp = requests.post(
        f"{base_url}/api/chat",
        json={
            "model":    model,
            "messages": [{"role": "user", "content": prompt}],
            "stream":   False,
            "options":  {"temperature": 0.1},
        },
        timeout=timeout,
    )
    resp.raise_for_status()
    return resp.json()["message"]["content"]


def parse_json_response(text: str) -> dict:
    import ast as _ast
    clean      = re.sub(r"```(?:json)?\s*|```", "", text).strip()
    last_open  = clean.rfind("{")
    last_close = clean.rfind("}")
    if last_open != -1 and last_close > last_open:
        blob = clean[last_open : last_close + 1]
        try:
            return json.loads(blob)
        except json.JSONDecodeError:
            try:
                r = _ast.literal_eval(blob)
                if isinstance(r, dict):
                    return {str(k): v for k, v in r.items()}
            except Exception:
                pass
    # Partial response: extract fields with regex
    result: dict = {}
    fragment = clean[last_open:] if last_open != -1 else clean
    for key in ("technique_id", "technique_name", "confidence", "explanation"):
        m = re.search('"' + key + r'"\s*:\s*"([^"]+)"', fragment)
        if m:
            result[key] = m.group(1)
    if "technique_id" in result:
        return result
    raise ValueError(f"No JSON found in LLM response: {text[:300]}")


def _chain_fingerprint(entry: dict) -> tuple:
    chain = entry["chain"]
    return (int(chain[0]), int(chain[-1]), len(chain), entry["peak_start"])


# ═══════════════════════════════════════════════════════════════════════════════
# Streamlit UI
# ═══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    from config import OLLAMA_BASE_URL, OLLAMA_MODEL, OLLAMA_TIMEOUT

    # ── Load resources ─────────────────────────────────────────────────────────
    ae_model, seq_model, seq_params = load_models()
    events_m, X_m_ae, X_m_seq, chains_m = load_data()
    kb_entries, retrieve_fn = load_kb()
    ollama_ok, _avail = check_ollama(OLLAMA_BASE_URL, OLLAMA_MODEL)

    # ── Sidebar ────────────────────────────────────────────────────────────────
    with st.sidebar:
        st.title("🛡️ Cyber Anomaly Detection")
        st.caption("Sysmon → MITRE ATT&CK attribution pipeline")
        st.divider()

        st.subheader("System Status")
        st.markdown(f"{'🟢' if ae_model  else '🔴'} **Single-event AE** (Word2Vec, 353-dim)")
        st.markdown(f"{'🟢' if seq_model else '🔴'} **Sequence TransformerAE** (W={seq_W})")
        st.markdown(f"{'🟢' if kb_entries else '🔴'} **ATT&CK KB** ({len(kb_entries)} entries)")
        st.markdown(
            f"{'🟢' if ollama_ok else '🟡'} **LLM** — "
            f"{'available' if ollama_ok else 'not detected'} (`{OLLAMA_MODEL}`)"
        )
        if not ollama_ok:
            st.info(
                "LLM unavailable. Stage 2 will show RAG candidates only.\n\n"
                f"To enable: `ollama serve` then `ollama pull {OLLAMA_MODEL}`"
            )

        st.divider()
        st.subheader("Select Example Chain")

        source_name = st.selectbox("Dataset source", list(SOURCE_BOUNDS.keys()))
        lo, hi      = SOURCE_BOUNDS[source_name]

        with st.spinner(f"Flagging {source_name} chains…"):
            flagged = get_flagged_for_source(seq_model, X_m_seq, chains_m, source_name, lo, hi)

        if not flagged:
            st.error("No flagged chains found for this source.")
            return

        # Top-20 by peak score
        top20 = sorted(flagged, key=lambda e: -e["peak_score"])[:20]
        annotated = [
            (e, get_chain_gt(e["chain"], events_m))
            for e in top20
        ]

        labels = [
            f"GT: {gt or '?':<14} | {len(e['chain'])} events | score={e['peak_score']:.4f}"
            for e, gt in annotated
        ]
        sel = st.selectbox(
            "Chain (top 20 by anomaly score)",
            range(len(labels)),
            format_func=lambda i: labels[i],
        )
        entry, selected_gt = annotated[sel]

        st.divider()
        st.markdown(f"**Ground truth:** `{selected_gt or 'unknown'}`")
        st.markdown(f"**Chain events:** `{len(entry['chain'])}`")
        st.markdown(f"**Peak window start:** event `#{entry['peak_start']}`")
        st.markdown(f"**Seq AE score:** `{entry['peak_score']:.4f}` (threshold `{SEQ_THRESHOLD}`)")

        st.divider()
        st.caption(
            f"Device: `{DEVICE}` | "
            f"AE layers: `[231,176,176,162]` | "
            f"Transformer: `H={seq_params.get('hidden_dim',256)} "
            f"L={seq_params.get('n_layers',2)} "
            f"heads={seq_params.get('nhead',8)}`"
        )

    # ── Main panel ─────────────────────────────────────────────────────────────
    st.title("Cyber Anomaly Detection")
    st.caption(
        "Windows Sysmon event logs → Sequence AE anomaly detection "
        "→ Multi-query RAG → LLM ATT&CK attribution"
    )

    tab1, tab2 = st.tabs(["🔍  Stage 1 — Detection", "🧠  Stage 2 — Attribution"])

    chain      = entry["chain"]
    all_rows   = list(chain)
    peak_start = entry.get("peak_start", 0)
    peak_rows  = all_rows[peak_start : peak_start + seq_W] or all_rows[:seq_W]
    fingerprint = _chain_fingerprint(entry)

    # ── STAGE 1 — DETECTION ───────────────────────────────────────────────────
    with tab1:
        st.header("Stage 1 — Anomaly Detection")

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Chain length",    f"{len(chain)} events")
        m2.metric("Peak window",     f"events {peak_start}-{peak_start + seq_W - 1}")
        m3.metric("Seq AE score",    f"{entry['peak_score']:.4f}")
        m4.metric("Threshold (0.1% FPR)", f"{SEQ_THRESHOLD:.4f}")

        # 1a — Sequence AE window scores
        st.subheader("1a.  Sequence TransformerAE — Window Scores")
        st.caption(
            f"Each bar = one {seq_W}-event non-overlapping window. "
            "🔴 Red = flagged above threshold. **Click a bar to view its events in 1b.**"
        )
        with st.spinner("Scoring windows…"):
            starts, win_scores = score_all_windows(seq_model, chain, X_m_seq)

        # Determine which window index is currently selected (default = peak)
        try:
            peak_win_idx = starts.index(peak_start)
        except ValueError:
            peak_win_idx = 0
        sel_win_idx = st.session_state.get("sel_win_idx", peak_win_idx)
        # Guard against stale index if chain has fewer windows
        sel_win_idx = min(sel_win_idx, len(starts) - 1)

        try:
            import plotly.graph_objects as go

            bar_colors   = ["#e74c3c" if s >= SEQ_THRESHOLD else "#2ecc71" for s in win_scores]
            border_widths = [4 if i == sel_win_idx else 0 for i in range(len(starts))]
            border_colors = ["#f5c518" if i == sel_win_idx else "#000" for i in range(len(starts))]

            fig = go.Figure()
            fig.add_hline(
                y=SEQ_THRESHOLD, line_dash="dash", line_color="#e74c3c",
                annotation_text=f"Threshold {SEQ_THRESHOLD:.4f}",
                annotation_position="top right",
            )
            fig.add_trace(go.Bar(
                x=[f"W{i} (ev {s}-{s+seq_W-1})" for i, s in enumerate(starts)],
                y=win_scores,
                marker_color=bar_colors,
                marker_line_color=border_colors,
                marker_line_width=border_widths,
                text=[f"{v:.4f}" for v in win_scores],
                textposition="outside",
            ))
            fig.update_layout(
                xaxis_title="Window",
                yaxis_title="Reconstruction error (MSE)",
                height=320,
                margin=dict(t=10, b=40),
                showlegend=False,
                plot_bgcolor="rgba(0,0,0,0)",
                clickmode="event",
            )
            chart_event = st.plotly_chart(
                fig, use_container_width=True,
                on_select="rerun", key="win_chart",
            )
            # Read click selection and update stored window index
            sel_points = []
            if chart_event is not None:
                try:
                    sel_points = chart_event.selection.get("points", [])
                except AttributeError:
                    sel_points = (chart_event or {}).get("selection", {}).get("points", [])
            if sel_points:
                clicked_idx = sel_points[0].get("point_index", sel_win_idx)
                if 0 <= clicked_idx < len(starts):
                    st.session_state["sel_win_idx"] = clicked_idx
                    sel_win_idx = clicked_idx

        except ImportError:
            win_df = pd.DataFrame({"Window start": starts, "Score": win_scores})
            st.bar_chart(win_df.set_index("Window start"))
            sel_win_idx = peak_win_idx

        # 1b — Single-event AE scores for the selected window
        display_start = starts[sel_win_idx] if starts else peak_start
        display_rows  = all_rows[display_start : display_start + seq_W] or all_rows[:seq_W]
        is_peak = (display_start == peak_start)
        win_label = (
            f"W{sel_win_idx} (events {display_start}-{display_start + len(display_rows) - 1})"
            + (" ⭐ peak" if is_peak else "")
        )
        st.subheader(f"1b.  Single-event AE — Per-event Scores  •  {win_label}")
        st.caption(
            f"{len(display_rows)} events in the selected window. "
            "Higher score = further from benign distribution. "
            "Click a bar in 1a to switch windows."
        )
        with st.spinner("Scoring individual events…"):
            ev_scores = score_events(ae_model, display_rows, X_m_ae)

        ev_rows = []
        for i, (r, sc) in enumerate(zip(display_rows, ev_scores)):
            ev        = events_m.iloc[r]
            eid       = ev.get("event_id", "")
            eid_lbl   = EID_NAMES.get(int(eid), "") if str(eid).isdigit() else ""
            image     = str(ev.get("image",        "")).strip()
            image     = image.split("\\")[-1] if "\\" in image else image
            cmd       = str(ev.get("command_line", "")).strip()[:70]
            target    = str(ev.get("target_object", "") or ev.get("target_image", "")).strip()[:60]
            ev_rows.append({
                "#":             i + 1,
                "EID":           f"{eid}" + (f" ({eid_lbl})" if eid_lbl else ""),
                "Image":         image or "—",
                "Command (trunc)": cmd    or "—",
                "Target":        target   or "—",
                "AE score":      round(float(sc), 5),
            })

        ev_df = pd.DataFrame(ev_rows)
        st.dataframe(
            ev_df.style.background_gradient(subset=["AE score"], cmap="OrRd"),
            use_container_width=True,
            hide_index=True,
        )

        # 1c — EID distribution across the full chain
        st.subheader("1c.  EID Distribution — Full Chain")
        eid_ctr: Counter = Counter()
        for r in all_rows:
            eid = events_m.iloc[r].get("event_id", "")
            if str(eid).isdigit():
                eid_ctr[int(eid)] += 1

        eid_df = pd.DataFrame([
            {"EID": f"EID {k} — {EID_NAMES.get(k,'Unknown')}", "Count": v}
            for k, v in sorted(eid_ctr.items(), key=lambda x: -x[1])
        ])
        st.bar_chart(eid_df.set_index("EID"))

    # ── STAGE 2 — ATTRIBUTION ─────────────────────────────────────────────────
    with tab2:
        st.header("Stage 2 — ATT&CK Attribution")

        # Clear stale session state when chain changes
        if st.session_state.get("_fp") != fingerprint:
            for k in ("rag_hits", "llm_result", "sel_win_idx"):
                st.session_state.pop(k, None)
            st.session_state["_fp"] = fingerprint

        # 2a — RAG retrieval
        st.subheader("2a.  Multi-query RAG — Candidate Retrieval")
        st.caption(
            f"Hybrid dense (all-mpnet-base-v2) + BM25, k={RAG_K}. "
            "One query per dominant EID type + combined query."
        )

        run_rag = st.button("Run RAG Retrieval", type="primary", key="btn_rag")

        if run_rag:
            with st.spinner("Running multi-query RAG…"):
                q_rows = all_rows if len(all_rows) <= 300 else sorted(random.sample(all_rows, 300))
                hits   = retrieve_multi_query(q_rows, events_m, retrieve_fn, k=RAG_K)
                st.session_state["rag_hits"] = hits

        hits = st.session_state.get("rag_hits")

        if hits is not None:
            gt_in_rag = selected_gt in [h["technique_id"] for h in hits]

            c_left, c_right = st.columns([3, 1])
            c_left.markdown(f"**{len(hits)} candidates retrieved**")
            c_right.markdown(
                f"GT in candidates: {'✅ Yes' if gt_in_rag else '❌ No'}"
                + (f" (`{selected_gt}`)" if selected_gt else "")
            )

            cand_df = pd.DataFrame([
                {
                    "Rank":           i + 1,
                    "Technique ID":   h["technique_id"],
                    "Technique Name": h["technique_name"],
                    "GT match":       "✅" if h["technique_id"] == selected_gt else "",
                }
                for i, h in enumerate(hits)
            ])
            st.dataframe(cand_df, use_container_width=True, hide_index=True)

            # 2b — Events window
            st.subheader("2b.  Events Sent to LLM (Peak Window)")
            event_text = format_events_for_slm(peak_rows, events_m)
            with st.expander(f"View formatted {len(peak_rows)} events"):
                st.code(event_text, language="text")

            # 2c — LLM attribution
            st.subheader("2c.  LLM Attribution")

            if ollama_ok:
                run_llm = st.button("Run LLM Attribution", type="primary", key="btn_llm")

                if run_llm:
                    top_tids  = list(dict.fromkeys(h["technique_id"] for h in hits[:5]))
                    sigma_pat = get_sigma_patterns(top_tids, kb_entries)

                    candidates_text = "".join(
                        f"[{h['technique_id']}] {h['technique_name']}: {h['document']}"
                        for h in hits
                    )
                    valid_ids        = ", ".join(dict.fromkeys(h["technique_id"] for h in hits))
                    candidates_text += f"\nValid technique IDs (you MUST choose one): {valid_ids}"

                    prompt = ATTRIBUTION_PROMPT.format(
                        event_text=event_text,
                        candidates_text=candidates_text,
                    )

                    with st.spinner("Waiting for LLM… (30-90 s for 32B model)"):
                        t0 = time.time()
                        try:
                            raw     = ollama_chat(OLLAMA_BASE_URL, OLLAMA_MODEL, prompt, OLLAMA_TIMEOUT)
                            elapsed = time.time() - t0
                            result  = parse_json_response(raw)
                            result["_raw"]      = raw
                            result["_latency"]  = round(elapsed, 2)
                            result["_prompt"]   = prompt
                            st.session_state["llm_result"] = result
                        except requests.exceptions.ConnectionError:
                            st.error("Ollama disconnected during inference.")
                            result = None
                        except Exception as exc:
                            st.error(f"LLM call failed: {exc}")
                            result = None

                result = st.session_state.get("llm_result")
                if result:
                    pred_id      = str(result.get("technique_id", "")).strip()
                    exact        = pred_id == selected_gt
                    parent_match = (
                        pred_id.split(".")[0] == selected_gt.split(".")[0]
                        if selected_gt and pred_id else False
                    )
                    match_label  = "Exact ✅" if exact else ("Parent ≈" if parent_match else "Miss ❌")

                    r1, r2, r3, r4 = st.columns(4)
                    r1.metric("Predicted",    pred_id or "—")
                    r2.metric("Confidence",   str(result.get("confidence", "—")).upper())
                    r3.metric("Ground truth", selected_gt or "unknown")
                    r4.metric("Match",        match_label)

                    st.markdown(f"**Technique name:** {result.get('technique_name', '—')}")
                    st.markdown(f"**Latency:** {result.get('_latency', '—')} s")

                    with st.expander("Explanation"):
                        st.write(result.get("explanation", "(none)"))
                    with st.expander("Recommended Action"):
                        st.write(result.get("recommended_action", "(none)"))
                    with st.expander("Step-by-Step Reasoning (Step 1)"):
                        st.write(extract_reasoning(result.get("_raw", "")))
                    with st.expander("Raw LLM response"):
                        st.code(result.get("_raw", ""), language="text")
                    with st.expander("Full prompt sent to LLM"):
                        st.code(result.get("_prompt", ""), language="text")
            else:
                st.info(
                    "**LLM not available** — Ollama not running or model not found.\n\n"
                    f"To enable: `ollama serve` then `ollama pull {OLLAMA_MODEL}`\n\n"
                    "Detection (Stage 1) and RAG candidates above are complete."
                )
                if selected_gt:
                    if gt_in_rag:
                        st.success(
                            f"GT `{selected_gt}` **is** in the RAG candidates — "
                            "LLM would have the correct technique available to choose from."
                        )
                    else:
                        st.warning(
                            f"GT `{selected_gt}` is **not** in the RAG candidates — "
                            "attribution is bottlenecked by KB coverage, not the LLM."
                        )
        else:
            st.info("Click **Run RAG Retrieval** to start attribution.")


if __name__ == "__main__":
    main()
