"""
embeddings.py
Tokenização field-aware e embeddings via hashing trick para registry keys,
command lines, processos e file paths. Sem dependências externas — usa
HashingVectorizer (sklearn) + features derivadas inteligentes.

Pipeline:
  1. tokenize_*    → list[str] por campo (paths, registry, cmdline, ports)
  2. embed_corpus  → matriz esparsa (N, dim) via HashingVectorizer
  3. window_embedding → mean-pool dos eventos de uma janela
  4. smart_features  → features derivadas (entropy de cmdline, depth de paths,
                       razão HKLM/HKCU, parent→child rarity, port categories,
                       distância ao centróide benigno)
"""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import Iterable

import numpy as np
from scipy.sparse import csr_matrix, vstack
from sklearn.feature_extraction.text import HashingVectorizer


# ─────────────────────────────────────────────
# Constantes
# ─────────────────────────────────────────────

EMBED_DIM = 128  # dimensão dos hash embeddings por campo

REGISTRY_HIVE_MAP = {
    "hkey_local_machine": "hklm", "hklm": "hklm",
    "hkey_current_user":  "hkcu", "hkcu": "hkcu",
    "hkey_classes_root":  "hkcr", "hkcr": "hkcr",
    "hkey_users":         "hku",  "hku":  "hku",
    "hkey_current_config": "hkcc", "hkcc": "hkcc",
}

# Sub-paths de registry frequentemente abusados (persistence / DLL hijack)
REGISTRY_SUSPICIOUS_PATTERNS = (
    "currentversion\\run",
    "currentversion\\runonce",
    "currentversion\\winlogon",
    "currentversion\\image file execution options",
    "services\\",
    "appinit_dlls",
    "knowndlls",
    "shellexecutehooks",
    "userinitmprlogonscript",
    "bootexecute",
    "policies\\explorer\\run",
)

# Tokens em command lines que geralmente indicam ofuscação ou LOLBIN abuse
CMDLINE_OBFUSCATION_RE = re.compile(
    r"(?i)("
    r"-enc(odedcommand)?|-e\s|-ec\s|"          # PowerShell encoded
    r"frombase64string|"                        # base64 decoding
    r"-windowstyle\s+hidden|-w\s+hidden|"
    r"-nop|-noprofile|-noni|-nointeractive|"
    r"downloadstring|invoke-expression|iex\s|"
    r"bypass|"
    r"reflection\.assembly|"
    r"add-mppreference|set-mppreference|"      # AV tampering
    r"vssadmin\s+delete|wbadmin\s+delete|"     # shadow copy deletion
    r"bcdedit|"
    r"net\s+user\s+/add|net\s+localgroup"
    r")"
)

CMDLINE_SHELL_SPLIT_RE = re.compile(r"[\s\"'`,;|&<>()\[\]{}]+")
PATH_SPLIT_RE = re.compile(r"[\\/]+")

# Categorias de portas (well-known, registered, dynamic, lateral)
PORT_CATEGORIES = ("well_known", "registered", "dynamic", "lateral", "rare_high")
LATERAL_PORTS = {445, 135, 139, 3389, 5985, 5986, 22, 1433, 3306, 5432}


# ─────────────────────────────────────────────
# Tokenizers field-aware
# ─────────────────────────────────────────────

def tokenize_path(p: str) -> list[str]:
    """C:\\Windows\\System32\\cmd.exe → ['c:', 'windows', 'system32', 'cmd.exe']"""
    if not p or p == "nan":
        return []
    parts = [t.lower() for t in PATH_SPLIT_RE.split(p) if t]
    return parts


def tokenize_registry(key: str) -> list[str]:
    """HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\foo
       → ['hklm', 'software', 'microsoft', 'windows', 'currentversion', 'run', 'foo']"""
    if not key or key == "nan":
        return []
    parts = [t.lower() for t in PATH_SPLIT_RE.split(key) if t]
    if parts:
        parts[0] = REGISTRY_HIVE_MAP.get(parts[0], parts[0])
    return parts


def tokenize_cmdline(cmd: str) -> list[str]:
    """Tokeniza command line preservando flags e LOLBIN tokens."""
    if not cmd or cmd == "nan":
        return []
    toks = [t.lower() for t in CMDLINE_SHELL_SPLIT_RE.split(cmd) if t]
    # Adiciona basenames de paths embutidos como tokens extra
    extra = []
    for t in toks:
        if "\\" in t or "/" in t:
            extra.extend(tokenize_path(t))
    return toks + extra


def tokenize_port(port: int | str | float) -> str:
    """Mapeia uma porta numérica para uma categoria + a própria porta como token."""
    try:
        p = int(float(port))
    except (TypeError, ValueError):
        return ""
    if p <= 0:
        return ""
    if p in LATERAL_PORTS:
        cat = "lateral"
    elif p < 1024:
        cat = "well_known"
    elif p < 49152:
        cat = "registered"
    else:
        cat = "dynamic"
    return f"port_{cat}_{p}"


def tokenize_process(name: str) -> list[str]:
    """powershell.exe → ['powershell', 'exe', 'powershell.exe']"""
    if not name or name == "nan":
        return []
    n = name.lower()
    base = [n]
    if "." in n:
        base.extend(n.rsplit(".", 1))
    return base


# ─────────────────────────────────────────────
# Hashing embeddings
# ─────────────────────────────────────────────

def _make_hasher(dim: int = EMBED_DIM) -> HashingVectorizer:
    """HashingVectorizer com tokenizer custom (já tokenizamos manualmente)."""
    return HashingVectorizer(
        n_features=dim,
        analyzer=lambda x: x,         # x já é list[str]
        alternate_sign=False,         # garante valores não-negativos
        norm="l2",
    )


_REG_HASHER = _make_hasher()
_CMD_HASHER = _make_hasher()
_PROC_HASHER = _make_hasher()
_PATH_HASHER = _make_hasher()


def embed_tokens(token_lists: list[list[str]], hasher: HashingVectorizer) -> csr_matrix:
    """Embed N documentos pré-tokenizados → matriz esparsa (N, dim)."""
    if not token_lists:
        return csr_matrix((0, hasher.n_features))
    return hasher.transform(token_lists)


def mean_pool(mat: csr_matrix) -> np.ndarray:
    """Mean-pool sobre as linhas. Devolve vetor denso (dim,)."""
    if mat.shape[0] == 0:
        return np.zeros(mat.shape[1], dtype=np.float32)
    return np.asarray(mat.mean(axis=0)).ravel().astype(np.float32)


# ─────────────────────────────────────────────
# Features derivadas inteligentes (por janela)
# ─────────────────────────────────────────────

def _shannon(values: Iterable[str]) -> float:
    counts = Counter(v for v in values if v)
    total = sum(counts.values())
    if total <= 1:
        return 0.0
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def cmdline_smart_features(cmdlines: list[str]) -> dict:
    """Features semânticas sobre command lines (não apenas counts)."""
    cmds = [c for c in cmdlines if c and c != "nan"]
    if not cmds:
        return {
            "cmdline_avg_len": 0.0,
            "cmdline_max_len": 0,
            "cmdline_avg_token_entropy": 0.0,
            "cmdline_obfuscation_hits": 0,
            "cmdline_b64_blob_count": 0,
            "cmdline_flag_density": 0.0,
            "cmdline_lolbin_calls": 0,
        }
    lengths = [len(c) for c in cmds]
    obfusc = sum(1 for c in cmds if CMDLINE_OBFUSCATION_RE.search(c))

    # Long base64 blobs (>=80 chars de [A-Za-z0-9+/=])
    b64_re = re.compile(r"[A-Za-z0-9+/=]{80,}")
    b64_blobs = sum(len(b64_re.findall(c)) for c in cmds)

    # Densidade de flags (-foo /bar) por token
    total_tokens = 0
    flag_tokens = 0
    entropies = []
    for c in cmds:
        toks = [t for t in CMDLINE_SHELL_SPLIT_RE.split(c) if t]
        total_tokens += len(toks)
        flag_tokens += sum(1 for t in toks if t.startswith(("-", "/")) and len(t) > 1)
        entropies.append(_shannon(list(c.lower())))

    lolbin_re = re.compile(
        r"(?i)\b(certutil|bitsadmin|regsvr32|rundll32|mshta|wmic|"
        r"installutil|msbuild|odbcconf|wscript|cscript)\b"
    )
    lolbin_calls = sum(1 for c in cmds if lolbin_re.search(c))

    return {
        "cmdline_avg_len": float(np.mean(lengths)),
        "cmdline_max_len": int(np.max(lengths)),
        "cmdline_avg_token_entropy": float(np.mean(entropies)) if entropies else 0.0,
        "cmdline_obfuscation_hits": int(obfusc),
        "cmdline_b64_blob_count": int(b64_blobs),
        "cmdline_flag_density": float(flag_tokens / total_tokens) if total_tokens else 0.0,
        "cmdline_lolbin_calls": int(lolbin_calls),
    }


def registry_smart_features(reg_keys: list[str]) -> dict:
    """Features sobre registry keys: hive distribution + suspicious paths."""
    keys = [k for k in reg_keys if k and k != "nan"]
    if not keys:
        return {
            "reg_hive_hklm_ratio": 0.0,
            "reg_hive_hkcu_ratio": 0.0,
            "reg_hive_other_ratio": 0.0,
            "reg_avg_depth": 0.0,
            "reg_suspicious_path_hits": 0,
            "reg_unique_subtrees": 0,
        }
    hives = []
    depths = []
    susp = 0
    subtrees = set()
    for k in keys:
        toks = tokenize_registry(k)
        if not toks:
            continue
        hives.append(toks[0])
        depths.append(len(toks))
        kl = k.lower().replace("/", "\\")
        if any(p in kl for p in REGISTRY_SUSPICIOUS_PATTERNS):
            susp += 1
        # subtree = primeiros 3 níveis
        subtrees.add("\\".join(toks[:3]))

    n = len(hives)
    counter = Counter(hives)
    return {
        "reg_hive_hklm_ratio": counter.get("hklm", 0) / n if n else 0.0,
        "reg_hive_hkcu_ratio": counter.get("hkcu", 0) / n if n else 0.0,
        "reg_hive_other_ratio": (n - counter.get("hklm", 0) - counter.get("hkcu", 0)) / n if n else 0.0,
        "reg_avg_depth": float(np.mean(depths)) if depths else 0.0,
        "reg_suspicious_path_hits": int(susp),
        "reg_unique_subtrees": len(subtrees),
    }


def path_smart_features(paths: list[str]) -> dict:
    """Features sobre file paths."""
    ps = [p for p in paths if p and p != "nan"]
    if not ps:
        return {
            "path_avg_depth": 0.0,
            "path_temp_ratio": 0.0,
            "path_appdata_ratio": 0.0,
            "path_system32_ratio": 0.0,
            "path_unique_extensions": 0,
            "path_executable_writes": 0,
        }
    depths = []
    temp = appdata = system32 = exe_writes = 0
    extensions = set()
    exec_exts = {"exe", "dll", "scr", "ps1", "vbs", "bat", "cmd", "hta", "lnk", "msi"}
    for p in ps:
        toks = tokenize_path(p)
        depths.append(len(toks))
        pl = p.lower()
        if "\\temp\\" in pl or "/tmp/" in pl:
            temp += 1
        if "appdata" in pl:
            appdata += 1
        if "system32" in pl or "syswow64" in pl:
            system32 += 1
        if "." in toks[-1] if toks else False:
            ext = toks[-1].rsplit(".", 1)[-1]
            extensions.add(ext)
            if ext in exec_exts:
                exe_writes += 1
    n = len(ps)
    return {
        "path_avg_depth": float(np.mean(depths)) if depths else 0.0,
        "path_temp_ratio": temp / n,
        "path_appdata_ratio": appdata / n,
        "path_system32_ratio": system32 / n,
        "path_unique_extensions": len(extensions),
        "path_executable_writes": exe_writes,
    }


def port_smart_features(ports: list) -> dict:
    """Distribuição de categorias de portas."""
    cats = Counter()
    rare_high = 0
    for p in ports:
        try:
            pi = int(float(p))
        except (TypeError, ValueError):
            continue
        if pi <= 0:
            continue
        if pi in LATERAL_PORTS:
            cats["lateral"] += 1
        elif pi < 1024:
            cats["well_known"] += 1
        elif pi < 49152:
            cats["registered"] += 1
        else:
            cats["dynamic"] += 1
            if pi > 60000:
                rare_high += 1
    total = sum(cats.values())
    return {
        "port_lateral_ratio":   cats["lateral"] / total if total else 0.0,
        "port_well_known_ratio": cats["well_known"] / total if total else 0.0,
        "port_dynamic_ratio":   cats["dynamic"] / total if total else 0.0,
        "port_rare_high_count": int(rare_high),
        "port_category_entropy": _shannon(
            [c for c, n in cats.items() for _ in range(n)]
        ),
    }


def process_tree_features(parent_child_pairs: list[tuple[str, str]]) -> dict:
    """Raridade de pares parent→child no contexto da janela."""
    pairs = [(p, c) for p, c in parent_child_pairs if p and c and p != "nan" and c != "nan"]
    if not pairs:
        return {
            "proctree_unique_pairs": 0,
            "proctree_pair_entropy": 0.0,
            "proctree_suspicious_pairs": 0,
        }
    suspicious_parents = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
                          "explorer.exe", "services.exe", "lsass.exe", "wininit.exe"}
    suspicious_children = {"powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
                           "rundll32.exe", "regsvr32.exe", "mshta.exe"}
    susp_pairs = sum(
        1 for p, c in pairs
        if p in suspicious_parents and c in suspicious_children
    )
    pair_strs = [f"{p}>{c}" for p, c in pairs]
    return {
        "proctree_unique_pairs": len(set(pair_strs)),
        "proctree_pair_entropy": _shannon(pair_strs),
        "proctree_suspicious_pairs": susp_pairs,
    }


# ─────────────────────────────────────────────
# Window-level embedding builder
# ─────────────────────────────────────────────

def build_window_embedding(chunk) -> dict:
    """
    Recebe um DataFrame chunk (uma janela) e devolve dict com:
      - 'embedding': vetor compacto (4 * EMBED_DIM/8) com mean-pool por campo,
                     reduzido por hashing+sum (mantém ~64 dims totais)
      - 'smart_features': dict de features derivadas inteligentes
    """
    cmd_list  = chunk["command_line"].astype(str).tolist() if "command_line" in chunk else []
    reg_list  = chunk["registry_key"].astype(str).tolist() if "registry_key" in chunk else []
    proc_list = chunk["process_name"].astype(str).tolist() if "process_name" in chunk else []
    path_list = chunk["file_path"].astype(str).tolist() if "file_path" in chunk else []

    parent_list = (
        chunk["parent_process"].astype(str).tolist()
        if "parent_process" in chunk else [""] * len(chunk)
    )
    parent_child = list(zip(parent_list, proc_list))

    port_list = (
        chunk["network_dest_port"].tolist()
        if "network_dest_port" in chunk else []
    )

    # Pooled hash embeddings por campo → reduz cada um para 16 dims via sum-buckets
    def _pool_compact(token_lists: list[list[str]], hasher: HashingVectorizer,
                      out_dim: int = 16) -> np.ndarray:
        if not token_lists:
            return np.zeros(out_dim, dtype=np.float32)
        full = mean_pool(embed_tokens(token_lists, hasher))  # (EMBED_DIM,)
        # Sum-bucket reduction: agrega EMBED_DIM em out_dim
        buckets = full.reshape(out_dim, -1).sum(axis=1)
        # L2-normalize para estabilidade
        norm = np.linalg.norm(buckets)
        return buckets / norm if norm > 0 else buckets

    cmd_emb  = _pool_compact([tokenize_cmdline(c)  for c in cmd_list],  _CMD_HASHER)
    reg_emb  = _pool_compact([tokenize_registry(r) for r in reg_list],  _REG_HASHER)
    proc_emb = _pool_compact([tokenize_process(p)  for p in proc_list], _PROC_HASHER)
    path_emb = _pool_compact([tokenize_path(p)     for p in path_list], _PATH_HASHER)

    embedding = np.concatenate([cmd_emb, reg_emb, proc_emb, path_emb])  # 64 dims

    smart = {}
    smart.update(cmdline_smart_features(cmd_list))
    smart.update(registry_smart_features(reg_list))
    smart.update(path_smart_features(path_list))
    smart.update(port_smart_features(port_list))
    smart.update(process_tree_features(parent_child))

    return {"embedding": embedding, "smart_features": smart}


SMART_FEATURE_NAMES = (
    # cmdline
    "cmdline_avg_len", "cmdline_max_len", "cmdline_avg_token_entropy",
    "cmdline_obfuscation_hits", "cmdline_b64_blob_count",
    "cmdline_flag_density", "cmdline_lolbin_calls",
    # registry
    "reg_hive_hklm_ratio", "reg_hive_hkcu_ratio", "reg_hive_other_ratio",
    "reg_avg_depth", "reg_suspicious_path_hits", "reg_unique_subtrees",
    # paths
    "path_avg_depth", "path_temp_ratio", "path_appdata_ratio",
    "path_system32_ratio", "path_unique_extensions", "path_executable_writes",
    # ports
    "port_lateral_ratio", "port_well_known_ratio", "port_dynamic_ratio",
    "port_rare_high_count", "port_category_entropy",
    # process tree
    "proctree_unique_pairs", "proctree_pair_entropy", "proctree_suspicious_pairs",
)

EMBEDDING_DIM = 64  # 4 campos × 16 dims
SMART_FEATURE_DIM = len(SMART_FEATURE_NAMES)
