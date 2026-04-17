"""
ATT&CK Knowledge Base builder.

Primary source:
  1. Official MITRE ATT&CK STIX bundle (enterprise-attack.json)
     Provides technique descriptions, data components (Sysmon event coverage),
     and real adversary procedure examples.

Secondary enrichment (merged into same T-code entries):
  2. OTRF atomic _metadata YAML files  → simulation tool names
  3. Splunk attack_techniques YAML files → scenario descriptions

Produces a list of KBEntry records written to ATTACK_KB_DIR/entries.json.
These are later ingested into ChromaDB by data/attack_kb/vector_store.py.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

import yaml

from config import (
    ATTACK_KB_DIR,
    OTRF_ATOMIC_META,
    SIGMA_RULES_DIR,
    SPLUNK_TECHNIQUES,
    SPLUNK_MALWARE_DIR,
)

logger = logging.getLogger(__name__)

KB_ENTRIES_PATH  = Path(ATTACK_KB_DIR) / "entries.json"
STIX_CACHE_PATH  = Path(ATTACK_KB_DIR) / "enterprise-attack.json"

# Max procedure examples to embed per technique (keeps documents concise)
_MAX_PROCEDURES = 3

# Sigma logsource category → Sysmon EventID
_LOGSOURCE_TO_EID: dict[str, int] = {
    "process_creation":    1,
    "network_connection":  3,
    "image_load":          7,
    "create_remote_thread": 8,
    "process_access":      10,
    "file_creation":       11,
    "file_event":          11,
    "registry_add":        12,
    "registry_delete":     12,
    "registry_event":      13,
    "registry_set":        13,
    "pipe_creation":       17,
    "dns_query":           22,
    "file_delete":         23,
    "process_tampering":   25,
}

_SIGMA_SKIP_STATUSES = {"deprecated", "unsupported"}


@dataclass
class KBEntry:
    technique_id: str          # e.g. "T1003.001"
    technique_name: str        # human-readable name
    tactic_ids: list[str]      # e.g. ["TA0006"]
    description: str           # full document text used for RAG embedding
    source: str                # "MITRE" | "OTRF" | "Splunk"
    source_id: str             # YAML id field or STIX id
    keywords: list[str] = field(default_factory=list)


def build_kb(force: bool = False) -> list[KBEntry]:
    """
    Build and cache the ATT&CK KB.

    Parse order: MITRE (primary) → OTRF → Splunk (enrichment).
    Results cached to KB_ENTRIES_PATH.

    Parameters
    ----------
    force : re-parse even if cache exists
    """
    if KB_ENTRIES_PATH.exists() and not force:
        logger.info("Loading cached ATT&CK KB from %s", KB_ENTRIES_PATH)
        with open(KB_ENTRIES_PATH, encoding="utf-8") as fh:
            raw = json.load(fh)
        return [KBEntry(**r) for r in raw]

    entries: list[KBEntry] = []
    entries.extend(_parse_mitre_attack())
    entries.extend(_parse_otrf_metadata())
    entries.extend(_parse_splunk_yaml())
    entries.extend(_parse_sigma_rules())

    merged = _merge_entries(entries)

    KB_ENTRIES_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(KB_ENTRIES_PATH, "w", encoding="utf-8") as fh:
        json.dump([asdict(e) for e in merged], fh, indent=2)
    logger.info("ATT&CK KB built: %d entries → %s", len(merged), KB_ENTRIES_PATH)
    return merged


# ---------------------------------------------------------------------------
# Primary source: official MITRE ATT&CK STIX bundle
# ---------------------------------------------------------------------------

def _get_stix_data():
    """
    Load MitreAttackData, downloading enterprise-attack.json once if absent.
    Caches to ATTACK_KB_DIR/enterprise-attack.json.
    """
    from mitreattack.stix20 import MitreAttackData

    if not STIX_CACHE_PATH.exists():
        logger.info("Downloading enterprise-attack.json from MITRE GitHub...")
        import urllib.request
        url = (
            "https://raw.githubusercontent.com/mitre/cti/master/"
            "enterprise-attack/enterprise-attack.json"
        )
        STIX_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        urllib.request.urlretrieve(url, STIX_CACHE_PATH)
        logger.info("Downloaded → %s", STIX_CACHE_PATH)

    return MitreAttackData(str(STIX_CACHE_PATH))


def _parse_mitre_attack() -> list[KBEntry]:
    """
    Extract all Windows-relevant ATT&CK techniques as KB entries.

    Each document contains:
      - Technique ID, name, tactic(s)
      - Official MITRE description
      - Data components that detect it (Sysmon event coverage)
      - Up to _MAX_PROCEDURES real adversary procedure examples
    """
    try:
        attack = _get_stix_data()
    except Exception as exc:
        logger.warning("Could not load MITRE ATT&CK data: %s", exc)
        return []

    entries: list[KBEntry] = []

    techniques = attack.get_techniques(remove_revoked_deprecated=True)

    for tech in techniques:
        props = tech.get("x_mitre_platforms", [])
        # Keep techniques relevant to Windows (or cross-platform)
        if props and not any(p in props for p in ("Windows", "Network", "PRE")):
            continue

        tid   = _extract_tid(tech)
        name  = tech.get("name", "")
        desc  = tech.get("description", "")
        stix_id = tech.get("id", "")

        # Tactics
        tactic_ids: list[str] = []
        try:
            tactics = attack.get_tactics_by_technique(tech)
            tactic_ids = [t.get("x_mitre_shortname", "") for t in tactics]
        except Exception:
            pass

        # Data components (translate to Sysmon event IDs in document text)
        data_components: list[str] = []
        try:
            dcs = attack.get_datacomponents_detecting_technique(tech)
            data_components = [dc.get("name", "") for dc in dcs if dc.get("name")]
        except Exception:
            pass

        # Procedure examples (real adversary usage)
        procedure_snippets: list[str] = []
        try:
            procs = attack.get_procedure_examples_by_technique(tech)
            for p in procs[:_MAX_PROCEDURES]:
                desc_p = p.get("description", "")
                if desc_p:
                    procedure_snippets.append(desc_p[:300])
        except Exception:
            pass

        document = _build_mitre_document(
            tid, name, tactic_ids, desc, data_components, procedure_snippets
        )

        entries.append(KBEntry(
            technique_id   = tid,
            technique_name = name,
            tactic_ids     = tactic_ids,
            description    = document,
            source         = "MITRE",
            source_id      = stix_id,
            keywords       = _extract_keywords(document),
        ))

    logger.info("MITRE ATT&CK: %d technique entries parsed", len(entries))
    return entries


def _extract_tid(tech) -> str:
    """Extract the T-code (e.g. 'T1003.001') from a STIX technique object."""
    ext_refs = tech.get("external_references", [])
    for ref in ext_refs:
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id", "")
    return tech.get("name", "")


def _build_mitre_document(
    tid: str,
    name: str,
    tactics: list[str],
    description: str,
    data_components: list[str],
    procedures: list[str],
) -> str:
    parts = [
        f"Technique: {tid} — {name}",
        f"Tactics: {', '.join(tactics) if tactics else 'unknown'}",
        f"Description: {description}",
    ]
    if data_components:
        parts.append(f"Detected via: {', '.join(data_components)}")
    if procedures:
        parts.append("Adversary procedure examples:")
        for p in procedures:
            parts.append(f"  - {p}")
    return "\n".join(p for p in parts if p.strip())


# ---------------------------------------------------------------------------
# OTRF metadata parser (enrichment)
# ---------------------------------------------------------------------------

def _parse_otrf_metadata() -> list[KBEntry]:
    entries: list[KBEntry] = []
    meta_dir = Path(OTRF_ATOMIC_META)
    if not meta_dir.exists():
        logger.warning("OTRF metadata dir not found: %s", meta_dir)
        return entries

    for yaml_path in meta_dir.glob("*.yaml"):
        try:
            with open(yaml_path, encoding="utf-8") as fh:
                doc = yaml.safe_load(fh)
        except Exception as exc:
            logger.debug("YAML parse error %s: %s", yaml_path.name, exc)
            continue

        if not isinstance(doc, dict):
            continue

        attack_mappings = doc.get("attack_mappings", []) or []
        for mapping in attack_mappings:
            technique = mapping.get("technique", "")
            sub       = mapping.get("sub-technique", "")
            tid       = f"{technique}.{sub}" if sub else technique
            tactics   = mapping.get("tactics", [])

            description = _build_otrf_description(doc, tid)
            entries.append(KBEntry(
                technique_id   = tid,
                technique_name = doc.get("title", ""),
                tactic_ids     = tactics if isinstance(tactics, list) else [tactics],
                description    = description,
                source         = "OTRF",
                source_id      = doc.get("id", yaml_path.stem),
                keywords       = _extract_keywords(description),
            ))
    logger.info("OTRF metadata: %d entries parsed", len(entries))
    return entries


def _build_otrf_description(doc: dict, tid: str) -> str:
    parts = [
        f"Technique: {tid}",
        f"Title: {doc.get('title', '')}",
        f"Description: {doc.get('description', '')}",
    ]
    simulation = doc.get("simulation", {}) or {}
    tools = simulation.get("tools", [])
    if tools:
        tool_names = [t.get("name", "") for t in tools if isinstance(t, dict)]
        parts.append(f"Simulation tools: {', '.join(tool_names)}")
    return "\n".join(p for p in parts if p.strip())


# ---------------------------------------------------------------------------
# Splunk YAML parser (enrichment)
# ---------------------------------------------------------------------------

def _parse_splunk_yaml() -> list[KBEntry]:
    entries: list[KBEntry] = []
    splunk_root = Path(SPLUNK_TECHNIQUES)
    if not splunk_root.exists():
        logger.warning("Splunk techniques dir not found: %s", splunk_root)
        return entries

    for yaml_path in sorted(splunk_root.rglob("*.yml")):
        try:
            with open(yaml_path, encoding="utf-8") as fh:
                doc = yaml.safe_load(fh)
        except Exception as exc:
            logger.debug("YAML parse error %s: %s", yaml_path.name, exc)
            continue

        if not isinstance(doc, dict):
            continue

        techniques = doc.get("mitre_technique", []) or []
        if isinstance(techniques, str):
            techniques = [techniques]

        description = _build_splunk_description(doc, yaml_path)
        for tid in techniques:
            entries.append(KBEntry(
                technique_id   = tid,
                technique_name = "",
                tactic_ids     = [],
                description    = description,
                source         = "Splunk",
                source_id      = str(doc.get("id", yaml_path.stem)),
                keywords       = _extract_keywords(description),
            ))

    malware_root = Path(SPLUNK_MALWARE_DIR)
    if malware_root.exists():
        for yaml_path in sorted(malware_root.rglob("*.yml")):
            try:
                with open(yaml_path, encoding="utf-8") as fh:
                    doc = yaml.safe_load(fh)
            except Exception:
                continue
            if not isinstance(doc, dict):
                continue
            techniques = doc.get("mitre_technique", []) or []
            if isinstance(techniques, str):
                techniques = [techniques]
            description = _build_splunk_description(doc, yaml_path)
            for tid in techniques:
                entries.append(KBEntry(
                    technique_id   = tid,
                    technique_name = "",
                    tactic_ids     = [],
                    description    = description,
                    source         = "Splunk-Malware",
                    source_id      = str(doc.get("id", yaml_path.stem)),
                    keywords       = _extract_keywords(description),
                ))

    logger.info("Splunk YAML: %d entries parsed", len(entries))
    return entries


def _build_splunk_description(doc: dict, path: Path) -> str:
    datasets = doc.get("datasets", []) or []
    ds_names = [d.get("name", "") for d in datasets if isinstance(d, dict)]
    parts = [
        f"Technique: {', '.join(doc.get('mitre_technique', []) or [])}",
        f"Description: {doc.get('description', '')}",
        f"Environment: {doc.get('environment', '')}",
        f"Datasets: {', '.join(ds_names)}",
    ]
    return "\n".join(p for p in parts if p.strip())


# ---------------------------------------------------------------------------
# SigmaHQ Windows rules parser (standalone enrichment)
# ---------------------------------------------------------------------------

def _parse_sigma_rules() -> list[KBEntry]:
    """
    Parse SigmaHQ Windows detection rules and convert to standalone KB entries.

    Downloads sigma-master.zip from GitHub once if not cached, then extracts
    only the rules/windows/ subtree.  Each rule that carries an ATT&CK T-code
    tag becomes a separate document — it is NOT merged into the MITRE entry so
    that BM25 can match on the rule's exact Sysmon indicator strings (process
    names, registry paths, command-line fragments).
    """
    import urllib.request
    import zipfile

    sigma_dir    = Path(SIGMA_RULES_DIR)
    zip_path     = sigma_dir / "sigma-master.zip"
    windows_dir  = sigma_dir / "sigma-master" / "rules" / "windows"

    if not windows_dir.exists():
        sigma_dir.mkdir(parents=True, exist_ok=True)
        if not zip_path.exists():
            logger.info("Downloading SigmaHQ rules from GitHub...")
            url = "https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip"
            urllib.request.urlretrieve(url, zip_path)
            logger.info("Downloaded → %s", zip_path)
        logger.info("Extracting Sigma rules/windows/ subtree...")
        with zipfile.ZipFile(zip_path) as zf:
            members = [m for m in zf.namelist() if "/rules/windows/" in m]
            zf.extractall(sigma_dir, members=members)
        logger.info("Extracted → %s", windows_dir)

    entries: list[KBEntry] = []

    for yaml_path in sorted(windows_dir.rglob("*.yml")):
        try:
            with open(yaml_path, encoding="utf-8") as fh:
                doc = yaml.safe_load(fh)
        except Exception as exc:
            logger.debug("Sigma YAML parse error %s: %s", yaml_path.name, exc)
            continue

        if not isinstance(doc, dict):
            continue

        # Skip deprecated / unsupported rules
        if str(doc.get("status", "")).lower() in _SIGMA_SKIP_STATUSES:
            continue

        # Extract ATT&CK technique IDs and tactic names from tags
        tids: list[str]      = []
        tactic_ids: list[str] = []
        for tag in (doc.get("tags") or []):
            tag_l = tag.lower()
            if tag_l.startswith("attack.t"):
                raw = tag[len("attack."):].upper()
                m = re.match(r"(T\d{4})(?:\.(\d{3}))?", raw)
                if m:
                    tids.append(m.group(1) + (f".{m.group(2)}" if m.group(2) else ""))
            elif tag_l.startswith("attack."):
                tactic_ids.append(tag[len("attack."):])

        if not tids:
            continue  # Only keep rules with ATT&CK technique mappings

        # Logsource → Sysmon EventID
        logsource = doc.get("logsource") or {}
        category  = logsource.get("category", "")
        eid       = _LOGSOURCE_TO_EID.get(category, 0)

        # Pull detection field values (process names, paths, hashes, etc.)
        detection   = doc.get("detection") or {}
        field_vals  = _extract_sigma_detection_fields(detection)

        title       = doc.get("title", yaml_path.stem)
        description = doc.get("description", "")

        doc_parts = [f"Sigma Detection Rule: {title}"]
        if eid:
            doc_parts.append(f"Sysmon EventID: {eid} (category: {category})")
        elif category:
            doc_parts.append(f"Log category: {category}")
        if description:
            doc_parts.append(f"Description: {description}")
        if field_vals:
            doc_parts.append("Detection indicators: " + "; ".join(field_vals[:25]))

        document = "\n".join(doc_parts)
        keywords  = list(set(tids + _extract_keywords(document)))

        # One entry per technique ID (a rule may cover multiple techniques)
        for tid_str in dict.fromkeys(tids):
            entries.append(KBEntry(
                technique_id   = tid_str,
                technique_name = title,
                tactic_ids     = tactic_ids,
                description    = document,
                source         = "Sigma",
                source_id      = yaml_path.stem,
                keywords       = keywords,
            ))

    logger.info("Sigma rules: %d entries parsed from %s", len(entries), windows_dir)
    return entries


def _extract_sigma_detection_fields(detection: dict) -> list[str]:
    """
    Walk a Sigma detection block and collect all non-wildcard string values.
    These are the concrete indicator strings (filenames, registry paths, etc.)
    that make Sigma rules valuable for BM25 keyword retrieval.
    """
    _SKIP_KEYS = {"condition", "timeframe", "keywords"}
    values: list[str] = []
    for key, val in detection.items():
        if key in _SKIP_KEYS:
            continue
        _collect_sigma_values(val, values)
    return values


def _collect_sigma_values(obj, out: list[str]) -> None:
    """Recursively collect non-trivial string leaves from a Sigma detection block."""
    if isinstance(obj, str):
        s = obj.strip()
        if s and s not in ("*", "?", "-", "null", ""):
            out.append(s)
    elif isinstance(obj, list):
        for item in obj:
            _collect_sigma_values(item, out)
    elif isinstance(obj, dict):
        for v in obj.values():
            _collect_sigma_values(v, out)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_keywords(text: str) -> list[str]:
    """Pull out T-code and TA-code references."""
    t_codes  = re.findall(r"T\d{4}(?:\.\d{3})?", text)
    ta_codes = re.findall(r"TA\d{4}", text)
    return list(set(t_codes + ta_codes))


def _merge_entries(entries: list[KBEntry]) -> list[KBEntry]:
    """
    For the same technique_id: keep MITRE as canonical, append OTRF/Splunk
    descriptions as additional context sections.
    Sigma entries are kept as standalone documents (not merged into MITRE).
    """
    mitre: dict[str, KBEntry]        = {}
    enrichment: dict[str, list[str]] = {}
    sigma_entries: list[KBEntry]     = []

    for e in entries:
        if e.source == "MITRE":
            mitre[e.technique_id] = e
        elif e.source == "Sigma":
            sigma_entries.append(e)
        else:
            enrichment.setdefault(e.technique_id, []).append(e.description)

    # Merge OTRF/Splunk enrichment into MITRE entries
    for tid, descs in enrichment.items():
        if tid in mitre:
            mitre[tid].description += "\n\n--- Observed scenarios ---\n" + "\n\n".join(descs)
            mitre[tid].keywords = list(set(mitre[tid].keywords + _extract_keywords("\n".join(descs))))
        else:
            # Technique not in MITRE data (e.g. malware-specific) — keep as-is
            first = next(
                e for e in entries
                if e.technique_id == tid and e.source not in ("MITRE", "Sigma")
            )
            combined = "\n\n".join(descs)
            first.description = combined
            first.keywords = list(set(first.keywords + _extract_keywords(combined)))
            mitre[tid] = first

    # Sigma entries are standalone: each rule is a separate document in ChromaDB
    # This gives BM25 direct access to Sysmon-specific process/registry indicators
    return list(mitre.values()) + sigma_entries
