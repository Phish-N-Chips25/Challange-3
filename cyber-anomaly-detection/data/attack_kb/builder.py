"""
ATT&CK Knowledge Base builder.

Parses:
  1. OTRF atomic _metadata YAML files  → technique + description + T-codes
  2. Splunk attack_techniques YAML files → technique + description + T-codes

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
    SPLUNK_TECHNIQUES,
    SPLUNK_MALWARE_DIR,
)

logger = logging.getLogger(__name__)

KB_ENTRIES_PATH = Path(ATTACK_KB_DIR) / "entries.json"


@dataclass
class KBEntry:
    technique_id: str          # e.g. "T1003.001"
    technique_name: str        # human-readable name (may be empty if not in YAML)
    tactic_ids: list[str]      # e.g. ["TA0006"]
    description: str           # used as RAG document text
    source: str                # "OTRF" | "Splunk"
    source_id: str             # YAML id field
    keywords: list[str] = field(default_factory=list)   # extra search terms


def build_kb(force: bool = False) -> list[KBEntry]:
    """
    Parse all YAML metadata and return a list of KBEntry objects.
    Results are cached to KB_ENTRIES_PATH.

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
    entries.extend(_parse_otrf_metadata())
    entries.extend(_parse_splunk_yaml())

    # Deduplicate by technique_id — keep union of descriptions
    merged = _merge_entries(entries)

    KB_ENTRIES_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(KB_ENTRIES_PATH, "w", encoding="utf-8") as fh:
        json.dump([asdict(e) for e in merged], fh, indent=2)
    logger.info("ATT&CK KB built: %d entries → %s", len(merged), KB_ENTRIES_PATH)
    return merged


# ---------------------------------------------------------------------------
# OTRF metadata parser
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
# Splunk YAML parser
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

    # Also parse malware-focused YAMLs
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
# Helpers
# ---------------------------------------------------------------------------

def _extract_keywords(text: str) -> list[str]:
    """Pull out T-code references and notable tool/tactic names."""
    t_codes = re.findall(r"T\d{4}(?:\.\d{3})?", text)
    ta_codes = re.findall(r"TA\d{4}", text)
    return list(set(t_codes + ta_codes))


def _merge_entries(entries: list[KBEntry]) -> list[KBEntry]:
    """
    For the same technique_id from multiple sources, concatenate descriptions.
    """
    by_tid: dict[str, KBEntry] = {}
    for e in entries:
        if e.technique_id not in by_tid:
            by_tid[e.technique_id] = e
        else:
            existing = by_tid[e.technique_id]
            existing.description = existing.description + "\n\n---\n\n" + e.description
            existing.keywords = list(set(existing.keywords + e.keywords))
            if not existing.technique_name and e.technique_name:
                existing.technique_name = e.technique_name
            if not existing.tactic_ids and e.tactic_ids:
                existing.tactic_ids = e.tactic_ids
    return list(by_tid.values())
