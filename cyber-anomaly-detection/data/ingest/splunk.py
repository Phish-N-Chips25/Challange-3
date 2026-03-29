"""
Splunk Attack Data loader.

Dataset layout:
  attack_techniques/<T-code>/<scenario>/  → YAML + Sysmon .log files
  malware/<family>/<variant>/             → YAML + Sysmon .log files
  apt_simulations/<group>/                → placeholder only (no data)

This loader:
  1. Reads YAML descriptors to identify Sysmon-sourced .log files and labels.
  2. Parses each qualifying .log file as raw Sysmon XML.
  3. Maps to canonical schema; stores the label in `attck_technique`.

Sysmon filter: only files whose YAML lists
  sourcetype: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
are parsed. Security / other event logs are skipped.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Iterator

import pandas as pd
import yaml

from config import SPLUNK_TECHNIQUES, SPLUNK_MALWARE_DIR
from data.ingest.otrf import _parse_xml_bytes, _records_to_df

logger = logging.getLogger(__name__)

_SYSMON_SOURCETYPE = "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"


# ---------------------------------------------------------------------------
# Public iterators
# ---------------------------------------------------------------------------

def iter_techniques(
    technique_filter: list[str] | None = None,
    chunksize: int = 5_000,
) -> Iterator[pd.DataFrame]:
    """
    Yield canonical DataFrames for each ATT&CK technique scenario.

    Parameters
    ----------
    technique_filter : if provided, only process T-codes in this list
                       (e.g. ['T1003', 'T1055.001'])
    chunksize        : records per yielded DataFrame
    """
    root = Path(SPLUNK_TECHNIQUES)
    if not root.exists():
        logger.warning("Splunk techniques dir not found: %s", root)
        return

    for tcode_dir in sorted(root.iterdir()):
        if not tcode_dir.is_dir():
            continue
        tcode = tcode_dir.name  # e.g. "T1003"
        if technique_filter and tcode not in technique_filter:
            continue
        for scenario_dir in sorted(tcode_dir.iterdir()):
            if not scenario_dir.is_dir():
                continue
            logger.info("Splunk technique %s / %s", tcode, scenario_dir.name)
            yield from _load_scenario(
                scenario_dir, label=tcode, source_tag="Splunk", chunksize=chunksize
            )


def iter_malware(
    family_filter: list[str] | None = None,
    chunksize: int = 5_000,
) -> Iterator[pd.DataFrame]:
    """
    Yield canonical DataFrames for each malware family variant.

    Parameters
    ----------
    family_filter : if provided, only process families in this list
                    (e.g. ['conti', 'clop'])
    chunksize     : records per yielded DataFrame
    """
    root = Path(SPLUNK_MALWARE_DIR)
    if not root.exists():
        logger.warning("Splunk malware dir not found: %s", root)
        return

    for family_dir in sorted(root.iterdir()):
        if not family_dir.is_dir():
            continue
        if family_filter and family_dir.name not in family_filter:
            continue
        for variant_dir in sorted(family_dir.iterdir()):
            if not variant_dir.is_dir():
                continue
            logger.info("Splunk malware %s / %s", family_dir.name, variant_dir.name)
            yield from _load_scenario(
                variant_dir,
                label=family_dir.name,
                source_tag="Splunk-Malware",
                chunksize=chunksize,
            )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _load_scenario(
    scenario_dir: Path,
    label: str,
    source_tag: str,
    chunksize: int,
) -> Iterator[pd.DataFrame]:
    """
    Load all Sysmon .log files from one scenario directory.

    Uses the YAML descriptor to identify which .log files are Sysmon-sourced.
    If no YAML is present, all .log files in the directory are attempted.
    """
    sysmon_stems = _sysmon_stems_from_yaml(scenario_dir)

    log_files = sorted(scenario_dir.glob("*.log"))
    if not log_files:
        return

    records: list[dict] = []
    for log_path in log_files:
        if sysmon_stems and log_path.stem not in sysmon_stems:
            logger.debug("Skipping non-Sysmon log: %s", log_path.name)
            continue

        try:
            data = log_path.read_bytes()
        except OSError as exc:
            logger.warning("Cannot read %s: %s", log_path, exc)
            continue

        for rec in _parse_xml_bytes(data):
            rec["attck_technique"] = label
            records.append(rec)

        while len(records) >= chunksize:
            yield _records_to_df(records[:chunksize], source_tag, label=1)
            records = records[chunksize:]

    if records:
        yield _records_to_df(records, source_tag, label=1)


def _sysmon_stems_from_yaml(scenario_dir: Path) -> set[str]:
    """
    Return the set of .log file stems that are Sysmon-sourced, per the YAML descriptor.
    Returns an empty set if no YAML is found (caller falls back to all .log files).
    """
    yaml_files = list(scenario_dir.glob("*.yml"))
    if not yaml_files:
        return set()

    try:
        with open(yaml_files[0], encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
    except Exception as exc:
        logger.debug("YAML parse error in %s: %s", scenario_dir, exc)
        return set()

    if not isinstance(doc, dict):
        return set()

    stems: set[str] = set()
    for ds in doc.get("datasets", []) or []:
        if isinstance(ds, dict) and ds.get("sourcetype") == _SYSMON_SOURCETYPE:
            name = ds.get("name", "")
            if name:
                stems.add(name)
    return stems
