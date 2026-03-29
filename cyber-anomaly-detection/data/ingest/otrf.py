"""
OTRF dataset loader.

OTRF datasets are ZIP archives containing Sysmon events in NDJSON format.
This loader:
  1. Scans OTRF_COMPOUND_DIR for APT29, LSASS campaigns, and Log4Shell datasets.
  2. Scans OTRF atomic sub-directories for individual technique exercises.
  3. For each ZIP: extracts .json / .xml entries, parses Sysmon events.
  4. Maps to canonical schema; assigns ground-truth attck_technique + label
     for compound campaigns where the technique is known.

ATT&CK metadata is loaded separately by data/attack_kb/builder.py.

Public API
----------
iter_apt29()      — APT29 Day 1 & Day 2 (multi-technique, label=-1)
iter_compound()   — LSASS campaigns + Log4Shell (labelled, T-code assigned)
iter_atomic()     — 130+ individual technique exercises
"""
from __future__ import annotations

import json
import logging
import zipfile
from pathlib import Path
from typing import Iterator
from xml.etree import ElementTree as ET

import yaml

import pandas as pd

from config import OTRF_COMPOUND_DIR, OTRF_ATOMIC_META
from data.schema import enforce_schema

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Compound campaign registry
# Each entry: dirname → (source_tag, attck_technique, label)
# label=1 means confirmed malicious (technique is known ground-truth)
# ---------------------------------------------------------------------------
_COMPOUND_CAMPAIGNS: dict[str, tuple[str, str, int]] = {
    "LSASS_campaign_01": ("OTRF-LSASS", "T1003.001", 1),  # Metasploit logonpasswords
    "LSASS_campaign_02": ("OTRF-LSASS", "T1003.001", 1),  # procdump
    "LSASS_campaign_03": ("OTRF-LSASS", "T1003.001", 1),  # comsvcs MiniDump
    "LSASS_campaign_04": ("OTRF-LSASS", "T1003.001", 1),  # out-minidump
    "LSASS_campaign_05": ("OTRF-LSASS", "T1003.001", 1),  # sharpdump
    "LSASS_campaign_06": ("OTRF-LSASS", "T1003.001", 1),  # outflank-dumpert
    "LSASS_campaign_07": ("OTRF-LSASS", "T1003.001", 1),  # nanodump
    "Log4Shell":         ("OTRF-Log4Shell", "T1190", 1),  # CVE-2021-44228
}

# ZIP stems that are NOT Sysmon NDJSON (pcap, zeek, syslog, cloud telemetry)
_SKIP_STEMS = frozenset({"pcap", "zeek", "vminsights", "syslog", "securityauditing",
                          "microsoft365", "aad", "office"})

# Sysmon XML namespace
_NS = "http://schemas.microsoft.com/win/2004/08/events/event"

# XPath shortcuts
_SYS  = f"{{{_NS}}}System"
_DATA = f"{{{_NS}}}EventData"
_EVT  = f"{{{_NS}}}Event"


def iter_apt29(chunksize: int = 5_000) -> Iterator[pd.DataFrame]:
    """Yield canonical DataFrames from the APT29 compound dataset."""
    for day_dir in sorted(OTRF_COMPOUND_DIR.glob("apt29/day*")):
        for zip_path in sorted(day_dir.rglob("*.zip")):
            logger.info("Parsing OTRF ZIP: %s", zip_path.name)
            yield from _parse_zip(zip_path, chunksize=chunksize, source_tag="OTRF-APT29")


def iter_compound(
    campaign_filter: list[str] | None = None,
    chunksize: int = 5_000,
) -> Iterator[pd.DataFrame]:
    """
    Yield canonical DataFrames from all labelled compound OTRF campaigns.

    Covers LSASS credential-dumping campaigns (01–07, all T1003.001) and
    Log4Shell (T1190).  Each yielded chunk has ``attck_technique`` and
    ``label=1`` pre-assigned because the ground-truth technique is known.

    Skips APT29 (use iter_apt29), pcap/zeek/syslog/cloud archives, and
    any compound sub-directory not listed in _COMPOUND_CAMPAIGNS.

    Parameters
    ----------
    campaign_filter : optional list of directory names to restrict loading,
                      e.g. ['LSASS_campaign_01', 'LSASS_campaign_06']
    chunksize       : rows per yielded DataFrame chunk
    """
    for campaign_dir in sorted(OTRF_COMPOUND_DIR.iterdir()):
        if not campaign_dir.is_dir():
            continue
        name = campaign_dir.name
        if name not in _COMPOUND_CAMPAIGNS:
            continue
        if campaign_filter and name not in campaign_filter:
            continue

        source_tag, technique, label = _COMPOUND_CAMPAIGNS[name]

        for zip_path in sorted(campaign_dir.rglob("*.zip")):
            stem_lower = zip_path.stem.lower()
            if any(skip in stem_lower for skip in _SKIP_STEMS):
                logger.debug("Skipping non-Sysmon archive: %s", zip_path.name)
                continue
            logger.info("Parsing compound ZIP: %s [%s]", zip_path.name, technique)
            yield from _parse_zip(
                zip_path,
                chunksize=chunksize,
                source_tag=source_tag,
                attck_technique=technique,
                label=label,
            )


def _build_atomic_tcode_map() -> dict[str, str]:
    """
    Parse SDWIN*.yaml files in OTRF_ATOMIC_META and return a mapping of
    ZIP basename -> ATT&CK T-code (e.g. 'empire_dcsync_...zip' -> 'T1003.006').

    Only Windows metadata files (SDWIN prefix) are considered.
    Returns an empty dict if the metadata directory is missing or unreadable.
    """
    tcode_map: dict[str, str] = {}
    if not OTRF_ATOMIC_META.is_dir():
        logger.warning("OTRF_ATOMIC_META not found: %s", OTRF_ATOMIC_META)
        return tcode_map

    for yaml_path in sorted(OTRF_ATOMIC_META.glob("SDWIN*.yaml")):
        try:
            with open(yaml_path, encoding="utf-8") as fh:
                doc = yaml.safe_load(fh)
        except Exception as exc:
            logger.debug("Could not parse %s: %s", yaml_path.name, exc)
            continue

        mappings = doc.get("attack_mappings", [])
        if not mappings:
            continue

        m         = mappings[0]
        technique = str(m.get("technique", ""))
        sub       = m.get("sub-technique", "")
        tcode     = f"{technique}.{str(sub).zfill(3)}" if sub else technique

        for fentry in doc.get("files", []):
            link     = fentry.get("link", "")
            zip_name = link.rsplit("/", 1)[-1]
            if zip_name.endswith(".zip"):
                tcode_map[zip_name] = tcode

    logger.info("Atomic T-code map built: %d ZIPs mapped", len(tcode_map))
    return tcode_map


def iter_atomic(
    technique_filter: list[str] | None = None,
    platforms: list[str] | None = None,
    chunksize: int = 5_000,
) -> Iterator[pd.DataFrame]:
    """
    Yield canonical DataFrames from OTRF atomic datasets.

    T-codes are assigned automatically from the _metadata YAML files:
    events from labelled ZIPs get ``attck_technique`` and ``label=1``;
    events from the ~9 unlabelled ZIPs get ``label=-1``.

    Parameters
    ----------
    technique_filter : only process ZIPs whose T-code matches one of these
                       (e.g. ['T1003.001', 'T1055'])
    platforms        : sub-directories to scan; defaults to ['windows']
    """
    atomic_root = OTRF_COMPOUND_DIR.parent / "atomic"
    platforms   = platforms or ["windows"]
    tcode_map   = _build_atomic_tcode_map()

    for platform_dir in sorted(atomic_root.iterdir()):
        if not platform_dir.is_dir() or platform_dir.name not in platforms:
            continue
        for zip_path in sorted(platform_dir.rglob("*.zip")):
            technique = tcode_map.get(zip_path.name, "")
            if technique_filter and technique not in technique_filter:
                continue
            label = 1 if technique else -1
            logger.info("Parsing OTRF atomic ZIP: %s [%s]", zip_path.name, technique or "unlabelled")
            yield from _parse_zip(
                zip_path,
                chunksize=chunksize,
                source_tag="OTRF-Atomic",
                attck_technique=technique,
                label=label,
            )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _parse_zip(
    zip_path: Path,
    chunksize: int,
    source_tag: str,
    attck_technique: str = "",
    label: int = -1,
) -> Iterator[pd.DataFrame]:
    """Open a ZIP, find XML or NDJSON entries, parse Sysmon events, yield chunks."""
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            all_names  = zf.namelist()
            xml_names  = [n for n in all_names if n.lower().endswith(".xml")]
            json_names = [n for n in all_names if n.lower().endswith(".json")]

            if not xml_names and not json_names:
                return

            records: list[dict] = []

            for xml_name in xml_names:
                with zf.open(xml_name) as fh:
                    data = fh.read()
                records.extend(_parse_xml_bytes(data))
                if len(records) >= chunksize:
                    yield _records_to_df(records, source_tag, attck_technique, label)
                    records = []

            for json_name in json_names:
                with zf.open(json_name) as fh:
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            rec = _extract_json_event(json.loads(line))
                        except (ValueError, KeyError):
                            continue
                        if rec:
                            records.append(rec)
                        if len(records) >= chunksize:
                            yield _records_to_df(records, source_tag, attck_technique, label)
                            records = []

            if records:
                yield _records_to_df(records, source_tag, attck_technique, label)
    except (zipfile.BadZipFile, Exception) as exc:
        logger.warning("Failed to parse %s: %s", zip_path.name, exc)


def _parse_xml_bytes(data: bytes) -> list[dict]:
    """
    Parse a Windows Event XML blob into a list of flat dicts.
    Handles both single <Event> documents and <Events> wrapper roots.
    """
    records: list[dict] = []
    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        # Try wrapping in a root element for multi-event files
        try:
            root = ET.fromstring(b"<Events>" + data + b"</Events>")
        except ET.ParseError as exc:
            logger.debug("XML parse error: %s", exc)
            return records

    # Collect all <Event> elements
    events = root.findall(f".//{_EVT}") if root.tag != _EVT else [root]

    for event in events:
        rec = _extract_event(event)
        if rec:
            records.append(rec)
    return records


def _extract_event(event: ET.Element) -> dict | None:
    """Extract fields from a single <Event> element."""
    system = event.find(_SYS)
    if system is None:
        return None

    # Only keep Sysmon events (provider = Microsoft-Windows-Sysmon)
    provider = system.find(f"{{{_NS}}}Provider")
    if provider is not None:
        name = provider.get("Name", "")
        if "Sysmon" not in name:
            return None

    event_id_el = system.find(f"{{{_NS}}}EventID")
    event_id = int(event_id_el.text) if event_id_el is not None and event_id_el.text else -1

    time_created = system.find(f"{{{_NS}}}TimeCreated")
    utc_time = time_created.get("SystemTime", "") if time_created is not None else ""

    # Flatten EventData / Data[@Name] fields
    event_data = event.find(_DATA)
    data_fields: dict[str, str] = {}
    if event_data is not None:
        for data_el in event_data:
            name = data_el.get("Name", "")
            if name:
                data_fields[name] = data_el.text or ""

    rec = {
        "event_id": event_id,
        "utc_time": utc_time,
        "process_guid":    data_fields.get("ProcessGuid", ""),
        "process_id":      data_fields.get("ProcessId", -1),
        "image":           data_fields.get("Image", ""),
        "command_line":    data_fields.get("CommandLine", ""),
        "current_dir":     data_fields.get("CurrentDirectory", ""),
        "user":            data_fields.get("User", ""),
        "integrity_level": data_fields.get("IntegrityLevel", ""),
        "parent_guid":     data_fields.get("ParentProcessGuid", ""),
        "parent_id":       data_fields.get("ParentProcessId", -1),
        "parent_image":    data_fields.get("ParentImage", ""),
        "parent_cmdline":  data_fields.get("ParentCommandLine", ""),
        "image_loaded":    data_fields.get("ImageLoaded", ""),
        "signed":          data_fields.get("Signed", ""),
        "signature":       data_fields.get("Signature", ""),
        "sig_status":      data_fields.get("SignatureStatus", ""),
        "target_object":   data_fields.get("TargetObject", ""),
        "details":         data_fields.get("Details", ""),
        "target_image":    data_fields.get("TargetImage", ""),
        "granted_access":  data_fields.get("GrantedAccess", ""),
        "call_trace":      data_fields.get("CallTrace", ""),
        "dest_ip":         data_fields.get("DestinationIp", ""),
        "dest_port":       data_fields.get("DestinationPort", -1),
        "dest_hostname":   data_fields.get("DestinationHostname", ""),
        "target_filename": data_fields.get("TargetFilename", ""),
        "event_type":      data_fields.get("EventType", ""),
        "pipe_name":       data_fields.get("PipeName", ""),
        "query_name":      data_fields.get("QueryName", ""),
        "query_results":   data_fields.get("QueryResults", ""),
        "rule_name":       data_fields.get("RuleName", ""),
        "hashes":          data_fields.get("Hashes", ""),
        "label":           -1,  # unknown for OTRF raw; set by attack_kb after mapping
    }
    return rec


def _extract_json_event(ev: dict) -> dict | None:
    """
    Map a flat OTRF NDJSON event (Mordor/Sigma format) to the canonical schema.

    OTRF JSON uses top-level keys directly (e.g. 'Image', 'EventID') rather than
    the nested XML EventData structure.  For process-access events (EID 10) the
    source process fields carry a 'Source' prefix; we fall back to those when the
    generic field is absent.
    """
    # Only keep Sysmon events — require SourceName or Channel to identify Sysmon.
    # Events with neither (e.g. AWS CloudTrail, Linux auditd) are silently dropped.
    source_name = ev.get("SourceName", ev.get("source_name", ""))
    channel     = ev.get("Channel",    ev.get("channel",    ""))
    if "Sysmon" not in source_name and "Sysmon" not in channel:
        return None

    event_id = ev.get("EventID", ev.get("event_id", -1))
    try:
        event_id = int(event_id)
    except (TypeError, ValueError):
        event_id = -1

    def get(*keys: str, default: object = "") -> object:
        for k in keys:
            v = ev.get(k)
            if v is not None:
                return v
        return default

    # EventType in NDJSON is Sysmon severity ("INFO"), not the registry op.
    # For registry events (EID 12/13/14) the operation is in 'EventType' too,
    # but its value will be "SetValue" / "DeleteValue" etc. — keep as-is.
    event_type_raw = str(get("EventType", default=""))
    event_type = "" if event_type_raw.upper() in ("INFO", "ERROR", "WARNING", "") else event_type_raw

    return {
        "event_id":       event_id,
        "utc_time":       get("UtcTime", "EventTime", "@timestamp"),
        "process_guid":   get("ProcessGuid", "SourceProcessGUID"),
        "process_id":     get("ProcessId", "SourceProcessId", default=-1),
        "image":          get("Image", "SourceImage"),
        "command_line":   get("CommandLine"),
        "current_dir":    get("CurrentDirectory"),
        "user":           get("User", "AccountName"),
        "integrity_level":get("IntegrityLevel"),
        "parent_guid":    get("ParentProcessGuid"),
        "parent_id":      get("ParentProcessId", default=-1),
        "parent_image":   get("ParentImage"),
        "parent_cmdline": get("ParentCommandLine"),
        "image_loaded":   get("ImageLoaded"),
        "signed":         get("Signed"),
        "signature":      get("Signature"),
        "sig_status":     get("SignatureStatus"),
        "target_object":  get("TargetObject"),
        "details":        get("Details"),
        "target_image":   get("TargetImage"),
        "granted_access": get("GrantedAccess"),
        "call_trace":     get("CallTrace"),
        "dest_ip":        get("DestinationIp"),
        "dest_port":      get("DestinationPort", default=-1),
        "dest_hostname":  get("DestinationHostname"),
        "target_filename":get("TargetFilename"),
        "event_type":     event_type,
        "pipe_name":      get("PipeName"),
        "query_name":     get("QueryName"),
        "query_results":  get("QueryResults"),
        "rule_name":      get("RuleName"),
        "hashes":         get("Hashes"),
        "label":          -1,
    }


def _records_to_df(
    records: list[dict],
    source_tag: str,
    attck_technique: str = "",
    label: int = -1,
) -> pd.DataFrame:
    df = pd.DataFrame(records)
    df["dataset_source"] = source_tag
    if attck_technique:
        df["attck_technique"] = attck_technique
    if label != -1:
        df["label"] = label
    return enforce_schema(df)
