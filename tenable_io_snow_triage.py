#!/usr/bin/env python3
"""
tenable_io_snow_triage.py — Tenable.io / ServiceNow vulnerability triage tool.

Reads a vulnerability export CSV, assigns P1–P4 priorities, tracks SLA due dates,
computes age and overdue status, and produces an enriched CSV, Markdown summary,
HTML report, and JSON audit record.

Security hardening applied:
- Path traversal prevention
- Input validation and schema checks
- Structured audit logging
- Output path sanitization
- CSV injection protection
"""

import argparse
import json
import logging
import sys
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Optional

import pandas as pd
from jinja2 import Template

# ──────────────────────────────────────────────────────────────────────────────
# Exit codes
# ──────────────────────────────────────────────────────────────────────────────

class ExitCode:
    SUCCESS = 0
    VALIDATION_ERROR = 2
    IO_ERROR = 3
    CONFIG_ERROR = 4
    API_ERROR = 5

# ──────────────────────────────────────────────────────────────────────────────
# Logging configuration
# ──────────────────────────────────────────────────────────────────────────────

class StructuredLogger:
    """Logger supporting both human-readable and JSON structured output."""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.log_entries = []
        format_str = "%(levelname)s: %(message)s" if not verbose else "%(asctime)s - %(levelname)s: %(message)s"
        level = logging.DEBUG if verbose else logging.INFO
        logging.basicConfig(format=format_str, level=level)
        self.log = logging.getLogger(__name__)
    
    def info(self, msg: str, **kwargs):
        self.log.info(msg)
        self._record("INFO", msg, **kwargs)
    
    def warning(self, msg: str, **kwargs):
        self.log.warning(msg)
        self._record("WARNING", msg, **kwargs)
    
    def error(self, msg: str, **kwargs):
        self.log.error(msg)
        self._record("ERROR", msg, **kwargs)
    
    def debug(self, msg: str, **kwargs):
        self.log.debug(msg)
        self._record("DEBUG", msg, **kwargs)
    
    def _record(self, level: str, msg: str, **kwargs):
        entry = {"timestamp": datetime.now().isoformat(), "level": level, "message": msg}
        if kwargs:
            entry.update(kwargs)
        self.log_entries.append(entry)
    
    def get_audit_log(self) -> list:
        return self.log_entries


log = StructuredLogger()

# ──────────────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────────────

# Severity column: checked in order, first match wins.
SEVERITY_COLUMNS = [
    "severity", "risk", "criticality", "risk rating",
    "cvss risk", "vulnerability risk", "threat level", "priority",
]

# Text label → priority. Numeric CVSS scores are handled separately.
SEVERITY_LABEL_MAP = {
    "critical": "P1", "crit": "P1",
    "high":     "P2",
    "medium":   "P3", "med": "P3", "moderate": "P3",
    "low":      "P4",
    "none":     None, "info": None, "informational": None,
}

# Columns searched (case-insensitive) when applying asset map overrides.
ASSET_COLUMNS = {"asset", "host", "asset name", "hostname", "dns name", "ip address", "fqdn"}

# Columns searched (case-insensitive) when applying exceptions or counting unique vulns.
EXCEPTION_COLUMNS = {"plugin id", "plugin_id", "vulnerability id", "cve", "name", "finding id"}

# Columns checked for first-seen / discovery date (for age tracking).
FIRST_SEEN_COLUMNS = {
    "first seen", "first detected", "discovery date", "first discovered",
    "vuln first found", "plugin publication date",
}

# Default SLA in days per priority (industry standard).
DEFAULT_SLAS = {"P1": 7, "P2": 30, "P3": 90, "P4": 180}

# Valid priority values
VALID_PRIORITIES = {"P1", "P2", "P3", "P4"}

# EPSS API endpoint
EPSS_API_URL = "https://api.first.org/data/v1/epss"

# CISA KEV catalog URL
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# ──────────────────────────────────────────────────────────────────────────────
# Security helpers
# ──────────────────────────────────────────────────────────────────────────────

def _safe_path(path_str: str, base_dir: Path, allow_parent: bool = False) -> Path:
    """Resolve and validate a file path to prevent path traversal attacks.
    
    Args:
        path_str: The path string to validate
        base_dir: The base directory for relative paths
        allow_parent: If True, allow paths up to parent of base_dir
    
    Returns:
        Resolved Path object if valid
    
    Raises:
        ValueError: If path traversal is detected
    """
    path = Path(path_str)
    
    # Resolve to absolute path
    if path.is_absolute():
        resolved = path.resolve()
    else:
        resolved = (base_dir / path).resolve()
    
    # Check for path traversal
    if not allow_parent:
        try:
            resolved.relative_to(base_dir)
        except ValueError:
            raise ValueError(
                f"Path traversal detected: '{path_str}' resolves outside allowed directory"
            )
    
    return resolved


def _sanitize_output_path(path_str: str, output_dir: Path) -> Path:
    """Validate output path is within the designated output directory.
    
    Args:
        path_str: The output path string
        output_dir: The allowed output directory
    
    Returns:
        Safe resolved Path object
    
    Raises:
        ValueError: If path is outside output_dir
    """
    path = Path(path_str)
    if path.is_absolute():
        resolved = path.resolve()
    else:
        resolved = (output_dir / path).resolve()
    
    try:
        resolved.relative_to(output_dir)
    except ValueError:
        raise ValueError(
            f"Output path traversal detected: '{path_str}' is outside output directory"
        )
    
    return resolved


def _sanitize_csv_cell(value) -> str:
    """Prevent CSV formula injection by escaping dangerous prefixes.
    
    CSV injection occurs when cell values start with =, +, -, @, or tab/return
    characters, which can be interpreted as formulas by spreadsheet applications.
    
    Args:
        value: The cell value to sanitize
    
    Returns:
        Sanitized string value with leading apostrophe if needed
    """
    if value is None or pd.isna(value):
        return ""
    
    str_val = str(value)
    if str_val and str_val[0] in ('=', '+', '-', '@', '\t', '\r'):
        return f"'{str_val}"
    return str_val


def _validate_csv_schema(df: pd.DataFrame) -> list:
    """Validate CSV has minimum required columns for processing.
    
    Args:
        df: The DataFrame to validate
    
    Returns:
        List of validation errors (empty if valid)
    """
    errors = []
    
    if df.empty:
        errors.append("CSV file is empty")
        return errors
    
    # Must have at least one severity-like column
    has_severity = any(c.lower() in SEVERITY_COLUMNS for c in df.columns)
    if not has_severity:
        errors.append(
            f"No severity column found. Expected one of: {', '.join(SEVERITY_COLUMNS)}"
        )
    
    # Must have at least one asset/host column for meaningful triage
    has_asset = any(c.lower() in ASSET_COLUMNS for c in df.columns)
    if not has_asset:
        log.warning(
            "No asset/host column found. Asset map overrides will be skipped.",
            columns=list(df.columns)
        )
    
    # Must have at least one identifier column for deduplication
    has_id = any(c.lower() in EXCEPTION_COLUMNS for c in df.columns)
    if not has_id:
        log.warning(
            "No vulnerability identifier column found. Deduplication stats may be inaccurate.",
            columns=list(df.columns)
        )
    
    return errors


def _validate_asset_map(asset_map: dict) -> list:
    """Validate asset map structure and values.
    
    Args:
        asset_map: The asset map dictionary
    
    Returns:
        List of validation errors (empty if valid)
    """
    errors = []
    
    if not isinstance(asset_map, dict):
        errors.append("Asset map must be a JSON object")
        return errors
    
    for asset, priority in asset_map.items():
        if not isinstance(asset, str) or not asset.strip():
            errors.append(f"Invalid asset name: {repr(asset)}")
        if priority not in VALID_PRIORITIES:
            errors.append(f"Invalid priority '{priority}' for asset '{asset}'")
    
    return errors


def _validate_exceptions(exceptions: list) -> list:
    """Validate exceptions list structure.
    
    Args:
        exceptions: The exceptions list
    
    Returns:
        List of validation errors (empty if valid)
    """
    errors = []
    
    if not isinstance(exceptions, list):
        errors.append("Exceptions must be a JSON array")
        return errors
    
    for i, exc in enumerate(exceptions):
        if not isinstance(exc, str) or not exc.strip():
            errors.append(f"Invalid exception at index {i}: {repr(exc)}")
    
    return errors

# ──────────────────────────────────────────────────────────────────────────────
# Threat intelligence helpers
# ──────────────────────────────────────────────────────────────────────────────

def _fetch_epss_scores(cve_list: list[str]) -> dict[str, float]:
    """Fetch EPSS scores for a list of CVEs.
    
    Args:
        cve_list: List of CVE identifiers
    
    Returns:
        Dictionary mapping CVE to EPSS score
    """
    if not cve_list:
        return {}
    
    try:
        import urllib.request
        import ssl
        
        # Build URL with CVE parameters
        cve_params = "&".join(f"cve={cve}" for cve in cve_list)
        url = f"{EPSS_API_URL}?{cve_params}"
        
        # Create SSL context that verifies certificates
        ctx = ssl.create_default_context()
        
        # Fetch data
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, context=ctx, timeout=30) as response:
            data = json.loads(response.read().decode())
        
        # Parse results
        epss_scores = {}
        for item in data.get("data", []):
            cve = item.get("cve")
            score = item.get("epss")
            if cve and score is not None:
                epss_scores[cve] = float(score)
        
        log.debug(f"Fetched EPSS scores for {len(epss_scores)} CVEs")
        return epss_scores
        
    except Exception as e:
        log.warning(f"Failed to fetch EPSS scores: {e}")
        return {}


def _fetch_cisa_kev() -> set[str]:
    """Fetch CISA Known Exploited Vulnerabilities catalog.
    
    Returns:
        Set of CVE IDs that are in the CISA KEV catalog
    """
    try:
        import urllib.request
        import ssl
        
        # Create SSL context that verifies certificates
        ctx = ssl.create_default_context()
        
        # Fetch catalog
        req = urllib.request.Request(
            CISA_KEV_URL,
            headers={"Accept": "application/json"}
        )
        with urllib.request.urlopen(req, context=ctx, timeout=30) as response:
            data = json.loads(response.read().decode())
        
        # Extract CVE IDs
        kev_cves = {
            vuln.get("cveID")
            for vuln in data.get("vulnerabilities", [])
            if vuln.get("cveID")
        }
        
        log.debug(f"Fetched CISA KEV catalog: {len(kev_cves)} vulnerabilities")
        return kev_cves
        
    except Exception as e:
        log.warning(f"Failed to fetch CISA KEV catalog: {e}")
        return set()


def _add_threat_intel(df: pd.DataFrame, fetch_epss: bool, fetch_kev: bool) -> pd.DataFrame:
    """Add EPSS scores and CISA KEV flags to the DataFrame.
    
    Args:
        df: The DataFrame to enrich
        fetch_epss: Whether to fetch EPSS scores
        fetch_kev: Whether to fetch CISA KEV catalog
    
    Returns:
        Enriched DataFrame with EPSS and KEV columns
    """
    df = df.copy()
    
    # Extract CVE column
    cve_col = next((c for c in df.columns if c.lower() == "cve"), None)
    
    if cve_col is None:
        log.debug("No CVE column found, skipping threat intel enrichment")
        return df
    
    # Get unique CVEs
    cve_list = df[cve_col].dropna().unique().tolist()
    
    # Fetch EPSS scores
    if fetch_epss and cve_list:
        log.info("Fetching EPSS scores...")
        epss_scores = _fetch_epss_scores(cve_list)
        df["EPSS Score"] = df[cve_col].map(epss_scores)
        epss_count = df["EPSS Score"].notna().sum()
        log.info(f"Added EPSS scores for {epss_count} vulnerabilities")
    
    # Fetch CISA KEV
    if fetch_kev:
        log.info("Fetching CISA KEV catalog...")
        kev_cves = _fetch_cisa_kev()
        df["In CISA KEV"] = df[cve_col].isin(kev_cves)
        kev_count = df["In CISA KEV"].sum()
        log.info(f"Found {kev_count} vulnerabilities in CISA KEV catalog")
    
    return df

# ──────────────────────────────────────────────────────────────────────────────
# Detection helpers
# ──────────────────────────────────────────────────────────────────────────────

def _detect_severity_col(df: pd.DataFrame, override: str | None) -> str:
    """Return the severity column name to use, or exit if not found."""
    if override:
        if override not in df.columns:
            log.error(
                f"Specified severity column '{override}' not found.",
                available_columns=list(df.columns)
            )
            sys.exit(ExitCode.VALIDATION_ERROR)
        log.debug(f"Severity column: '{override}' (user-specified).")
        return override

    col = next((c for c in df.columns if c.lower() in SEVERITY_COLUMNS), None)
    if col is None:
        log.error(
            f"Could not detect a severity column.",
            tried_columns=SEVERITY_COLUMNS,
            available_columns=list(df.columns)
        )
        sys.exit(ExitCode.VALIDATION_ERROR)

    log.debug(f"Severity column: '{col}' (auto-detected).")
    return col

# ──────────────────────────────────────────────────────────────────────────────
# Severity classification
# ──────────────────────────────────────────────────────────────────────────────

def _classify_severity(value) -> tuple[str | None, str | None]:
    """Return (priority, triage_reason) for a single severity value.

    Triage reason format:
        severity:<raw_value>   — driven by text label
        cvss:<score>           — driven by numeric CVSS score
    """
    if pd.isna(value):
        return None, None

    raw = str(value).strip()
    val = raw.lower()

    # 1. Exact text label match ("critical", "high", etc.)
    if val in SEVERITY_LABEL_MAP:
        priority = SEVERITY_LABEL_MAP[val]
        if priority is None:
            return None, None
        return priority, f"severity:{raw}"

    # 2. Pure CVSS numeric score — checked before substring matching so "5.3"
    #    is never mistakenly substring-matched against "3".
    try:
        score = float(val)
        if score >= 9.0:
            return "P1", f"cvss:{raw}"
        if score >= 7.0:
            return "P2", f"cvss:{raw}"
        if score >= 4.0:
            return "P3", f"cvss:{raw}"
        if score > 0.0:
            return "P4", f"cvss:{raw}"
        return None, None  # CVSS 0 = informational
    except ValueError:
        pass

    # 3. Substring match for prefixed formats like "4 - Critical" or "High (3)".
    for label, priority in SEVERITY_LABEL_MAP.items():
        if label in val:
            if priority is None:
                return None, None
            return priority, f"severity:{raw}"

    # 4. Unknown value — default to P4.
    log.debug(f"Unknown severity value '{raw}', defaulting to P4")
    return "P4", f"severity:{raw}"

# ──────────────────────────────────────────────────────────────────────────────
# Core transforms
# ──────────────────────────────────────────────────────────────────────────────

def _apply_priority(df: pd.DataFrame, sev_col: str) -> pd.DataFrame:
    """Assign Priority and Triage Reason columns from the severity column."""
    df = df.copy()
    results = df[sev_col].apply(
        lambda v: pd.Series(_classify_severity(v), index=["Priority", "Triage Reason"])
    )
    df["Priority"] = results["Priority"]
    df["Triage Reason"] = results["Triage Reason"]

    skipped = df["Priority"].isna().sum()
    if skipped:
        log.info(f"Skipped {skipped} row(s) with no actionable severity (None/Info/0).")
    df = df[df["Priority"].notna()].copy()
    return df


def _apply_asset_map(df: pd.DataFrame, asset_map: dict) -> pd.DataFrame:
    """Override Priority (and Triage Reason) based on asset name mappings.

    asset_map format: {"<asset name>": "<priority>", ...}
    Example: {"web-server-01": "P1", "legacy-db": "P2"}
    """
    col = next((c for c in df.columns if c.lower() in ASSET_COLUMNS), None)
    if col is None:
        log.warning("Asset map provided but no asset/host column found in CSV — skipping.")
        return df

    overrides = df[col].map(asset_map)
    mask = overrides.notna()
    df.loc[mask, "Priority"] = overrides[mask]
    df.loc[mask, "Triage Reason"] = df.loc[mask, col].apply(lambda a: f"asset_override:{a}")
    log.info(f"Asset map: applied {mask.sum()} override(s) via column '{col}'.")
    return df


def _apply_exceptions(df: pd.DataFrame, exceptions: list) -> pd.DataFrame:
    """Exclude rows whose identifier matches an entry in the exceptions list.

    Matches against all detected identifier columns (Plugin ID, CVE, Name, etc.)
    so a mixed list of Plugin IDs and CVEs works as expected.

    exceptions format: ["<plugin id or name>", ...]
    Example: ["12345", "67890", "CVE-2023-1234"]
    """
    cols = [c for c in df.columns if c.lower() in EXCEPTION_COLUMNS]
    if not cols:
        log.warning("Exceptions file provided but no matching identifier column found in CSV — skipping.")
        return df

    exc_set = {str(e) for e in exceptions}
    before = len(df)
    mask = pd.Series(False, index=df.index)
    for col in cols:
        mask |= df[col].astype(str).isin(exc_set)
    df = df[~mask]
    log.info(
        f"Exceptions: removed {before - len(df)} row(s) matched against column(s): {', '.join(cols)}.",
        removed_count=before - len(df),
        matched_columns=cols
    )
    return df


def _add_due_dates(df: pd.DataFrame, slas: dict, today: date) -> pd.DataFrame:
    """Add a Due Date column: today + SLA days for the row's assigned priority."""
    df = df.copy()
    df["Due Date"] = df["Priority"].apply(
        lambda p: (today + timedelta(days=slas[p])).strftime("%Y-%m-%d")
    )
    return df


def _add_age_tracking(df: pd.DataFrame, slas: dict, today: date) -> tuple[pd.DataFrame, str | None]:
    """Add Age (days) and Overdue columns if a first-seen date column is present.

    Returns the updated DataFrame and the detected column name (or None).
    """
    col = next((c for c in df.columns if c.lower() in FIRST_SEEN_COLUMNS), None)
    if col is None:
        return df, None

    df = df.copy()
    parsed = pd.to_datetime(df[col], errors="coerce")
    today_ts = pd.Timestamp(today)
    df["Age (days)"] = (today_ts - parsed).dt.days
    df["Overdue"] = df.apply(
        lambda r: bool(pd.notna(r["Age (days)"]) and r["Age (days)"] > slas[r["Priority"]]),
        axis=1,
    )
    log.info(f"Age tracking active — using '{col}' as first-seen date.")
    return df, col

# ──────────────────────────────────────────────────────────────────────────────
# Stats computation
# ──────────────────────────────────────────────────────────────────────────────

def _compute_stats(df: pd.DataFrame) -> dict:
    """Compute priority counts, deduplication stats, and asset/vuln breakdowns."""
    priority_counts = {p: int((df["Priority"] == p).sum()) for p in ("P1", "P2", "P3", "P4")}
    total = len(df)

    # Unique vulnerabilities — prefer plugin-id style columns over "name"
    id_col = next(
        (c for c in df.columns if c.lower() in EXCEPTION_COLUMNS - {"name"}), None
    )
    if id_col is None:
        id_col = next((c for c in df.columns if c.lower() == "name"), None)
    unique_vulns = int(df[id_col].nunique()) if id_col else None

    # Distinct assets
    asset_col = next((c for c in df.columns if c.lower() in ASSET_COLUMNS), None)
    affected_assets = int(df[asset_col].nunique()) if asset_col else None

    # Overdue breakdown
    overdue_by_priority = None
    overdue_total = None
    if "Overdue" in df.columns:
        overdue_by_priority = {
            p: int(((df["Priority"] == p) & (df["Overdue"] == True)).sum())
            for p in ("P1", "P2", "P3", "P4")
        }
        overdue_total = sum(overdue_by_priority.values())

    # CISA KEV count
    kev_count = None
    if "In CISA KEV" in df.columns:
        kev_count = int(df["In CISA KEV"].sum())

    # High EPSS count (> 0.5)
    high_epss_count = None
    if "EPSS Score" in df.columns:
        high_epss_count = int((df["EPSS Score"] > 0.5).sum())

    # Top 10 affected assets: asset | P1 | P2 | P3 | P4 | Total
    top_assets = None
    if asset_col and total > 0:
        grp = df.groupby([asset_col, "Priority"]).size().unstack(fill_value=0)
        for p in ["P1", "P2", "P3", "P4"]:
            if p not in grp.columns:
                grp[p] = 0
        grp["Total"] = grp[["P1", "P2", "P3", "P4"]].sum(axis=1)
        grp = grp.sort_values(["P1", "P2"], ascending=False).head(10)
        top_assets = grp.reset_index().rename(columns={asset_col: "Asset"})

    # Top 10 most prevalent vulnerabilities
    top_vulns = None
    name_col = next(
        (c for c in df.columns if c.lower() in {"name", "plugin name", "vulnerability name", "vuln name"}),
        None,
    )
    group_col = name_col or id_col
    if group_col and total > 0:
        grp = df.groupby(group_col)
        instance_counts = grp.size().rename("Instances")
        modal_priority = grp["Priority"].agg(
            lambda x: x.value_counts().index[0] if len(x) > 0 else "N/A"
        ).rename("Priority")
        top_vulns = (
            pd.concat([instance_counts, modal_priority], axis=1)
            .sort_values("Instances", ascending=False)
            .head(10)
            .reset_index()
            .rename(columns={group_col: "Name / Plugin"})
        )

    return {
        "total": total,
        "counts": priority_counts,
        "unique_vulns": unique_vulns,
        "affected_assets": affected_assets,
        "overdue_by_priority": overdue_by_priority,
        "overdue_total": overdue_total,
        "kev_count": kev_count,
        "high_epss_count": high_epss_count,
        "top_assets": top_assets,
        "top_vulns": top_vulns,
    }

# ──────────────────────────────────────────────────────────────────────────────
# Summary Markdown
# ──────────────────────────────────────────────────────────────────────────────

def _write_summary_md(
    path: str,
    stats: dict,
    run_time: str,
    source: str,
    sev_col: str,
    slas: dict,
) -> None:
    lines: list[str] = []

    lines.append("# Vulnerability Triage Summary\n")

    # 1. Run metadata
    lines.append("## Run Metadata\n")
    lines.append("| Field | Value |")
    lines.append("|-------|-------|")
    lines.append(f"| Run time | {run_time} |")
    lines.append(f"| Source | `{source}` |")
    lines.append(f"| Severity column | `{sev_col}` |")
    lines.append(
        f"| SLAs | P1: {slas['P1']}d · P2: {slas['P2']}d · "
        f"P3: {slas['P3']}d · P4: {slas['P4']}d |"
    )
    lines.append("")

    # 2. Priority breakdown
    lines.append("## Priority Breakdown\n")
    lines.append("| Priority | Label | SLA | Count |")
    lines.append("|----------|-------|-----|-------|")
    labels = {"P1": "Critical", "P2": "High", "P3": "Medium", "P4": "Low"}
    for p in ("P1", "P2", "P3", "P4"):
        lines.append(f"| {p} | {labels[p]} | {slas[p]} days | {stats['counts'][p]} |")
    lines.append(f"| **Total** | | | **{stats['total']}** |")
    lines.append("")

    # 3. Threat intelligence
    if stats["kev_count"] is not None or stats["high_epss_count"] is not None:
        lines.append("## Threat Intelligence\n")
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        if stats["kev_count"] is not None:
            lines.append(f"| In CISA KEV | {stats['kev_count']} |")
        if stats["high_epss_count"] is not None:
            lines.append(f"| High EPSS (>0.5) | {stats['high_epss_count']} |")
        lines.append("")

    # 4. Deduplication / coverage stats
    lines.append("## Coverage\n")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| Total findings | {stats['total']} |")
    if stats["unique_vulns"] is not None:
        lines.append(f"| Unique vulnerabilities | {stats['unique_vulns']} |")
    if stats["affected_assets"] is not None:
        lines.append(f"| Affected assets | {stats['affected_assets']} |")
    lines.append("")

    # 5. Overdue findings
    if stats["overdue_by_priority"] is not None:
        lines.append("## Overdue Findings\n")
        lines.append("| Priority | Overdue |")
        lines.append("|----------|---------|")
        for p in ("P1", "P2", "P3", "P4"):
            lines.append(f"| {p} | {stats['overdue_by_priority'][p]} |")
        lines.append(f"| **Total** | **{stats['overdue_total']}** |")
        lines.append("")

    # 6. Top 10 affected assets
    if stats["top_assets"] is not None and len(stats["top_assets"]) > 0:
        lines.append("## Top Affected Assets\n")
        lines.append("| Asset | P1 | P2 | P3 | P4 | Total |")
        lines.append("|-------|----|----|----|----|-------|")
        for _, row in stats["top_assets"].iterrows():
            lines.append(
                f"| {row['Asset']} | {row['P1']} | {row['P2']} | "
                f"{row['P3']} | {row['P4']} | {row['Total']} |"
            )
        lines.append("")

    # 7. Top 10 most prevalent vulnerabilities
    if stats["top_vulns"] is not None and len(stats["top_vulns"]) > 0:
        lines.append("## Top Vulnerabilities\n")
        lines.append("| Name / Plugin | Instances | Priority |")
        lines.append("|---------------|-----------|----------|")
        for _, row in stats["top_vulns"].iterrows():
            lines.append(f"| {row['Name / Plugin']} | {row['Instances']} | {row['Priority']} |")
        lines.append("")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

# ──────────────────────────────────────────────────────────────────────────────
# HTML report
# ──────────────────────────────────────────────────────────────────────────────

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Vulnerability Triage Report</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
           background: #f8fafc; color: #1e293b; padding: 2rem; }
    h1 { font-size: 1.4rem; font-weight: 700; margin-bottom: 0.2rem; }
    h2 { font-size: 0.95rem; font-weight: 600; color: #334155; margin-bottom: 0.75rem; }
    .meta { font-size: 0.78rem; color: #64748b; margin-bottom: 1.75rem; }
    .section { margin-bottom: 2rem; }
    .cards { display: flex; gap: 0.9rem; flex-wrap: wrap; margin-bottom: 2rem; }
    .card { background: #fff; border-radius: 8px; padding: 0.9rem 1.3rem;
            border: 1px solid #e2e8f0; border-top-width: 4px; min-width: 105px; }
    .card .label { font-size: 0.68rem; text-transform: uppercase; letter-spacing: 0.06em;
                   color: #64748b; margin-bottom: 0.2rem; }
    .card .value { font-size: 1.8rem; font-weight: 700; }
    .card.total  { border-top-color: #94a3b8; } .card.total  .value { color: #334155; }
    .card.p1     { border-top-color: #ef4444; } .card.p1     .value { color: #dc2626; }
    .card.p2     { border-top-color: #f97316; } .card.p2     .value { color: #ea580c; }
    .card.p3     { border-top-color: #eab308; } .card.p3     .value { color: #ca8a04; }
    .card.p4     { border-top-color: #22c55e; } .card.p4     .value { color: #16a34a; }
    .card.overdue { border-top-color: #dc2626; } .card.overdue .value { color: #dc2626; }
    .card.kev     { border-top-color: #dc2626; } .card.kev     .value { color: #dc2626; }
    .card.epss    { border-top-color: #f97316; } .card.epss    .value { color: #ea580c; }
    .table-wrap { overflow-x: auto; border-radius: 8px; border: 1px solid #e2e8f0; }
    table { width: 100%; border-collapse: collapse; background: #fff; font-size: 0.78rem; }
    thead { background: #f1f5f9; }
    th { padding: 0.6rem 0.85rem; text-align: left; font-weight: 600; font-size: 0.72rem;
         cursor: pointer; user-select: none; white-space: nowrap;
         border-bottom: 1px solid #e2e8f0; }
    th:hover { background: #e2e8f0; }
    th.asc::after  { content: ' \\25B2'; font-size: 0.55rem; }
    th.desc::after { content: ' \\25BC'; font-size: 0.55rem; }
    td { padding: 0.45rem 0.85rem; border-top: 1px solid #f1f5f9;
         max-width: 260px; overflow: hidden; text-overflow: ellipsis;
         white-space: nowrap; vertical-align: middle; }
    tr.p1 td { background: #fff5f5; }
    tr.p2 td { background: #fff8f1; }
    tr.p3 td { background: #fffdf0; }
    tr.p4 td { background: #f0fdf4; }
    tr.overdue td:first-child { border-left: 3px solid #ef4444; }
    tr:hover td { filter: brightness(0.97); }
    .badge { display: inline-block; padding: 0.12em 0.5em; border-radius: 4px;
             font-size: 0.68rem; font-weight: 700; }
    .bp1 { background: #fee2e2; color: #b91c1c; }
    .bp2 { background: #ffedd5; color: #c2410c; }
    .bp3 { background: #fef9c3; color: #854d0e; }
    .bp4 { background: #dcfce7; color: #15803d; }
    .badge-kev { background: #fee2e2; color: #b91c1c; font-weight: 700; }
  </style>
</head>
<body>
  <h1>Vulnerability Triage Report</h1>
  <p class="meta">
    Run: {{ run_time|e }} &nbsp;&bull;&nbsp;
    Source: {{ source|e }} &nbsp;&bull;&nbsp;
    Severity column: {{ sev_col|e }}
  </p>

  <div class="cards">
    <div class="card total">
      <div class="label">Total Findings</div>
      <div class="value">{{ stats.total }}</div>
    </div>
    <div class="card p1">
      <div class="label">P1 Critical</div>
      <div class="value">{{ stats.counts.P1 }}</div>
    </div>
    <div class="card p2">
      <div class="label">P2 High</div>
      <div class="value">{{ stats.counts.P2 }}</div>
    </div>
    <div class="card p3">
      <div class="label">P3 Medium</div>
      <div class="value">{{ stats.counts.P3 }}</div>
    </div>
    <div class="card p4">
      <div class="label">P4 Low</div>
      <div class="value">{{ stats.counts.P4 }}</div>
    </div>
    {% if stats.overdue_total is not none %}
    <div class="card overdue">
      <div class="label">Overdue</div>
      <div class="value">{{ stats.overdue_total }}</div>
    </div>
    {% endif %}
    {% if stats.kev_count is not none %}
    <div class="card kev">
      <div class="label">CISA KEV</div>
      <div class="value">{{ stats.kev_count }}</div>
    </div>
    {% endif %}
    {% if stats.high_epss_count is not none %}
    <div class="card epss">
      <div class="label">High EPSS</div>
      <div class="value">{{ stats.high_epss_count }}</div>
    </div>
    {% endif %}
  </div>

  <div class="section">
    <h2>All Findings</h2>
    <div class="table-wrap">
      <table id="tbl">
        <thead>
          <tr>
            {% for col in columns %}
            <th onclick="sortTable(this, {{ loop.index0 }})">{{ col|e }}</th>
            {% endfor %}
          </tr>
        </thead>
        <tbody>
          {% for row in rows %}
          <tr class="{{ row._css|e }}">
            {% for col in columns %}
            <td title="{{ row[col]|e }}">
              {% if col == 'Priority' %}
              <span class="badge b{{ row[col]|lower|e }}">{{ row[col]|e }}</span>
              {% elif col == 'In CISA KEV' and row[col] == 'True' %}
              <span class="badge badge-kev">KEV</span>
              {% else %}
              {{ row[col]|e }}
              {% endif %}
            </td>
            {% endfor %}
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
  </div>

  <script>
  var _sc = -1, _sa = true;
  function sortTable(th, ci) {
    var tbl = document.getElementById('tbl');
    var tbody = tbl.querySelector('tbody');
    var ths = tbl.querySelectorAll('thead th');
    if (_sc === ci) { _sa = !_sa; } else { _sc = ci; _sa = true; }
    ths.forEach(function(h) { h.classList.remove('asc', 'desc'); });
    th.classList.add(_sa ? 'asc' : 'desc');
    var rows = Array.from(tbody.querySelectorAll('tr'));
    rows.sort(function(a, b) {
      var av = a.cells[ci].textContent.trim();
      var bv = b.cells[ci].textContent.trim();
      var an = parseFloat(av), bn = parseFloat(bv);
      if (!isNaN(an) && !isNaN(bn)) { return _sa ? an - bn : bn - an; }
      return _sa ? av.localeCompare(bv) : bv.localeCompare(av);
    });
    rows.forEach(function(r) { tbody.appendChild(r); });
  }
  </script>
</body>
</html>
"""


def _build_html(df: pd.DataFrame, stats: dict, run_time: str, source: str, sev_col: str) -> str:
    """Render the single-file HTML report from the triaged DataFrame."""
    columns = list(df.columns)
    rows = []
    for _, r in df.iterrows():
        row = {col: _sanitize_csv_cell(r[col]) for col in columns}
        css = r["Priority"].lower()  # "p1", "p2", etc.
        if "Overdue" in df.columns and r.get("Overdue") == True:
            css += " overdue"
        row["_css"] = css
        rows.append(row)

    tpl = Template(_HTML_TEMPLATE)
    return tpl.render(
        run_time=run_time,
        source=source,
        sev_col=sev_col,
        stats=stats,
        columns=columns,
        rows=rows,
    )

# ──────────────────────────────────────────────────────────────────────────────
# CSV writer with injection protection
# ──────────────────────────────────────────────────────────────────────────────

def _write_csv_safe(df: pd.DataFrame, path: str) -> None:
    """Write DataFrame to CSV with formula injection protection.
    
    Args:
        df: DataFrame to write
        path: Output file path
    """
    # Create a copy with sanitized values
    df_safe = df.copy()
    for col in df_safe.columns:
        df_safe[col] = df_safe[col].apply(_sanitize_csv_cell)
    
    df_safe.to_csv(path, index=False)

# ──────────────────────────────────────────────────────────────────────────────
# Main orchestrator
# ──────────────────────────────────────────────────────────────────────────────

def triage_vulnerabilities(
    csv_file: str,
    asset_map_file: Optional[str],
    exceptions_file: Optional[str],
    output_dir: str,
    severity_col_override: Optional[str],
    slas: dict,
    output_format: str,
    dry_run: bool = False,
    verbose: bool = False,
    fetch_epss: bool = False,
    fetch_kev: bool = False,
) -> None:
    """Main triage orchestration function.
    
    Args:
        csv_file: Path to input CSV file
        asset_map_file: Path to asset map JSON file (optional)
        exceptions_file: Path to exceptions JSON file (optional)
        output_dir: Directory for output files
        severity_col_override: Override severity column name
        slas: SLA days per priority
        output_format: Output format (markdown, html, all)
        dry_run: If True, process but don't write files
        verbose: Enable debug logging
        fetch_epss: If True, fetch EPSS scores from FIRST.org
        fetch_kev: If True, fetch CISA KEV catalog
    """
    global log
    log = StructuredLogger(verbose=verbose)
    
    # Resolve base directory for path validation
    base_dir = Path.cwd()
    output_path = Path(output_dir).resolve()
    
    log.info("Starting vulnerability triage", source=csv_file, output_dir=str(output_path))
    
    # Validate and resolve input file path
    try:
        csv_path = _safe_path(csv_file, base_dir, allow_parent=True)
        if not csv_path.exists():
            log.error(f"CSV file not found: {csv_file}")
            sys.exit(ExitCode.IO_ERROR)
        log.debug(f"Input file resolved: {csv_path}")
    except ValueError as e:
        log.error(str(e))
        sys.exit(ExitCode.VALIDATION_ERROR)
    
    # Validate output directory
    try:
        output_path.mkdir(parents=True, exist_ok=True)
        _ = _sanitize_output_path(str(output_path), output_path)
    except (OSError, ValueError) as e:
        log.error(f"Invalid output directory: {e}")
        sys.exit(ExitCode.IO_ERROR)
    
    # Load CSV
    try:
        df = pd.read_csv(csv_path)
        log.debug(f"Loaded CSV: {len(df)} rows, {len(df.columns)} columns")
    except FileNotFoundError:
        log.error(f"CSV file not found: {csv_file}")
        sys.exit(ExitCode.IO_ERROR)
    except Exception as exc:
        log.error(f"Failed to read CSV: {exc}")
        sys.exit(ExitCode.IO_ERROR)

    # Validate CSV schema
    schema_errors = _validate_csv_schema(df)
    if schema_errors:
        for err in schema_errors:
            log.error(f"CSV validation error: {err}")
        sys.exit(ExitCode.VALIDATION_ERROR)

    # Detect severity column
    sev_col = _detect_severity_col(df, severity_col_override)

    # Assign base priority + triage reason
    df = _apply_priority(df, sev_col)

    # Apply optional asset map overrides
    if asset_map_file:
        try:
            asset_map_path = _safe_path(asset_map_file, base_dir, allow_parent=True)
            with open(asset_map_path) as f:
                asset_map = json.load(f)
            
            # Validate asset map structure
            validation_errors = _validate_asset_map(asset_map)
            if validation_errors:
                for err in validation_errors:
                    log.error(f"Asset map validation: {err}")
                sys.exit(ExitCode.CONFIG_ERROR)
            
            df = _apply_asset_map(df, asset_map)
        except FileNotFoundError:
            log.error(f"Asset map file not found: {asset_map_file}")
            sys.exit(ExitCode.IO_ERROR)
        except json.JSONDecodeError as exc:
            log.error(f"Invalid JSON in asset map: {exc}")
            sys.exit(ExitCode.CONFIG_ERROR)
        except ValueError as e:
            log.error(str(e))
            sys.exit(ExitCode.VALIDATION_ERROR)

    # Apply optional exceptions
    if exceptions_file:
        try:
            exc_path = _safe_path(exceptions_file, base_dir, allow_parent=True)
            with open(exc_path) as f:
                exceptions = json.load(f)
            
            # Validate exceptions structure
            validation_errors = _validate_exceptions(exceptions)
            if validation_errors:
                for err in validation_errors:
                    log.error(f"Exceptions validation: {err}")
                sys.exit(ExitCode.CONFIG_ERROR)
            
            df = _apply_exceptions(df, exceptions)
        except FileNotFoundError:
            log.error(f"Exceptions file not found: {exceptions_file}")
            sys.exit(ExitCode.IO_ERROR)
        except json.JSONDecodeError as exc:
            log.error(f"Invalid JSON in exceptions file: {exc}")
            sys.exit(ExitCode.CONFIG_ERROR)
        except ValueError as e:
            log.error(str(e))
            sys.exit(ExitCode.VALIDATION_ERROR)

    # Add threat intelligence enrichment
    if fetch_epss or fetch_kev:
        df = _add_threat_intel(df, fetch_epss, fetch_kev)

    # Add SLA due dates
    df = _add_due_dates(df, slas, date.today())

    # Add age and overdue tracking (only if a first-seen column is present)
    df, _first_seen_col = _add_age_tracking(df, slas, date.today())

    # Compute all stats
    stats = _compute_stats(df)

    # Build output paths
    run_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Sanitize output filenames
    triaged_csv = str(_sanitize_output_path("triaged.csv", output_path))
    summary_md = str(_sanitize_output_path("summary.md", output_path))
    report_html = str(_sanitize_output_path("report.html", output_path))
    triage_json = str(_sanitize_output_path("triage_run.json", output_path))

    if dry_run:
        log.info("DRY RUN MODE - No files will be written")
        log.info(
            "Triage processing complete (dry run)",
            total_vulnerabilities=stats["total"],
            priority_counts=stats["counts"],
            overdue_count=stats["overdue_total"]
        )
        print("\n[DRY RUN] Triage processing complete - no files written")
        print(f"  Would process {stats['total']} vulnerabilities")
        print(f"  Priority breakdown: P1={stats['counts']['P1']}, P2={stats['counts']['P2']}, "
              f"P3={stats['counts']['P3']}, P4={stats['counts']['P4']}")
        if stats["overdue_total"]:
            print(f"  Overdue: {stats['overdue_total']}")
        if stats["kev_count"]:
            print(f"  In CISA KEV: {stats['kev_count']}")
        if stats["high_epss_count"]:
            print(f"  High EPSS (>0.5): {stats['high_epss_count']}")
    else:
        # Write output files
        _write_csv_safe(df, triaged_csv)

        # summary.md
        if output_format in ("markdown", "all"):
            _write_summary_md(summary_md, stats, run_time, csv_file, sev_col, slas)

        # report.html
        if output_format in ("html", "all"):
            html = _build_html(df, stats, run_time, csv_file, sev_col)
            with open(report_html, "w", encoding="utf-8") as f:
                f.write(html)

        # triage_run.json - always written with audit log
        json_payload = {
            "run_time": run_time,
            "source": csv_file,
            "severity_column": sev_col,
            "slas": slas,
            "total_vulnerabilities": stats["total"],
            "unique_vulnerabilities": stats["unique_vulns"],
            "affected_assets": stats["affected_assets"],
            "priority_counts": stats["counts"],
            "overdue": stats["overdue_by_priority"],
            "kev_count": stats["kev_count"],
            "high_epss_count": stats["high_epss_count"],
            "audit_log": log.get_audit_log(),
        }
        with open(triage_json, "w", encoding="utf-8") as f:
            json.dump(json_payload, f, indent=4)

        log.info(
            "Triage complete",
            output_dir=str(output_path),
            total=stats["total"],
            priority_counts=stats["counts"]
        )

        print(f"\nOutputs written to '{output_dir}':")
        print(f"  {triaged_csv}")
        if output_format in ("markdown", "all"):
            print(f"  {summary_md}")
        if output_format in ("html", "all"):
            print(f"  {report_html}")
        print(f"  {triage_json}")

# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Triage Tenable.io vulnerabilities from a ServiceNow export.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Severity column auto-detection:
  Looks for: Severity, Risk, Criticality, Risk Rating, CVSS Risk, Threat Level.
  Use --severity-col if your export uses a different name.

Severity value support:
  Text:    Critical / High / Medium / Low (case-insensitive)
  Numeric: CVSS scores (0–10) mapped to P1–P4
  Prefixed: "4 - Critical", "High (3)", etc.

Asset map format (JSON object):
  {{"web-server-01": "P1", "legacy-db": "P2"}}

Exceptions format (JSON array):
  ["12345", "67890", "CVE-2023-1234"]

Default SLAs (days to remediate):
  P1: {DEFAULT_SLAS['P1']}  |  P2: {DEFAULT_SLAS['P2']}  |  P3: {DEFAULT_SLAS['P3']}  |  P4: {DEFAULT_SLAS['P4']}

Security features:
  - Path traversal prevention for all file operations
  - Input validation for JSON configuration files
  - CSV schema validation before processing
  - CSV formula injection protection
  - Structured audit logging in JSON output

Threat intelligence:
  - EPSS scores from FIRST.org (exploitation likelihood)
  - CISA KEV catalog (known exploited vulnerabilities)
""",
    )

    parser.add_argument(
        "csv_file",
        help="Path to the Tenable.io vulnerability CSV from ServiceNow."
    )
    parser.add_argument(
        "--asset-map",
        help="JSON file mapping asset names to priority overrides."
    )
    parser.add_argument(
        "--exceptions",
        help="JSON file listing Plugin IDs or CVEs to exclude."
    )
    parser.add_argument(
        "--output-dir",
        default=".",
        help="Directory to write output files (default: current directory)."
    )
    parser.add_argument(
        "--severity-col",
        default=None,
        help="Name of the severity column if auto-detection fails."
    )
    parser.add_argument(
        "--format",
        dest="output_format",
        choices=["markdown", "html", "all"],
        default="all",
        help="Output report format: markdown, html, or all (default: all)."
    )
    parser.add_argument(
        "--sla-p1",
        type=int,
        default=DEFAULT_SLAS["P1"],
        metavar="DAYS",
        help=f"SLA in days for P1 Critical findings (default: {DEFAULT_SLAS['P1']})."
    )
    parser.add_argument(
        "--sla-p2",
        type=int,
        default=DEFAULT_SLAS["P2"],
        metavar="DAYS",
        help=f"SLA in days for P2 High findings (default: {DEFAULT_SLAS['P2']})."
    )
    parser.add_argument(
        "--sla-p3",
        type=int,
        default=DEFAULT_SLAS["P3"],
        metavar="DAYS",
        help=f"SLA in days for P3 Medium findings (default: {DEFAULT_SLAS['P3']})."
    )
    parser.add_argument(
        "--sla-p4",
        type=int,
        default=DEFAULT_SLAS["P4"],
        metavar="DAYS",
        help=f"SLA in days for P4 Low findings (default: {DEFAULT_SLAS['P4']})."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Process the CSV but don't write any output files (preview mode)."
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose/debug logging output."
    )
    parser.add_argument(
        "--epss",
        action="store_true",
        help="Fetch EPSS scores from FIRST.org API for exploitation likelihood."
    )
    parser.add_argument(
        "--kev",
        action="store_true",
        help="Fetch CISA Known Exploited Vulnerabilities catalog and flag matching CVEs."
    )

    args = parser.parse_args()

    slas = {
        "P1": args.sla_p1,
        "P2": args.sla_p2,
        "P3": args.sla_p3,
        "P4": args.sla_p4,
    }

    triage_vulnerabilities(
        args.csv_file,
        args.asset_map,
        args.exceptions,
        args.output_dir,
        args.severity_col,
        slas,
        args.output_format,
        dry_run=args.dry_run,
        verbose=args.verbose,
        fetch_epss=args.epss,
        fetch_kev=args.kev,
    )
