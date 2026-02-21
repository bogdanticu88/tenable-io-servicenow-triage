
import argparse
import json
import logging
import os
import sys
from datetime import datetime

import numpy as np
import pandas as pd

logging.basicConfig(format="%(levelname)s: %(message)s", level=logging.INFO)
log = logging.getLogger(__name__)

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

# Columns searched (case-insensitive) when applying exceptions.
EXCEPTION_COLUMNS = {"plugin id", "plugin_id", "vulnerability id", "cve", "name", "finding id"}


def _detect_severity_col(df: pd.DataFrame, override: str | None) -> str:
    """Return the severity column name to use, or exit if not found."""
    if override:
        if override not in df.columns:
            log.error(f"Specified severity column '{override}' not found. Available: {list(df.columns)}")
            sys.exit(1)
        log.info(f"Severity column: '{override}' (user-specified).")
        return override

    col = next((c for c in df.columns if c.lower() in SEVERITY_COLUMNS), None)
    if col is None:
        log.error(
            f"Could not detect a severity column. Tried: {SEVERITY_COLUMNS}. "
            f"Available columns: {list(df.columns)}. "
            f"Use --severity-col to specify it explicitly."
        )
        sys.exit(1)

    log.info(f"Severity column: '{col}' (auto-detected).")
    return col


def _normalize_severity(value: str) -> str | None:
    """Map a raw severity value to a priority string, or None to skip the row."""
    if pd.isna(value):
        return None

    val = str(value).strip().lower()

    # 1. Exact text label match ("critical", "high", etc.)
    if val in SEVERITY_LABEL_MAP:
        return SEVERITY_LABEL_MAP[val]

    # 2. Try as a pure CVSS numeric score before substring matching,
    #    so "5.3" is treated as a float and not substring-matched against "3".
    try:
        score = float(val)
        if score >= 9.0:
            return "P1"
        if score >= 7.0:
            return "P2"
        if score >= 4.0:
            return "P3"
        if score > 0.0:
            return "P4"
        return None  # CVSS 0 = informational
    except ValueError:
        pass

    # 3. Substring match for prefixed formats like "4 - Critical" or "High (3)".
    for label, priority in SEVERITY_LABEL_MAP.items():
        if label in val:
            return priority

    # 4. Unknown value — default to P4.
    return "P4"


def _apply_priority(df: pd.DataFrame, sev_col: str) -> pd.DataFrame:
    df["Priority"] = df[sev_col].apply(_normalize_severity)

    skipped = df["Priority"].isna().sum()
    if skipped:
        log.info(f"Skipped {skipped} row(s) with no actionable severity (None/Info/0).")
    df = df[df["Priority"].notna()].copy()
    return df


def _apply_asset_map(df: pd.DataFrame, asset_map: dict) -> pd.DataFrame:
    """Override priority based on asset name mappings.

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
    log.info(f"Exceptions: removed {before - len(df)} row(s) matched against column(s): {', '.join(cols)}.")
    return df


def triage_vulnerabilities(
    csv_file: str,
    asset_map_file: str | None,
    exceptions_file: str | None,
    output_dir: str,
    severity_col_override: str | None,
) -> None:
    os.makedirs(output_dir, exist_ok=True)

    # Load CSV
    try:
        df = pd.read_csv(csv_file)
    except FileNotFoundError:
        log.error(f"CSV file not found: {csv_file}")
        sys.exit(1)
    except Exception as exc:
        log.error(f"Failed to read CSV: {exc}")
        sys.exit(1)

    if df.empty:
        log.error("CSV file is empty.")
        sys.exit(1)

    # Detect severity column
    sev_col = _detect_severity_col(df, severity_col_override)

    # Assign base priority from severity
    df = _apply_priority(df, sev_col)

    # Apply optional asset map overrides
    if asset_map_file:
        try:
            with open(asset_map_file) as f:
                asset_map = json.load(f)
            if not isinstance(asset_map, dict):
                raise ValueError("Asset map must be a JSON object mapping asset names to priorities.")
            df = _apply_asset_map(df, asset_map)
        except FileNotFoundError:
            log.error(f"Asset map file not found: {asset_map_file}")
            sys.exit(1)
        except (json.JSONDecodeError, ValueError) as exc:
            log.error(f"Failed to load asset map: {exc}")
            sys.exit(1)

    # Apply optional exceptions
    if exceptions_file:
        try:
            with open(exceptions_file) as f:
                exceptions = json.load(f)
            if not isinstance(exceptions, list):
                raise ValueError("Exceptions file must be a JSON array of identifiers.")
            df = _apply_exceptions(df, exceptions)
        except FileNotFoundError:
            log.error(f"Exceptions file not found: {exceptions_file}")
            sys.exit(1)
        except (json.JSONDecodeError, ValueError) as exc:
            log.error(f"Failed to load exceptions file: {exc}")
            sys.exit(1)

    # Write outputs
    run_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    counts = {p: int((df["Priority"] == p).sum()) for p in ("P1", "P2", "P3", "P4")}

    triaged_csv = os.path.join(output_dir, "triaged.csv")
    summary_md = os.path.join(output_dir, "summary.md")
    triage_json = os.path.join(output_dir, "triage_run.json")

    df.to_csv(triaged_csv, index=False)

    with open(summary_md, "w") as f:
        f.write("# Vulnerability Triage Summary\n\n")
        f.write(f"**Run time:** {run_time}  \n")
        f.write(f"**Source:** {csv_file}  \n")
        f.write(f"**Total vulnerabilities:** {len(df)}\n\n")
        f.write("## Priority Breakdown\n\n")
        f.write("| Priority | Count |\n")
        f.write("|----------|-------|\n")
        for p in ("P1", "P2", "P3", "P4"):
            f.write(f"| {p} | {counts[p]} |\n")

    summary = {
        "run_time": run_time,
        "source": csv_file,
        "severity_column": sev_col,
        "total_vulnerabilities": len(df),
        "priority_counts": counts,
    }
    with open(triage_json, "w") as f:
        json.dump(summary, f, indent=4)

    log.info(f"Triage complete — {len(df)} vulnerabilities processed.")
    print(f"\nOutputs written to '{output_dir}':")
    print(f"  {triaged_csv}")
    print(f"  {summary_md}")
    print(f"  {triage_json}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Triage Tenable.io vulnerabilities from a ServiceNow export.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Severity column auto-detection:
  Looks for: Severity, Risk, Criticality, Risk Rating, CVSS Risk, Threat Level.
  Use --severity-col if your export uses a different name.

Severity value support:
  Text:    Critical / High / Medium / Low (case-insensitive)
  Numeric: CVSS scores (0-10) mapped to P1-P4
  Prefixed: "4 - Critical", "High (3)", etc.

Asset map format (JSON object):
  {"web-server-01": "P1", "legacy-db": "P2"}

Exceptions format (JSON array):
  ["12345", "67890", "CVE-2023-1234"]
""",
    )
    parser.add_argument("csv_file", help="Path to the Tenable.io vulnerability CSV from ServiceNow.")
    parser.add_argument("--asset-map", help="JSON file mapping asset names to priority overrides.")
    parser.add_argument("--exceptions", help="JSON file listing Plugin IDs or CVEs to exclude.")
    parser.add_argument(
        "--output-dir",
        default=".",
        help="Directory to write output files (default: current directory).",
    )
    parser.add_argument(
        "--severity-col",
        default=None,
        help="Name of the severity column if auto-detection fails.",
    )
    args = parser.parse_args()

    triage_vulnerabilities(
        args.csv_file,
        args.asset_map,
        args.exceptions,
        args.output_dir,
        args.severity_col,
    )
