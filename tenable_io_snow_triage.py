
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

REQUIRED_COLUMNS = {"Severity"}

# Columns searched (case-insensitive) when applying asset map overrides.
ASSET_COLUMNS = {"asset", "host", "asset name", "hostname", "dns name"}

# Columns searched (case-insensitive) when applying exceptions.
EXCEPTION_COLUMNS = {"plugin id", "plugin_id", "vulnerability id", "cve", "name"}


def _validate_columns(df: pd.DataFrame, required: set) -> None:
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"CSV is missing required column(s): {', '.join(sorted(missing))}")


def _apply_priority(df: pd.DataFrame) -> pd.Series:
    conditions = [
        df["Severity"].str.strip().str.lower() == "critical",
        df["Severity"].str.strip().str.lower() == "high",
        df["Severity"].str.strip().str.lower() == "medium",
        df["Severity"].str.strip().str.lower() == "low",
    ]
    return pd.Series(np.select(conditions, ["P1", "P2", "P3", "P4"], default="P4"), index=df.index)


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

    exceptions format: ["<plugin id or name>", ...]
    Example: ["12345", "67890", "CVE-2023-1234"]
    """
    col = next((c for c in df.columns if c.lower() in EXCEPTION_COLUMNS), None)
    if col is None:
        log.warning("Exceptions file provided but no matching identifier column found in CSV — skipping.")
        return df

    exc_set = {str(e) for e in exceptions}
    before = len(df)
    df = df[~df[col].astype(str).isin(exc_set)]
    log.info(f"Exceptions: removed {before - len(df)} row(s) matched against column '{col}'.")
    return df


def triage_vulnerabilities(
    csv_file: str,
    asset_map_file: str | None,
    exceptions_file: str | None,
    output_dir: str,
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

    try:
        _validate_columns(df, REQUIRED_COLUMNS)
    except ValueError as exc:
        log.error(str(exc))
        sys.exit(1)

    # Assign base priority from severity
    df["Priority"] = _apply_priority(df)

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
    args = parser.parse_args()

    triage_vulnerabilities(args.csv_file, args.asset_map, args.exceptions, args.output_dir)
