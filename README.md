# tenable-io-servicenow-triage

Triage Tenable.io vulnerabilities exported from ServiceNow into P1–P4 priorities with consistent, audit-friendly output.

## Why

Security teams often struggle with a high volume of vulnerabilities from Tenable.io. When this data is managed in ServiceNow, the export formats can be inconsistent and difficult to work with. This tool provides a standardized way to triage these vulnerabilities, apply consistent priority ratings, and generate clear, auditable reports.

## Requirements

- Python 3.11+
- pandas

## Installation

```bash
pip install pandas
```

## Usage

```bash
python tenable_io_snow_triage.py <path_to_your_servicenow_export.csv>
```

### Optional Arguments

- `--asset-map <path_to_asset_map.json>`: Apply custom asset priority mappings.
- `--exceptions <path_to_exceptions.json>`: Exclude vulnerabilities based on a predefined list.

### Examples

**Basic Triage:**

```bash
python tenable_io_snow_triage.py vulnerabilities.csv
```

**Triage with Asset Map and Exceptions:**

```bash
python tenable_io_snow_triage.py vulnerabilities.csv --asset-map assets.json --exceptions exceptions.json
```

## Output

The tool generates three files:

- `triaged.csv`: The original CSV data with an added `Priority` column (P1, P2, P3, P4).
- `summary.md`: A human-readable Markdown summary of the triage run, including vulnerability counts by priority.
- `triage_run.json`: A machine-readable JSON file containing the summary data, useful for automation and integration with other tools.
