# tenable-io-servicenow-triage

Triage Tenable.io vulnerabilities exported from ServiceNow into P1–P4 priorities with consistent, audit-friendly output.

## Why

Security teams often struggle with a high volume of vulnerabilities from Tenable.io. When this data is managed in ServiceNow, the export formats can be inconsistent and difficult to work with. This tool provides a standardized way to triage these vulnerabilities, apply consistent priority ratings, and generate clear, auditable reports.

## Requirements

- Python 3.10+
- pandas
- numpy

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
python tenable_io_snow_triage.py <path_to_your_servicenow_export.csv>
```

### Options

| Flag | Description |
|------|-------------|
| `--asset-map <file>` | JSON file mapping asset names to priority overrides |
| `--exceptions <file>` | JSON file listing Plugin IDs or CVEs to exclude |
| `--output-dir <dir>` | Directory to write output files (default: current directory) |
| `--severity-col <name>` | Override the severity column name if auto-detection fails |

### Examples

**Basic triage:**

```bash
python tenable_io_snow_triage.py vulnerabilities.csv
```

**Triage with asset map and exceptions, writing to a specific directory:**

```bash
python tenable_io_snow_triage.py vulnerabilities.csv \
  --asset-map assets.json \
  --exceptions exceptions.json \
  --output-dir ./reports/2024-01-15
```

**Force a specific severity column:**

```bash
python tenable_io_snow_triage.py vulnerabilities.csv --severity-col "Risk Rating"
```

## Severity Column Auto-Detection

The script automatically detects the severity column from common export formats. You don't need to rename or reformat your CSV.

| Export source | Column detected |
|---------------|----------------|
| ServiceNow export | `Severity` |
| Tenable.io direct export | `Risk` |
| CVSS-based exports | `CVSS Risk` |
| Custom/other | `Criticality`, `Risk Rating`, `Threat Level` |

If none of these match, use `--severity-col <name>`. The script will print all available column names in the error message to help identify the right one.

## Severity Value Support

Values are normalized automatically regardless of format:

| Format | Examples |
|--------|---------|
| Text labels | `Critical`, `High`, `Medium`, `Low` (case-insensitive) |
| CVSS numeric scores | `9.8` → P1, `7.5` → P2, `5.3` → P3, `2.1` → P4 |
| Prefixed formats | `4 - Critical`, `3 - High`, `High (3)` |
| Informational / None | Rows are skipped, not assigned P4 |

## Priority Mapping

| Severity | Priority |
|----------|----------|
| Critical | P1 |
| High | P2 |
| Medium | P3 |
| Low | P4 |

Asset map overrides are applied after the severity-based assignment. Exceptions are removed before output is written.

## Asset Map Format

A JSON object mapping asset names to a priority level. Matched against any host, hostname, or asset name column in the CSV. Use this to elevate or downgrade priority for specific assets regardless of vulnerability severity.

```json
{
  "web-server-01": "P1",
  "legacy-db": "P2",
  "dev-sandbox": "P4"
}
```

## Exceptions Format

A JSON array of identifiers to exclude from the output. Matched against all identifier columns present in the CSV (Plugin ID, CVE, Name, etc.), so a mixed list works without needing to separate by type.

```json
["12345", "67890", "CVE-2023-1234"]
```

## Output

Three files are written to the output directory:

| File | Description |
|------|-------------|
| `triaged.csv` | Original CSV with an added `Priority` column (P1–P4) |
| `summary.md` | Markdown summary with vulnerability counts by priority |
| `triage_run.json` | Machine-readable JSON summary for automation and integration |
