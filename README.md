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

## Asset Map Format

A JSON object mapping asset names (matched against any host/asset column in the CSV) to a priority level. Use this to elevate or downgrade priority for specific assets regardless of vulnerability severity.

```json
{
  "web-server-01": "P1",
  "legacy-db": "P2",
  "dev-sandbox": "P4"
}
```

## Exceptions Format

A JSON array of identifiers to exclude from the output. Matched against Plugin ID, CVE, or Name columns if present.

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

### Priority Mapping

| Severity | Priority |
|----------|----------|
| Critical | P1 |
| High | P2 |
| Medium | P3 |
| Low | P4 |

Asset map overrides are applied after the severity-based assignment. Exceptions are removed before output is written.
