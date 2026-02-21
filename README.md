# tenable-io-servicenow-triage

Triage Tenable.io vulnerabilities exported from ServiceNow into P1–P4 priorities with SLA tracking, age analysis, asset breakdowns, and audit-ready reports.

## Why

Security teams dealing with high-volume Tenable.io exports from ServiceNow need more than a simple priority label. This tool provides a full triage workflow: consistent priority assignment, SLA due dates, age and overdue tracking, deduplication stats, asset-level breakdowns, and clean reports in both Markdown and HTML.

## Requirements

- Python 3.10+
- pandas
- numpy
- jinja2

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
python tenable_io_snow_triage.py <path_to_export.csv> [options]
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--asset-map <file>` | — | JSON file mapping asset names to priority overrides |
| `--exceptions <file>` | — | JSON file listing Plugin IDs or CVEs to exclude |
| `--output-dir <dir>` | `.` | Directory to write output files |
| `--severity-col <name>` | auto | Severity column name if auto-detection fails |
| `--format <mode>` | `all` | Output format: `markdown`, `html`, or `all` |
| `--sla-p1 <days>` | `7` | Remediation SLA in days for P1 Critical |
| `--sla-p2 <days>` | `30` | Remediation SLA in days for P2 High |
| `--sla-p3 <days>` | `90` | Remediation SLA in days for P3 Medium |
| `--sla-p4 <days>` | `180` | Remediation SLA in days for P4 Low |

### Examples

**Basic triage:**

```bash
python tenable_io_snow_triage.py vulnerabilities.csv
```

**Full triage with asset overrides, exceptions, custom SLAs, and a specific output directory:**

```bash
python tenable_io_snow_triage.py vulnerabilities.csv \
  --asset-map assets.json \
  --exceptions exceptions.json \
  --output-dir ./reports/2024-01-15 \
  --sla-p1 3 \
  --format all
```

**HTML report only:**

```bash
python tenable_io_snow_triage.py vulnerabilities.csv --format html
```

**Force a specific severity column:**

```bash
python tenable_io_snow_triage.py vulnerabilities.csv --severity-col "Risk Rating"
```

## Severity Column Auto-Detection

The script detects the severity column from common export formats automatically.

| Export source | Column detected |
|---------------|----------------|
| ServiceNow export | `Severity` |
| Tenable.io direct export | `Risk` |
| CVSS-based exports | `CVSS Risk` |
| Custom/other | `Criticality`, `Risk Rating`, `Threat Level` |

If none match, use `--severity-col <name>`. The error message prints all available column names.

## Severity Value Support

Values are normalized automatically regardless of format:

| Format | Examples |
|--------|---------|
| Text labels | `Critical`, `High`, `Medium`, `Low` (case-insensitive) |
| CVSS numeric scores | `9.8` → P1, `7.5` → P2, `5.3` → P3, `2.1` → P4 |
| Prefixed formats | `4 - Critical`, `3 - High`, `High (3)` |
| Informational / None | Rows are skipped, not assigned P4 |

## Priority Mapping

| Severity | Priority | Default SLA |
|----------|----------|-------------|
| Critical | P1 | 7 days |
| High | P2 | 30 days |
| Medium | P3 | 90 days |
| Low | P4 | 180 days |

Asset map overrides are applied after the severity-based assignment. Exceptions are removed before any output is written.

## Asset Map Format

A JSON object mapping asset names to a priority level. Matched against any host, hostname, or asset name column in the CSV.

```json
{
  "web-server-01": "P1",
  "legacy-db": "P2",
  "dev-sandbox": "P4"
}
```

## Exceptions Format

A JSON array of identifiers to exclude. Matched against all identifier columns present in the CSV (Plugin ID, CVE, Name, etc.).

```json
["12345", "67890", "CVE-2023-1234"]
```

## Age Tracking

If the CSV contains a first-seen or discovery date column (e.g. `First Seen`, `First Detected`, `Discovery Date`, `Plugin Publication Date`), the script automatically adds:

- **Age (days)** — number of days since the finding was first observed
- **Overdue** — `True` if age exceeds the SLA for the assigned priority

This requires no configuration — the column is detected automatically.

## Output Files

| File | Written when | Description |
|------|-------------|-------------|
| `triaged.csv` | Always | Original CSV with `Priority`, `Triage Reason`, `Due Date`, and (if applicable) `Age (days)`, `Overdue` columns added |
| `summary.md` | `markdown` or `all` | Markdown report with priority breakdown, coverage stats, overdue counts, top assets, and top vulnerabilities |
| `report.html` | `html` or `all` | Self-contained HTML report with summary cards, colour-coded sortable findings table |
| `triage_run.json` | Always | Machine-readable JSON audit record for automation and integration |

### Triage Reason column

Every row in `triaged.csv` includes a `Triage Reason` column explaining the source of the priority:

| Reason format | Meaning |
|---------------|---------|
| `severity:Critical` | Assigned from text severity label |
| `cvss:9.8` | Assigned from numeric CVSS score |
| `asset_override:legacy-db` | Overridden by asset map |

### triage_run.json structure

```json
{
  "run_time": "2024-01-15 14:32:01",
  "source": "vulnerabilities.csv",
  "severity_column": "Severity",
  "slas": {"P1": 7, "P2": 30, "P3": 90, "P4": 180},
  "total_vulnerabilities": 142,
  "unique_vulnerabilities": 38,
  "affected_assets": 12,
  "priority_counts": {"P1": 5, "P2": 22, "P3": 89, "P4": 26},
  "overdue": {"P1": 3, "P2": 1, "P3": 0, "P4": 0}
}
```
