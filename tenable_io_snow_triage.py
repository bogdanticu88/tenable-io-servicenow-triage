
import argparse
import pandas as pd
import json
from datetime import datetime

def triage_vulnerabilities(csv_file, asset_map_file, exceptions_file):
    """
    Triage Tenable.io vulnerabilities from a ServiceNow export.
    """
    df = pd.read_csv(csv_file)

    # Priority assignment logic (customize as needed)
    conditions = [
        (df['Severity'] == 'Critical'),
        (df['Severity'] == 'High'),
        (df['Severity'] == 'Medium'),
        (df['Severity'] == 'Low')
    ]
    priorities = ['P1', 'P2', 'P3', 'P4']
    df['Priority'] = pd.np.select(conditions, priorities, default='P4')

    if asset_map_file:
        with open(asset_map_file, 'r') as f:
            asset_map = json.load(f)
        # Apply asset map logic if necessary
        # Example: df['Asset Priority'] = df['Asset Name'].map(asset_map)

    if exceptions_file:
        with open(exceptions_file, 'r') as f:
            exceptions = json.load(f)
        # Apply exceptions logic
        # Example: df = df[~df['Vulnerability ID'].isin(exceptions)]

    # Generate outputs
    run_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    triaged_csv_file = 'triaged.csv'
    summary_md_file = 'summary.md'
    triage_run_json_file = 'triage_run.json'

    df.to_csv(triaged_csv_file, index=False)

    summary = {
        'run_time': run_time,
        'total_vulnerabilities': len(df),
        'p1_count': len(df[df['Priority'] == 'P1']),
        'p2_count': len(df[df['Priority'] == 'P2']),
        'p3_count': len(df[df['Priority'] == 'P3']),
        'p4_count': len(df[df['Priority'] == 'P4']),
    }

    with open(summary_md_file, 'w') as f:
        f.write("# Vulnerability Triage Summary

")
        f.write(f"Run Time: {run_time}
")
        f.write(f"Total Vulnerabilities: {summary['total_vulnerabilities']}

")
        f.write("## Priority Counts
")
        f.write(f"- P1: {summary['p1_count']}
")
        f.write(f"- P2: {summary['p2_count']}
")
        f.write(f"- P3: {summary['p3_count']}
")
        f.write(f"- P4: {summary['p4_count']}
")

    with open(triage_run_json_file, 'w') as f:
        json.dump(summary, f, indent=4)

    print(f"Triage complete. Outputs:")
    print(f"- {triaged_csv_file}")
    print(f"- {summary_md_file}")
    print(f"- {triage_run_json_file}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Triage Tenable.io vulnerabilities from ServiceNow.')
    parser.add_argument('csv_file', help='Path to the Tenable.io vulnerability CSV from ServiceNow.')
    parser.add_argument('--asset-map', help='Path to an optional asset map JSON file.')
    parser.add_argument('--exceptions', help='Path to an optional exceptions JSON file.')
    args = parser.parse_args()

    triage_vulnerabilities(args.csv_file, args.asset_map, args.exceptions)
