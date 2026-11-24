"""
Load real findings from the VulnX SQLite database and run the
evaluation harness on them.

This reuses the application's own database getters, so it reads the
exact findings your scans produced (report/vulnx.db by default).

Run from the project root:

    # list available scans
    python -m experiments.load_from_db --list

    # run experiments on the latest scan
    python -m experiments.load_from_db

    # run experiments on a specific scan id
    python -m experiments.load_from_db --scan 3

    # run experiments on ALL findings across all scans
    python -m experiments.load_from_db --all
"""

import argparse
from typing import Any

from vulnerability_engine.database import (
    get_scan_history,
    get_findings_by_scan,
)

from experiments.run_experiments import (
    experiment_ranking_comparison,
    experiment_ablation,
    experiment_ranking_quality,
    _ensure_results_dir,
)


def _to_experiment_finding(row: dict[str, Any]) -> dict[str, Any]:
    """
    Convert a database finding row into the dict shape the scoring
    models expect. The DB already stores every field the engine uses,
    so this is mostly a pass-through with a stable id and title.
    """

    finding = dict(row)
    finding["id"] = f"D{row.get('id')}"
    finding["title"] = row.get("title") or row.get("service") or "finding"
    # cvss is stored as a REAL; the engine's normalizer accepts a float.
    return finding


def list_scans() -> None:
    history = get_scan_history()
    if not history:
        print("No scans found in report/vulnx.db. Run a scan in VulnX first.")
        return
    print(f"{'scan_id':<9}{'target':<20}{'findings':<10}{'started'}")
    for scan in history:
        print(f"{str(scan.get('id')):<9}"
              f"{str(scan.get('target', '')):<20}"
              f"{str(scan.get('findings', '?')):<10}"
              f"{scan.get('started_at', '')}")


def load_findings(scan_id: int | None, use_all: bool) -> list[dict[str, Any]]:
    history = get_scan_history()
    if not history:
        return []

    if use_all:
        rows: list[dict[str, Any]] = []
        for scan in history:
            rows.extend(get_findings_by_scan(scan["id"]))
    else:
        if scan_id is None:
            # Latest scan (history is typically newest first; fall back
            # to max id to be safe).
            scan_id = max(s["id"] for s in history)
        rows = get_findings_by_scan(scan_id)

    return [_to_experiment_finding(r) for r in rows]


def main() -> None:
    parser = argparse.ArgumentParser(description="Run VulnX experiments on real DB findings.")
    parser.add_argument("--list", action="store_true", help="list available scans and exit")
    parser.add_argument("--scan", type=int, default=None, help="scan id to evaluate")
    parser.add_argument("--all", action="store_true", help="use findings from all scans")
    args = parser.parse_args()

    if args.list:
        list_scans()
        return

    _ensure_results_dir()
    findings = load_findings(args.scan, args.all)

    if len(findings) < 2:
        print(f"Only {len(findings)} finding(s) available. Need at least 2 to "
              "rank. Run a scan with more results, or use --all.")
        return

    label = "db_all" if args.all else (f"db_scan{args.scan}" if args.scan else "db_latest")
    print(f"Loaded {len(findings)} findings from the database (label: {label}).")

    experiment_ranking_comparison(findings, label=label)
    experiment_ablation(findings, label=label)
    experiment_ranking_quality(findings, label=label)
    print(f"\nDone. CSVs written to experiments/results/ with the '{label}' suffix.")


if __name__ == "__main__":
    main()
