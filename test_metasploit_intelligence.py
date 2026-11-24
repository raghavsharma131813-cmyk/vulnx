from __future__ import annotations

import sqlite3
from getpass import getpass

import paramiko

from scanner.metasploit_intelligence import (
    discover_for_finding,
    summarize_intelligence,
)
from scanner.metasploit_runner import MetasploitRunner


DATABASE_PATH = "report/vulnx.db"

KALI_HOST = "192.168.56.101"
KALI_USERNAME = "kali"

SCAN_ID = 18


def load_first_cve_finding(
    scan_id: int,
) -> dict | None:
    """Load the first stored finding that contains a CVE."""

    connection = sqlite3.connect(
        DATABASE_PATH
    )

    connection.row_factory = sqlite3.Row

    try:
        row = connection.execute(
            """
            SELECT
                id,
                host,
                port,
                service,
                product,
                version,
                title,
                cves,
                severity,
                risk_level,
                risk_score,
                status
            FROM findings
            WHERE scan_id = ?
              AND cves IS NOT NULL
              AND cves != ''
            ORDER BY id
            LIMIT 1
            """,
            (scan_id,),
        ).fetchone()

        if row is None:
            return None

        cves = [
            value.strip().upper()
            for value in row["cves"].split(",")
            if value.strip()
        ]

        return {
            "id": row["id"],
            "host": row["host"],
            "port": row["port"],
            "service": row["service"],
            "product": row["product"],
            "version": row["version"],
            "title": row["title"],
            "cves": cves,
            "severity": row["severity"],
            "risk_level": row["risk_level"],
            "risk_score": row["risk_score"],
            "status": row["status"],
        }

    finally:
        connection.close()


def main() -> None:
    print(
        "=== VulnX Metasploit Intelligence Test ==="
    )

    finding = load_first_cve_finding(
        SCAN_ID
    )

    if finding is None:
        print(
            f"\nNo CVE-backed finding found in Scan {SCAN_ID}."
        )
        return

    print("\n" + "=" * 70)
    print("STORED VULNX FINDING")
    print("=" * 70)

    print(
        f"Finding ID: {finding['id']}"
    )

    print(
        f"Title:      {finding['title']}"
    )

    print(
        f"Service:    {finding['service']}"
    )

    print(
        f"Product:    {finding['product']}"
    )

    print(
        f"Version:    {finding['version']}"
    )

    print(
        f"CVEs:       {', '.join(finding['cves'])}"
    )

    password = getpass(
        f"\nEnter password for "
        f"{KALI_USERNAME}@{KALI_HOST}: "
    )

    client = paramiko.SSHClient()

    client.set_missing_host_key_policy(
        paramiko.AutoAddPolicy()
    )

    try:
        print("\nConnecting to Kali...")

        client.connect(
            hostname=KALI_HOST,
            username=KALI_USERNAME,
            password=password,
            timeout=15,
            banner_timeout=15,
            auth_timeout=15,
        )

        print("SSH connection: OK")

        runner = MetasploitRunner(
            ssh_client=client
        )

        print(
            "\nBuilding Metasploit intelligence..."
        )

        intelligence = discover_for_finding(
            finding,
            runner,
        )

        summary = summarize_intelligence(
            intelligence
        )

        print("\n" + "=" * 70)
        print("CVE-LINKED MODULES")
        print("=" * 70)

        cve_linked = intelligence[
            "cve_linked"
        ]

        print(
            f"Auxiliary: "
            f"{len(cve_linked['auxiliary'])}"
        )

        for module in cve_linked["auxiliary"]:
            print(
                f"  - {module['module_name']}"
            )

        print(
            f"Exploit:   "
            f"{len(cve_linked['exploit'])}"
        )

        for module in cve_linked["exploit"]:
            print(
                f"  - {module['module_name']}"
            )

        print(
            f"Errors:    "
            f"{len(cve_linked['errors'])}"
        )

        print("\n" + "=" * 70)
        print("SERVICE-BASED CANDIDATE MODULES")
        print("=" * 70)

        service_candidates = intelligence[
            "service_candidates"
        ]

        print(
            f"Auxiliary: "
            f"{len(service_candidates['auxiliary'])}"
        )

        for module in service_candidates["auxiliary"]:
            print(
                f"  - {module['module_name']}"
            )

        print(
            f"Exploit:   "
            f"{len(service_candidates['exploit'])}"
        )

        for module in service_candidates["exploit"]:
            print(
                f"  - {module['module_name']}"
            )

        print(
            f"Errors:    "
            f"{len(service_candidates['errors'])}"
        )

        print("\n" + "=" * 70)
        print("INTELLIGENCE SUMMARY")
        print("=" * 70)

        for key, value in summary.items():
            print(
                f"{key}: {value}"
            )

        print("\n" + "=" * 70)
        print("RESULT")
        print("=" * 70)

        if (
            summary["cve_errors"] == 0
            and summary["service_errors"] == 0
        ):
            print(
                "Metasploit intelligence discovery: SUCCESS"
            )
        else:
            print(
                "Metasploit intelligence discovery: "
                "COMPLETED WITH ERRORS"
            )

    except Exception as exc:
        print("\nTest failed:")
        print(type(exc).__name__)
        print(str(exc))

    finally:
        client.close()
        print("\nSSH connection closed.")


if __name__ == "__main__":
    main()
    