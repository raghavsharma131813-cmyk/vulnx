from getpass import getpass
import sqlite3

import paramiko

from scanner.metasploit_mapper import (
    map_finding_to_metasploit,
    split_metasploit_modules,
)
from scanner.metasploit_runner import MetasploitRunner


DATABASE_PATH = "report/vulnx.db"

KALI_HOST = "192.168.56.101"
KALI_USERNAME = "kali"

SCAN_ID = 18


def load_findings(scan_id: int) -> list[dict]:
    """Load stored VulnX findings from SQLite."""

    connection = sqlite3.connect(
        DATABASE_PATH
    )

    connection.row_factory = sqlite3.Row

    try:
        rows = connection.execute(
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
            ORDER BY id
            """,
            (scan_id,),
        ).fetchall()

        findings = []

        for row in rows:
            cves_text = row["cves"] or ""

            cves = [
                cve.strip().upper()
                for cve in cves_text.split(",")
                if cve.strip()
            ]

            findings.append(
                {
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
            )

        return findings

    finally:
        connection.close()


def main() -> None:
    print("=== VulnX All-CVE Metasploit Discovery Test ===")

    findings = load_findings(
        SCAN_ID
    )

    print(
        f"\nLoaded {len(findings)} stored findings "
        f"from Scan {SCAN_ID}."
    )

    cve_findings = [
        finding
        for finding in findings
        if finding["cves"]
    ]

    print(
        f"Findings containing CVE references: "
        f"{len(cve_findings)}"
    )

    if not cve_findings:
        print("\nNo CVE-backed findings found.")
        return

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

        total_cves = 0
        cves_with_modules = 0
        cves_without_modules = 0
        total_auxiliary = 0
        total_exploit = 0
        total_errors = 0

        processed_cves: set[str] = set()

        for finding in cve_findings:

            for cve_id in finding["cves"]:

                if cve_id in processed_cves:
                    continue

                processed_cves.add(cve_id)
                total_cves += 1

                print("\n" + "=" * 70)
                print(f"CVE: {cve_id}")
                print("=" * 70)

                modules = map_finding_to_metasploit(
                    {
                        "cves": [cve_id]
                    },
                    runner,
                )

                grouped = split_metasploit_modules(
                    modules
                )

                auxiliary_count = len(
                    grouped["auxiliary"]
                )

                exploit_count = len(
                    grouped["exploit"]
                )

                error_count = len(
                    grouped["error"]
                )

                total_auxiliary += auxiliary_count
                total_exploit += exploit_count
                total_errors += error_count

                print(
                    f"Auxiliary modules: {auxiliary_count}"
                )

                for module in grouped["auxiliary"]:
                    print(
                        f"  - {module['module_name']}"
                    )

                print(
                    f"Exploit modules:   {exploit_count}"
                )

                for module in grouped["exploit"]:
                    print(
                        f"  - {module['module_name']}"
                    )

                print(
                    f"Search errors:      {error_count}"
                )

                if modules:
                    cves_with_modules += 1
                    print(
                        "\nResult: MODULES FOUND"
                    )
                else:
                    cves_without_modules += 1
                    print(
                        "\nResult: NO MODULES FOUND"
                    )

        print("\n" + "=" * 70)
        print("ALL-CVE DISCOVERY SUMMARY")
        print("=" * 70)

        print(
            f"Unique CVEs checked:       {total_cves}"
        )

        print(
            f"CVEs with modules:         {cves_with_modules}"
        )

        print(
            f"CVEs without modules:      {cves_without_modules}"
        )

        print(
            f"Auxiliary modules found:   {total_auxiliary}"
        )

        print(
            f"Exploit modules found:     {total_exploit}"
        )

        print(
            f"Search errors:             {total_errors}"
        )

        if total_errors == 0:
            print(
                "\nMetasploit CVE discovery: SUCCESS"
            )
        else:
            print(
                "\nMetasploit CVE discovery: "
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