from getpass import getpass
import sqlite3

import paramiko

from scanner.metasploit_runner import MetasploitRunner


DATABASE_PATH = "report/vulnx.db"

KALI_HOST = "192.168.56.101"
KALI_USERNAME = "kali"

SCAN_ID = 18


def load_service_context(scan_id: int) -> dict | None:
    """Load the first stored service from a VulnX scan."""

    connection = sqlite3.connect(
        DATABASE_PATH
    )

    connection.row_factory = sqlite3.Row

    try:
        row = connection.execute(
            """
            SELECT
                host,
                port,
                service,
                product,
                version
            FROM findings
            WHERE scan_id = ?
              AND service IS NOT NULL
              AND service != ''
            ORDER BY id
            LIMIT 1
            """,
            (scan_id,),
        ).fetchone()

        if row is None:
            return None

        return {
            "host": row["host"],
            "port": row["port"],
            "service": row["service"],
            "product": row["product"],
            "version": row["version"],
        }

    finally:
        connection.close()


def main() -> None:
    print("=== VulnX Service-Based Metasploit Discovery Test ===")

    context = load_service_context(
        SCAN_ID
    )

    if context is None:
        print(
            f"No service context found in Scan {SCAN_ID}."
        )
        return

    print("\n" + "=" * 70)
    print("STORED SERVICE CONTEXT")
    print("=" * 70)

    print(
        f"Host:     {context['host']}"
    )

    print(
        f"Port:     {context['port']}"
    )

    print(
        f"Service:  {context['service']}"
    )

    print(
        f"Product:  {context['product']}"
    )

    print(
        f"Version:  {context['version']}"
    )

    service = (
        context["service"]
        or ""
    ).strip().lower()

    if not service:
        print("\nNo usable service name.")
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

        query = f"name:{service}"

        print(
            f"\nSearching auxiliary modules with: "
            f"{query}"
        )

        auxiliary = runner.search_auxiliary(
            query
        )

        print(
            f"Auxiliary modules found: "
            f"{len(auxiliary)}"
        )

        for module in auxiliary:
            print(
                f"  - {module['module_name']}"
            )

        print(
            f"\nSearching exploit modules with: "
            f"{query}"
        )

        exploits = runner.search_exploits(
            query
        )

        print(
            f"Exploit modules found: "
            f"{len(exploits)}"
        )

        for module in exploits:
            print(
                f"  - {module['module_name']}"
            )

        print("\n" + "=" * 70)
        print("SERVICE-BASED DISCOVERY SUMMARY")
        print("=" * 70)

        print(
            f"Service searched:       {service}"
        )

        print(
            f"Auxiliary candidates:   {len(auxiliary)}"
        )

        print(
            f"Exploit candidates:     {len(exploits)}"
        )

        print(
            "\nThese are service-based candidate modules. "
            "They are not treated as proof of vulnerability."
        )

        print(
            "\nService-based Metasploit discovery: SUCCESS"
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