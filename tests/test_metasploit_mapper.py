from getpass import getpass

import paramiko

from scanner.metasploit_mapper import (
    map_finding_to_metasploit,
    split_metasploit_modules,
)
from scanner.metasploit_runner import MetasploitRunner


KALI_HOST = "192.168.56.101"
KALI_USERNAME = "kali"


def main() -> None:
    print("=== VulnX Metasploit Mapper Test ===")

    password = getpass(
        f"Enter password for {KALI_USERNAME}@{KALI_HOST}: "
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

        # Controlled synthetic VulnX findings.
        findings = [
            {
                "title": "CVE-2018-15473 test finding",
                "cves": ["CVE-2018-15473"],
            },
            {
                "title": "CVE-2017-5638 test finding",
                "cves": ["CVE-2017-5638"],
            },
            {
                "title": "Multiple CVE test finding",
                "cves": [
                    "CVE-2018-15473",
                    "CVE-2017-5638",
                ],
            },
        ]

        for finding in findings:
            print("\n" + "=" * 70)
            print(finding["title"])
            print("=" * 70)

            modules = map_finding_to_metasploit(
                finding,
                runner,
            )

            grouped = split_metasploit_modules(
                modules
            )

            print(
                f"CVE(s): {', '.join(finding['cves'])}"
            )

            print(
                f"Total discovered modules: "
                f"{len(modules)}"
            )

            print(
                f"Auxiliary modules: "
                f"{len(grouped['auxiliary'])}"
            )

            for module in grouped["auxiliary"]:
                print(
                    f"  - {module['module_name']}"
                )

            print(
                f"Exploit modules: "
                f"{len(grouped['exploit'])}"
            )

            for module in grouped["exploit"]:
                print(
                    f"  - {module['module_name']}"
                )

            if grouped["error"]:
                print(
                    f"Errors: {len(grouped['error'])}"
                )

                for error in grouped["error"]:
                    print(
                        f"  - {error['description']}"
                    )

        print("\n" + "=" * 70)
        print("MAPPER TEST COMPLETE")
        print("=" * 70)

    except Exception as exc:
        print("\nTest failed:")
        print(type(exc).__name__)
        print(str(exc))

    finally:
        client.close()
        print("\nSSH connection closed.")


if __name__ == "__main__":
    main()